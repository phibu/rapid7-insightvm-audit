from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding, Severity, Status
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)

# Match both v3 (/api/3/...) and v4 (/v4/integration/...) paths. The
# alternation `(?:/api/3|/v4/integration)` keeps the existing capture-
# group structure intact (3 groups, one per error-message form) so
# `m.group(1) or m.group(2) or m.group(3)` still works downstream.
_ERROR_PATH_RE = re.compile(
    r' on \w+ ((?:/api/3|/v4/integration)/[^\s:]+)'        # "...on GET /api/3/..." or "...on POST /v4/integration/..."
    r'|(?: at )((?:/api/3|/v4/integration)/[^\s:]+)'       # "...at /api/3/..." or "...at /v4/integration/..."
    r'|(?: from (?:\w+ )?)((?:/api/3|/v4/integration)/[^\s:]+)'  # "...from GET /api/3/..." or verbless "...from /api/3/..." (verb optional, both API versions)
)


def _extract_diagnostics(e: Exception) -> tuple[str | None, int | None]:
    """Pull an API path and HTTP status code out of a ``Rapid7ClientError``.

    Returns ``(None, None)`` for non-Rapid7ClientError exceptions. Path
    extraction relies on the v0.1.7 standardized message format which
    prefixes the failing path with " on <METHOD> ", " at ", or
    " from <METHOD> "; all three forms are matched.
    """
    if not isinstance(e, Rapid7ClientError):
        return None, None
    m = _ERROR_PATH_RE.search(str(e))
    path = (m.group(1) or m.group(2) or m.group(3)) if m else None
    return path, e.status_code


@dataclass
class RuleResult:
    """Result of running one audit rule or operational-check concept.

    `card_summary` — three canonical counts the report renders uniformly
    in the rule card header: ``{"examined": int, "passed": int, "failed": int}``.
    Set when the rule has a meaningful per-item population it examined;
    leave None for rules where "examined" is genuinely ambiguous
    (ratio questions, single-entity questions). Separate from
    ``summary`` to preserve the delta-blob signature on existing rules.
    """
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    card_summary: dict[str, int] | None = None
    sampled: bool = False
    sample_info: str | None = None
    sources: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int | None = None
    error_path: str | None = None
    error_status_code: int | None = None


class Rule(Protocol):
    rule_id: str
    rule_name: str
    description: str
    default_severity: Severity
    expensive: bool
    sources: list[str]

    def run(
        self,
        snapshot: Any,
        severity: Severity,
        full_scan: bool,
        sample_size: int,
        rule_config: dict,
    ) -> RuleResult: ...


_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register(rule_cls: type[Rule]) -> type[Rule]:
    _RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


def _rollup_audit_status(rule_results: list[RuleResult]) -> Status:
    if any(r.status in ("fail", "error") for r in rule_results):
        return "fail"
    if any(r.status == "warn" for r in rule_results):
        return "warn"
    return "pass"


def _flatten_findings(rule_results: list[RuleResult]) -> list[Finding]:
    return [f for r in rule_results for f in r.findings]


class ConfigurationAuditCheck:
    name = "Configuration Audit"
    description = "Best-practice configuration audits sourced from Rapid7 documentation."

    def run(self, client: Any, config: AppConfig, *, progress=None, **_kwargs: Any) -> CheckResult:
        # Accepts the uniform check-dispatch kwarg superset (snapshot,
        # cloud_client, progress) and uses only what it needs. See CONTEXT.md
        # "Check dispatch": __main__ hands every check the same kwargs.
        from rapid7_healthcheck.audit._runner import AuditCategory, AuditRunner, GateDecision

        def gate(client, config, _cloud) -> GateDecision:
            return GateDecision(
                enabled=config.audit.enabled,
                skip_reason="audit.enabled is false",
            )

        def build_snapshot(client, config, _cloud) -> EnvSnapshot:
            return EnvSnapshot(
                client,
                full_scan=config.audit.full_scan,
                sample_size=config.audit.sample_size,
                agents_timeout_seconds=config.audit.agents_timeout_seconds,
            )

        category = AuditCategory(
            name=self.name,
            description=self.description,
            progress_prefix="audit",
            registry=_RULE_REGISTRY,
            rules_config=lambda c: c.audit.rules,
            full_scan=config.audit.full_scan,
            sample_size=config.audit.sample_size,
            gate=gate,
            build_snapshot=build_snapshot,
        )
        return AuditRunner().run(category, client=client, config=config, progress=progress)


# Register every audit rule at package-import time by importing each module
# under `audit/rules/` so its @register decorator fires. The directory is the
# single source of truth — adding a new rule is just a new decorated file under
# `audit/rules/`, no import line to maintain. See CONTEXT.md "Rule registration".
from rapid7_healthcheck._rule_loader import load_rules  # noqa: E402

load_rules("rapid7_healthcheck.audit.rules")
