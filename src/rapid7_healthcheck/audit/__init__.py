from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from rapid7_healthcheck.audit.snapshot import EnvSnapshot, build_env_snapshot
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


class AuditRule:
    """Base for the four audit categories' concrete rules — the single owner of
    the findings -> ``RuleResult`` build (see CONTEXT.md "AuditRule").

    Subclasses declare their identity as class attributes (``rule_id``,
    ``rule_name``, ``description``, ``default_severity``, ``expensive``,
    ``sources``) and call ``self.result(...)`` at each return point instead of
    hand-rolling the ``fail > warn > pass`` status derivation, the
    ``card_summary`` shape, and the ``RuleResult(...)`` metadata wrap. The build
    delegates to ``rule_rollup.make_rule_result`` — the same builder the
    operational checks use — so both verticals share one result-build.

    ``AuditRule`` *structurally* satisfies the ``Rule`` protocol; inheritance
    leaves the registry and ``AuditRunner`` dispatch untouched (``@register``
    still keys on ``rule_id``).
    """

    rule_id: str
    rule_name: str
    description: str
    default_severity: Severity
    expensive: bool
    sources: list[str]

    def result(
        self,
        findings: list[Finding],
        *,
        severity: Severity,
        summary: dict | None = None,
        examined: int | None = None,
        failed: int | None = None,
        sampled: bool = False,
        sample_info: str | None = None,
        card_summary: dict[str, int] | None = None,
    ) -> RuleResult:
        """Build this rule's ``RuleResult`` from its findings.

        ``severity`` is the config-overridden run-time severity (passed
        explicitly, not read from ``self.default_severity`` — the two diverge
        under an operator override and ``RuleResult.severity`` feeds the state
        blob). Status is derived from the findings; ``card_summary`` is built
        from ``examined``/``failed`` when both are given, or passed through when
        the rule already shaped one. ``duration_ms`` is stamped by
        ``AuditRunner`` after ``run`` returns, so rules never set it here.
        """
        # Deferred import: ``rule_rollup`` imports ``RuleResult`` from this
        # package, so importing it at module top level would be a cycle during
        # package init (same idiom as ``_op_rule._extract_diagnostics``).
        from rapid7_healthcheck.audit.rule_rollup import make_rule_result

        return make_rule_result(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            findings=findings,
            sources=self.sources,
            summary=summary,
            default_severity=severity,
            sampled=sampled,
            sample_info=sample_info,
            examined=examined,
            failed=failed,
            card_summary=card_summary,
        )


_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register(rule_cls: type[Rule]) -> type[Rule]:
    _RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


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
            return build_env_snapshot(
                client,
                sampling=config.audit,
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
