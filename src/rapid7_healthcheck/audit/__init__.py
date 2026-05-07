from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding, Severity, Status
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)

_ERROR_PATH_RE = re.compile(
    r' on \w+ (/api/3/[^\s:]+)'        # "network error after N attempt(s) on GET /api/3/..."
    r'|(?: at )(/api/3/[^\s:]+)'       # "401 at /api/3/..."
    r'|(?: from \w+ )(/api/3/[^\s:]+)' # "HTTP 500 from POST /api/3/..."
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
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    sampled: bool = False
    sample_info: str | None = None
    sources: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
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

    def run(self, client: Any, config: AppConfig, progress=None) -> CheckResult:
        start = time.monotonic()

        if not config.audit.enabled:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[],
                summary={"reason": "audit.enabled is false"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        snapshot = EnvSnapshot(
            client,
            full_scan=config.audit.full_scan,
            sample_size=config.audit.sample_size,
            agents_timeout_seconds=config.audit.agents_timeout_seconds,
        )

        rule_results: list[RuleResult] = []
        total_rules = len(_RULE_REGISTRY)
        for rule_idx, (rule_id, rule_cls) in enumerate(_RULE_REGISTRY.items(), start=1):
            rule_cfg = config.audit.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                if progress is not None:
                    skipped_label = f"audit: {rule_id} (skipped)"
                    progress.step(rule_idx, total_rules, skipped_label)
                    progress.done(rule_idx, total_rules, skipped_label, duration_ms=0)
                continue
            label = f"audit: {rule_id}"
            if progress is not None:
                progress.step(rule_idx, total_rules, label)
            rule_start = time.monotonic()
            try:
                try:
                    result = rule_cls().run(
                        snapshot,
                        rule_cfg.severity,
                        config.audit.full_scan,
                        config.audit.sample_size,
                        rule_cfg.knobs,
                    )
                    result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                    rule_results.append(result)
                except Exception as e:
                    logger.exception("audit rule %s raised", rule_id)
                    error_path, error_status_code = _extract_diagnostics(e)
                    rule_results.append(RuleResult(
                        rule_id=rule_id,
                        rule_name=rule_cls.rule_name,
                        description=rule_cls.description,
                        severity=rule_cfg.severity,
                        status="error",
                        sources=list(rule_cls.sources),
                        error=str(e),
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                        error_path=error_path,
                        error_status_code=error_status_code,
                    ))
            finally:
                if progress is not None:
                    progress.done(
                        rule_idx, total_rules, label,
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                    )

        return CheckResult(
            name=self.name,
            description=self.description,
            status=_rollup_audit_status(rule_results),
            findings=_flatten_findings(rule_results),
            summary={
                "rules_total": len(rule_results),
                "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
                "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
                "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
                "rules_error": sum(1 for r in rule_results if r.status == "error"),
                "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )


# Side-effect imports: register all 12 audit rules at package-import time.
# Adding a new rule = one new file under `audit/rules/` + one line here.
from rapid7_healthcheck.audit.rules import (  # noqa: E402,F401
    agent_unauth_collision,
    site_vuln_template_no_creds,
    overlapping_scan_windows,
    single_engine_overload,
    discovery_template_on_prod_site,
    policy_and_vuln_in_same_template,
    local_engine_production_scope,
    dynamic_groups_and_nested_tags,
    scan_report_schedule_overlap,
    engine_version_drift,
    insight_agent_deployed,
)
