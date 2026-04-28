from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from rapid7_healthcheck.checks import CheckResult, Finding, Severity, Status
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


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

    def run(self, client: Any, config: AppConfig) -> CheckResult:
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

        from rapid7_healthcheck.audit.snapshot import EnvSnapshot
        snapshot = EnvSnapshot(
            client,
            full_scan=config.audit.full_scan,
            sample_size=config.audit.sample_size,
        )

        rule_results: list[RuleResult] = []
        for rule_id, rule_cls in _RULE_REGISTRY.items():
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
                continue
            rule_start = time.monotonic()
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
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity=rule_cfg.severity,
                    status="error",
                    sources=list(rule_cls.sources),
                    error=str(e),
                    duration_ms=int((time.monotonic() - rule_start) * 1000),
                ))

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
