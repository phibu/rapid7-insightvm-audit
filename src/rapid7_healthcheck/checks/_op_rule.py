"""Helpers for operational checks that emit `RuleResult`s.

Operational checks (`scan_engines`, `scan_activity`, `asset_coverage`,
`data_quality`) historically produced flat `Finding` lists. As of 0.2.6 they
emit one `RuleResult` per concept so the report renders them with the same
rule-card layout as the audit checks.

Rule IDs follow the `op.<check>.<concept>` convention to keep them distinct
from audit `rule_id`s in the delta blob's signature index.
"""
from __future__ import annotations

from typing import Iterable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding, Severity, Status


def make_rule_result(
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    findings: list[Finding],
    sources: Iterable[str] = (),
    summary: dict | None = None,
    duration_ms: int = 0,
    default_severity: Severity = "warn",
) -> RuleResult:
    """Build a RuleResult for an operational check concept.

    Status is derived from the highest-severity finding (fail > warn > pass).
    `default_severity` is the rule's own severity tag — it's used by the
    state-blob/delta logic; individual finding severities still control rollup.
    """
    status: Status
    if any(f.severity == "fail" for f in findings):
        status = "fail"
    elif any(f.severity == "warn" for f in findings):
        status = "warn"
    else:
        status = "pass"

    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        description=description,
        severity=default_severity,
        status=status,
        findings=list(findings),
        summary=summary or {},
        sources=list(sources),
        duration_ms=duration_ms,
    )


def skipped_rule(
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    sources: Iterable[str] = (),
) -> RuleResult:
    """Build a skipped RuleResult — used when a concept's threshold flag is off."""
    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        description=description,
        severity="info",
        status="skipped",
        sources=list(sources),
    )


def rollup_check_status(rule_results: list[RuleResult]) -> Status:
    """Aggregate rule statuses into a check-level status.

    Mirrors `audit._rollup_audit_status`. Pure pass when every rule passed
    or was skipped; warn if any warned; fail if any failed or errored.
    """
    if any(r.status in ("fail", "error") for r in rule_results):
        return "fail"
    if any(r.status == "warn" for r in rule_results):
        return "warn"
    return "pass"


def flatten_findings(rule_results: list[RuleResult]) -> list[Finding]:
    return [f for r in rule_results for f in r.findings]


def rule_summary(rule_results: list[RuleResult]) -> dict:
    """Build the tile-strip summary dict expected by report.html.j2.

    Mirrors the shape produced by `ConfigurationAuditCheck` so the template's
    rule-tile branch renders for operational checks too.
    """
    return {
        "rules_total": len(rule_results),
        "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
        "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
        "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
        "rules_error": sum(1 for r in rule_results if r.status == "error"),
        "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
    }
