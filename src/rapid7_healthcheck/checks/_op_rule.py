"""Helpers for operational checks that emit `RuleResult`s.

Operational checks (`scan_engines`, `scan_activity`, `asset_coverage`,
`data_quality`) historically produced flat `Finding` lists. As of 0.2.6 they
emit one `RuleResult` per concept so the report renders them with the same
rule-card layout as the audit checks.

Rule IDs follow the `op.<check>.<concept>` convention to keep them distinct
from audit `rule_id`s in the delta blob's signature index.
"""
from __future__ import annotations

import logging
import time
from dataclasses import replace
from typing import Callable, Iterable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding, Severity, Status

logger = logging.getLogger(__name__)


def make_rule_result(
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    findings: list[Finding],
    sources: Iterable[str] = (),
    summary: dict | None = None,
    duration_ms: int | None = None,
    default_severity: Severity = "warn",
    sampled: bool = False,
    sample_info: str | None = None,
    examined: int | None = None,
    failed: int | None = None,
) -> RuleResult:
    """Build a RuleResult for an operational check concept.

    Status is derived from the highest-severity finding (fail > warn > pass).
    `default_severity` is the rule's own severity tag — it's used by the
    state-blob/delta logic; individual finding severities still control rollup.

    `examined` / `failed`: when BOTH are provided, build a standardized
    `card_summary` of ``{"examined": N, "passed": N - failed, "failed": failed}``
    for uniform rule-card rendering. `passed` is clamped to >= 0 defensively
    (failed > examined is a programming bug, but render 0 not negative).
    Pass None for rules where "examined" is genuinely ambiguous.
    """
    status: Status
    if any(f.severity == "fail" for f in findings):
        status = "fail"
    elif any(f.severity == "warn" for f in findings):
        status = "warn"
    else:
        status = "pass"

    card_summary: dict[str, int] | None = None
    if examined is not None and failed is not None:
        card_summary = {
            "examined": examined,
            "passed": max(0, examined - failed),
            "failed": failed,
        }

    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        description=description,
        severity=default_severity,
        status=status,
        findings=list(findings),
        summary=summary or {},
        card_summary=card_summary,
        sources=list(sources),
        duration_ms=duration_ms,
        sampled=sampled,
        sample_info=sample_info,
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


def error_rule(
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    error: Exception,
    sources: Iterable[str] = (),
    duration_ms: int | None = None,
    default_severity: Severity = "warn",
) -> RuleResult:
    """Build an error RuleResult for an op-check concept whose execution raised.

    Mirrors the audit orchestrator's per-rule isolation pattern: when a single
    rule's API call raises, the surrounding check still produces a CheckResult
    with the remaining rules' output, and the failing rule shows as error in
    the report rather than blacking out the entire check.

    `error_path` and `error_status_code` are populated from a Rapid7ClientError;
    other exception types leave them None.
    """
    # Defer import to avoid a circular dependency at module load time.
    from rapid7_healthcheck.audit import _extract_diagnostics
    error_path, error_status_code = _extract_diagnostics(error)
    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        description=description,
        severity=default_severity,
        status="error",
        findings=[],
        summary={"error": str(error)[:300]},
        sources=list(sources),
        duration_ms=duration_ms,
        error=str(error),
        error_path=error_path,
        error_status_code=error_status_code,
    )


def safe_run(
    fn: Callable[[], RuleResult],
    *,
    rule_id: str,
    rule_name: str,
    description: str,
    sources: Iterable[str] = (),
    default_severity: Severity = "warn",
) -> RuleResult:
    """Run a rule producer; on any Exception, return an error_rule.

    Identity (rule_id/name/description/sources) is supplied by the caller
    because the rule method may raise before returning, so we cannot read
    its internal constants reflectively. Drift between the wrapper's
    identity and the rule method's own constants is caught by per-check
    unit tests that assert rule_id stability.

    `default_severity` is the rule's own severity tag — used by the
    state-blob/delta logic; surfaces in the synthesized error_rule when
    the producer raises.
    """
    rule_start = time.monotonic()
    try:
        result = fn()
    except Exception as e:
        logger.exception("op-check rule %s raised", rule_id)
        return error_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            sources=sources,
            error=e,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
            default_severity=default_severity,
        )
    duration_ms = int((time.monotonic() - rule_start) * 1000)
    # If the rule producer didn't set its own timing (the common case —
    # make_rule_result() defaults duration_ms=None), stamp the wall-clock
    # elapsed so the per-rule card in the report shows a real timing.
    # A rule that explicitly set duration_ms=0 (measured sub-millisecond)
    # is preserved as-is — None is the unambiguous "not measured" sentinel.
    if result.duration_ms is None:
        return replace(result, duration_ms=duration_ms)
    return result


def safe_run_rule(rule, fn: Callable[[], RuleResult]) -> RuleResult:
    """Run a rule's producer, reading identity from the rule's class attributes.

    Convenience wrapper over `safe_run` for rule classes that declare their
    identity as `RULE_ID`, `RULE_NAME`, `DESCRIPTION`, `DEFAULT_SEVERITY`,
    `SOURCES` class attributes. The helper preserves `safe_run`'s contract:
    on any exception in `fn`, returns an `error_rule` keyed on the rule's
    identity instead of propagating.
    """
    return safe_run(
        fn,
        rule_id=rule.RULE_ID,
        rule_name=rule.RULE_NAME,
        description=rule.DESCRIPTION,
        sources=rule.SOURCES,
        default_severity=rule.DEFAULT_SEVERITY,
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
