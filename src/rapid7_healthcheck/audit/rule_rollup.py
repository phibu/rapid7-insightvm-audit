"""The shared result-build and the three terminal rollups at the audit/checks
seam.

``make_rule_result`` builds one ``RuleResult`` from a findings list (deriving
status and the card summary); ``rollup_status`` / ``flatten_findings`` /
``rule_summary`` turn a ``list[RuleResult]`` into the fields of a
``CheckResult``. The build is the per-rule mirror of the per-check rollups, so
it lives alongside them rather than in the op-only ``_op_rule`` module where it
started — both verticals share it now: the operational checks call
``make_rule_result`` directly, the audit rules reach it through
``AuditRule.result`` (see CONTEXT.md "AuditRule"). ``_op_rule`` re-exports
``make_rule_result`` so its existing call sites are unchanged.

Both runners assemble their ``CheckResult`` from the same three rollups.
``AuditRunner`` and ``OpCheckRunner`` keep their own loops (they differ — one
drives a registry, the other a single ``produce_rule_results`` callable), but
the terminal rollup is identical, so it lives here once. Previously these were
three byte-identical pairs (``_rollup_audit_status``/``rollup_check_status``,
``_flatten_findings``/``flatten_findings``, ``_summary_counts``/``rule_summary``)
kept in sync by hand.

This module imports only ``RuleResult`` (from ``audit``) and ``Finding``/
``Severity``/``Status`` (from ``checks``) — the same import directions both
runners already use — so it introduces no new package cycle.
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
    duration_ms: int | None = None,
    default_severity: Severity = "warn",
    sampled: bool = False,
    sample_info: str | None = None,
    examined: int | None = None,
    failed: int | None = None,
    card_summary: dict[str, int] | None = None,
) -> RuleResult:
    """Build a RuleResult from findings, deriving status and the card summary.

    Status is derived from the highest-severity finding (fail > warn > pass);
    an ``info``-only finding set stays ``pass`` (info never escalates). This is
    the one owner of the findings -> RuleResult build, shared by both the
    operational checks (which call it directly) and the audit rules (which reach
    it through ``AuditRule.result`` — see CONTEXT.md "AuditRule").

    `default_severity` is the RuleResult's own severity tag — for op-checks it is
    the rule's fixed tag; for audit rules ``AuditRule.result`` passes the
    config-overridden run-time severity here (the two diverge under an override
    and the field feeds the state blob).

    `examined` / `failed`: when BOTH are provided, build a standardized
    `card_summary` of ``{"examined": N, "passed": N - failed, "failed": failed}``
    for uniform rule-card rendering. `passed` is clamped to >= 0 defensively
    (failed > examined is a programming bug, but render 0 not negative). Pass an
    explicit `card_summary` instead when the rule already shaped one; pass
    neither for rules where "examined" is genuinely ambiguous.
    """
    status: Status
    if any(f.severity == "fail" for f in findings):
        status = "fail"
    elif any(f.severity == "warn" for f in findings):
        status = "warn"
    else:
        status = "pass"

    if card_summary is None and examined is not None and failed is not None:
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


def rollup_status(rule_results: list[RuleResult]) -> Status:
    """Aggregate rule statuses into a check-level status.

    Pure pass when every rule passed or was skipped; warn if any warned; fail
    if any failed or errored.
    """
    if any(r.status in ("fail", "error") for r in rule_results):
        return "fail"
    if any(r.status == "warn" for r in rule_results):
        return "warn"
    return "pass"


def flatten_findings(rule_results: list[RuleResult]) -> list[Finding]:
    """The top-level ``CheckResult.findings`` mirror — every rule's findings,
    flattened. Indexing both this and ``rule_results`` double-counts a finding
    in the delta-blob signature index; see ``checks.findings_of``.
    """
    return [f for r in rule_results for f in r.findings]


def rule_summary(rule_results: list[RuleResult]) -> dict:
    """Build the tile-strip ``rules_*`` summary expected by report.html.j2."""
    return {
        "rules_total": len(rule_results),
        "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
        "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
        "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
        "rules_error": sum(1 for r in rule_results if r.status == "error"),
        "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
    }
