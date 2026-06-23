"""The three terminal rollups that turn a ``list[RuleResult]`` into the fields
of a ``CheckResult``: status, the flattened findings mirror, and the ``rules_*``
tile-strip summary.

Both runners assemble their ``CheckResult`` from these same three operations.
``AuditRunner`` and ``OpCheckRunner`` keep their own loops (they differ — one
drives a registry, the other a single ``produce_rule_results`` callable), but
the terminal rollup is identical, so it lives here once. Previously these were
three byte-identical pairs (``_rollup_audit_status``/``rollup_check_status``,
``_flatten_findings``/``flatten_findings``, ``_summary_counts``/``rule_summary``)
kept in sync by hand.

This module imports only ``RuleResult`` (from ``audit``) and ``Finding``/
``Status`` (from ``checks``) — the same import directions both runners already
use — so it introduces no new package cycle.
"""
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding, Status


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
