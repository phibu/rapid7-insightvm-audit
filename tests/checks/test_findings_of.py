"""Tests for `findings_of` -- the single iterator over a CheckResult's findings.

Owns the one fragile invariant the render + delta paths kept hand-copying:
walk `rule_results`' findings XOR the top-level `findings` mirror, never both
(indexing both double-counts a finding in the delta-blob signature index).
"""
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding, findings_of


def _finding(msg: str, severity: str = "warn") -> Finding:
    return Finding(severity=severity, message=msg)


def test_yields_rule_findings_tagged_with_rule_id():
    """A modern check yields each rule's findings tagged with that rule's id."""
    check = CheckResult(
        name="Scan Engines",
        description="",
        status="warn",
        rule_results=[
            RuleResult(
                rule_id="op.scan_engines.bad_status",
                rule_name="Bad status",
                description="",
                severity="warn",
                status="warn",
                findings=[_finding("engine A bad"), _finding("engine B bad")],
            ),
            RuleResult(
                rule_id="op.scan_engines.last_contact",
                rule_name="Last contact",
                description="",
                severity="warn",
                status="pass",
                findings=[_finding("engine C stale")],
            ),
        ],
    )

    result = list(findings_of(check))

    assert result == [
        ("op.scan_engines.bad_status", check.rule_results[0].findings[0]),
        ("op.scan_engines.bad_status", check.rule_results[0].findings[1]),
        ("op.scan_engines.last_contact", check.rule_results[1].findings[0]),
    ]


def test_does_not_double_count_when_top_level_findings_mirror_rule_findings():
    """The load-bearing invariant: when rule_results exist, the top-level
    `findings` mirror is IGNORED -- yielding it too would double-count every
    finding in the delta-blob signature index."""
    rule_findings = [_finding("dup me")]
    check = CheckResult(
        name="Data Quality",
        description="",
        status="warn",
        # The flattened mirror that flatten_findings() produces:
        findings=list(rule_findings),
        rule_results=[
            RuleResult(
                rule_id="op.data_quality.missing_os",
                rule_name="Missing OS",
                description="",
                severity="warn",
                status="warn",
                findings=rule_findings,
            ),
        ],
    )

    result = list(findings_of(check))

    # Exactly one -- not two.
    assert result == [("op.data_quality.missing_os", rule_findings[0])]


def test_legacy_check_without_rule_results_yields_top_level_tagged_with_name():
    """A pre-0.2.6 check has only top-level findings; yield them tagged with
    the check name (matching the historical delta-index fallback)."""
    f1, f2 = _finding("legacy 1"), _finding("legacy 2")
    check = CheckResult(
        name="Legacy Check",
        description="",
        status="warn",
        findings=[f1, f2],
        rule_results=None,
    )

    result = list(findings_of(check))

    assert result == [("Legacy Check", f1), ("Legacy Check", f2)]


def test_empty_rule_results_list_falls_back_to_top_level():
    """An empty (not None) rule_results list is falsy, so the legacy branch
    applies -- matches `if r.rule_results:` truthiness used at every call site."""
    f1 = _finding("only here")
    check = CheckResult(
        name="Edge",
        description="",
        status="warn",
        findings=[f1],
        rule_results=[],
    )

    result = list(findings_of(check))

    assert result == [("Edge", f1)]


def test_no_findings_yields_nothing():
    check = CheckResult(name="Quiet", description="", status="pass", rule_results=[])
    assert list(findings_of(check)) == []
