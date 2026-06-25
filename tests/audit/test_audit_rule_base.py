"""Tests for ``AuditRule.result`` -- the shared result-build the four audit
categories' rules inherit (see CONTEXT.md "AuditRule").

These assert the build's observable output: derived status, forwarded identity,
the ``card_summary`` shape, and the sampling fields -- the contract every
migrated rule relies on staying byte-identical.
"""
from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule
from rapid7_healthcheck.checks import Finding


class _SampleRule(AuditRule):
    rule_id = "sample_rule"
    rule_name = "Sample Rule"
    description = "A rule used only to exercise AuditRule.result()."
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/"]


def test_result_derives_fail_status_from_findings():
    rule = _SampleRule()
    r = rule.result(
        [Finding(severity="fail", message="boom")],
        severity="fail",
    )
    assert r.status == "fail"


def test_result_derives_warn_status_from_findings():
    rule = _SampleRule()
    r = rule.result(
        [Finding(severity="warn", message="careful")],
        severity="warn",
    )
    assert r.status == "warn"


def test_result_info_only_findings_stay_pass():
    """An info finding alone must not escalate status (the deliberate
    info-doesn't-escalate rule -- see severity semantics in CLAUDE.md)."""
    rule = _SampleRule()
    r = rule.result(
        [Finding(severity="info", message="fyi")],
        severity="warn",
    )
    assert r.status == "pass"


def test_result_forwards_rule_identity_from_self():
    rule = _SampleRule()
    r = rule.result([], severity="warn")
    assert r.rule_id == "sample_rule"
    assert r.rule_name == "Sample Rule"
    assert r.description == _SampleRule.description
    assert r.sources == ["https://docs.rapid7.com/insightvm/"]


def test_result_severity_is_the_runtime_arg_not_default():
    """RuleResult.severity must be the config-overridden run-time value, not
    self.default_severity -- the two diverge under an operator override and the
    field feeds the state blob."""
    rule = _SampleRule()  # default_severity == "warn"
    r = rule.result([], severity="fail")
    assert r.severity == "fail"


def test_result_builds_card_summary_from_examined_and_failed():
    rule = _SampleRule()
    r = rule.result(
        [Finding(severity="warn", message="x")],
        severity="warn",
        examined=10,
        failed=3,
    )
    assert r.card_summary == {"examined": 10, "passed": 7, "failed": 3}


def test_result_omits_card_summary_when_counts_absent():
    rule = _SampleRule()
    r = rule.result([], severity="warn")
    assert r.card_summary is None


def test_result_forwards_summary_and_sampling_fields():
    rule = _SampleRule()
    r = rule.result(
        [],
        severity="warn",
        summary={"k": 1},
        sampled=True,
        sample_info="sampled 5 of 50",
    )
    assert r.summary == {"k": 1}
    assert r.sampled is True
    assert r.sample_info == "sampled 5 of 50"
