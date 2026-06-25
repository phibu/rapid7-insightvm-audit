"""Tests for OpCheckRunner / OpCheckDescriptor -- the operational-vertical
mirror of AuditRunner / AuditCategory.

The runner owns the envelope every operational check repeats verbatim: start
timer -> rollup_check_status -> flatten_findings -> rule_summary -> assemble
CheckResult. The per-check irreducible behaviour (shared-fetch closures,
heterogeneous rule signatures, peek/paginate dances, the safe_run_rule per-rule
trap) lives inside the descriptor's single `produce_rule_results` callable.
"""
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_runner import OpCheckDescriptor, OpCheckRunner


def _rule(rule_id: str, status: str, findings=()) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_id,
        description="",
        severity="warn",
        status=status,
        findings=list(findings),
    )


def test_assembles_check_result_from_produced_rules():
    """The runner calls produce_rule_results and wraps the list in a
    CheckResult with the right name/description and the rules attached."""
    rules = [_rule("op.x.a", "pass"), _rule("op.x.b", "warn")]

    descriptor = OpCheckDescriptor(
        name="Demo Check",
        description="a demo",
        produce_rule_results=lambda client, config, snapshot: rules,
    )

    result = OpCheckRunner().run(descriptor, client=object(), config=object(), snapshot=object())

    assert isinstance(result, CheckResult)
    assert result.name == "Demo Check"
    assert result.description == "a demo"
    assert result.rule_results == rules


def test_rolls_up_status_fail_beats_warn_beats_pass():
    rules = [_rule("op.x.a", "pass"), _rule("op.x.b", "warn"), _rule("op.x.c", "fail")]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.status == "fail"


def test_error_status_rolls_up_to_fail():
    rules = [_rule("op.x.a", "pass"), _rule("op.x.b", "error")]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.status == "fail"


def test_flattens_findings_across_rules():
    f1, f2 = Finding("warn", "one"), Finding("fail", "two")
    rules = [_rule("op.x.a", "warn", [f1]), _rule("op.x.b", "fail", [f2])]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.findings == [f1, f2]


def test_summary_counts_rules_by_status():
    rules = [
        _rule("op.x.a", "pass"),
        _rule("op.x.b", "warn"),
        _rule("op.x.c", "fail"),
        _rule("op.x.d", "skipped"),
    ]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.summary["rules_total"] == 4
    assert result.summary["rules_pass"] == 1
    assert result.summary["rules_warn"] == 1
    assert result.summary["rules_fail"] == 1
    assert result.summary["rules_skipped"] == 1


def test_all_pass_is_pass_with_empty_findings():
    rules = [_rule("op.x.a", "pass"), _rule("op.x.b", "pass")]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.status == "pass"
    assert result.findings == []


def test_duration_is_stamped():
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: [_rule("op.x.a", "pass")]
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert result.duration_ms is not None
    assert result.duration_ms >= 0


def test_summary_extra_is_merged_onto_rule_summary():
    """A check whose check-level summary carries more than the rules_* rollup
    (scan_engines folds in engine counts) supplies a summary_extra callable;
    the runner merges its dict on top of rule_summary."""
    rules = [_rule("op.x.a", "pass")]
    descriptor = OpCheckDescriptor(
        name="C",
        description="",
        produce_rule_results=lambda c, cfg, s: rules,
        summary_extra=lambda rrs: {"engines_total": 7, "engines_healthy": 7},
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    # rules_* rollup still present...
    assert result.summary["rules_total"] == 1
    # ...plus the check-specific extras.
    assert result.summary["engines_total"] == 7
    assert result.summary["engines_healthy"] == 7


def test_summary_extra_defaults_to_none_and_is_omitted():
    """Checks with no extra summary leave summary_extra unset; summary is just
    the rules_* rollup."""
    rules = [_rule("op.x.a", "pass")]
    descriptor = OpCheckDescriptor(
        name="C", description="", produce_rule_results=lambda c, cfg, s: rules
    )
    result = OpCheckRunner().run(descriptor, client=None, config=None, snapshot=None)
    assert set(result.summary) == {
        "rules_total", "rules_pass", "rules_warn", "rules_fail",
        "rules_error", "rules_skipped",
    }


def test_produce_receives_client_config_snapshot():
    """The three positional args are forwarded verbatim to the callable."""
    seen = {}

    def produce(client, config, snapshot):
        seen["client"] = client
        seen["config"] = config
        seen["snapshot"] = snapshot
        return []

    client, config, snapshot = object(), object(), object()
    descriptor = OpCheckDescriptor(name="C", description="", produce_rule_results=produce)
    OpCheckRunner().run(descriptor, client=client, config=config, snapshot=snapshot)

    assert seen == {"client": client, "config": config, "snapshot": snapshot}
