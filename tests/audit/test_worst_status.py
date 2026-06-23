"""Tests for ``worst_status`` — the single owner of the status precedence
``fail/error > warn > pass`` (see CONTEXT.md "worst_status").

It reduces any iterable of status-carrying items (``RuleResult`` or
``CheckResult`` — anything with a ``.status``) to the worst status. The report
verdict and the process exit code both map its result; the two runners reach it
through the ``rollup_status`` alias.
"""
from __future__ import annotations

from rapid7_healthcheck.audit.rule_rollup import rollup_status, worst_status
from rapid7_healthcheck.checks import CheckResult


def _check(status):
    return CheckResult(name="x", description="d", status=status)


def test_empty_is_pass():
    assert worst_status([]) == "pass"


def test_all_pass_is_pass():
    assert worst_status([_check("pass"), _check("pass")]) == "pass"


def test_any_warn_is_warn():
    assert worst_status([_check("pass"), _check("warn")]) == "warn"


def test_any_fail_is_fail():
    assert worst_status([_check("warn"), _check("fail")]) == "fail"


def test_error_counts_as_fail():
    assert worst_status([_check("pass"), _check("error")]) == "fail"


def test_fail_outranks_warn():
    assert worst_status([_check("warn"), _check("fail"), _check("pass")]) == "fail"


def test_skipped_does_not_escalate():
    """A skipped item is neither fail/error nor warn — it falls through to pass,
    so a self-skipped check/rule never escalates the run."""
    assert worst_status([_check("skipped"), _check("pass")]) == "pass"
    assert worst_status([_check("skipped")]) == "pass"


def test_skipped_alongside_warn_is_warn():
    assert worst_status([_check("skipped"), _check("warn")]) == "warn"


def test_rollup_status_is_the_same_owner():
    """rollup_status is a bare alias of worst_status — the same callable."""
    assert rollup_status is worst_status
