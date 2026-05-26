from __future__ import annotations

import time

import pytest

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import Finding
from rapid7_healthcheck.checks._op_rule import make_rule_result, safe_run
from rapid7_healthcheck.client import Rapid7ClientError


def _success_rule() -> RuleResult:
    return RuleResult(
        rule_id="op.test.success",
        rule_name="Success",
        description="Always passes",
        severity="warn",
        status="pass",
        findings=[],
        summary={"ok": True},
        sources=[],
    )


def test_safe_run_returns_fn_result_on_success():
    """safe_run is a transparent passthrough when the rule producer returns normally."""
    result = safe_run(
        _success_rule,
        rule_id="op.test.success",
        rule_name="Success",
        description="Always passes",
        sources=["https://example.test/source"],
    )
    assert result.rule_id == "op.test.success"
    assert result.status == "pass"
    assert result.summary == {"ok": True}


def test_safe_run_returns_error_rule_on_exception():
    """safe_run synthesizes an error_rule when the producer raises."""
    def raises():
        raise Rapid7ClientError("Read timed out", status_code=None)

    result = safe_run(
        raises,
        rule_id="op.test.boom",
        rule_name="Boom",
        description="This rule always raises",
        sources=["https://example.test/boom-docs"],
    )
    assert result.rule_id == "op.test.boom"
    assert result.status == "error"
    assert "Read timed out" in (result.error or "")
    assert result.rule_name == "Boom"
    assert result.description == "This rule always raises"
    assert "https://example.test/boom-docs" in result.sources
    assert result.duration_ms >= 0


def test_safe_run_populates_status_code_for_rapid7_client_error():
    """For a Rapid7ClientError with a status_code, the synthesized error_rule
    must carry error_status_code so the report can render it inline."""
    def raises_500():
        raise Rapid7ClientError("HTTP 500 from GET /api/3/x: server error", status_code=500)

    result = safe_run(
        raises_500,
        rule_id="op.test.5xx",
        rule_name="500",
        description="raises 500",
        sources=[],
    )
    assert result.error_status_code == 500


def test_safe_run_handles_arbitrary_exception_types():
    """Non-Rapid7ClientError exceptions also produce an error_rule (with
    error_path=None and error_status_code=None — the diagnostics extractor
    only knows how to read Rapid7ClientError). Also covers the default
    `sources=()` argument: when omitted, the synthesized error_rule
    surfaces an empty sources list."""
    def raises():
        raise ValueError("not a Rapid7ClientError")

    # Note: no `sources=` kwarg — exercises the default `sources=()`.
    result = safe_run(
        raises,
        rule_id="op.test.value_err",
        rule_name="ValueError",
        description="raises ValueError",
    )
    assert result.status == "error"
    assert result.error_status_code is None
    assert "not a Rapid7ClientError" in (result.error or "")
    assert result.sources == []
    assert result.duration_ms >= 0


def test_safe_run_sets_duration_ms_on_success_path():
    """safe_run measures wall-clock time on the success path and sets
    duration_ms on the returned RuleResult when the rule producer did not
    populate it itself (i.e. it defaulted to 0)."""
    def slow_rule():
        time.sleep(0.01)  # 10ms minimum
        return make_rule_result(
            rule_id="op.test.rule",
            rule_name="Test",
            description="d",
            findings=[],
        )

    result = safe_run(
        slow_rule,
        rule_id="op.test.rule",
        rule_name="Test",
        description="d",
    )
    assert result.duration_ms >= 10, f"expected >=10ms, got {result.duration_ms}"


def test_safe_run_preserves_explicit_duration_ms():
    """If the rule producer explicitly set duration_ms, safe_run must not
    overwrite it. Lets a rule report its own internal timing if it cares to."""
    def rule_with_own_timing():
        return make_rule_result(
            rule_id="op.test.rule2",
            rule_name="Test2",
            description="d",
            findings=[],
            duration_ms=999,
        )

    result = safe_run(
        rule_with_own_timing,
        rule_id="op.test.rule2",
        rule_name="Test2",
        description="d",
    )
    assert result.duration_ms == 999


def test_make_rule_result_default_sampled_false():
    """make_rule_result defaults sampled=False and sample_info=None."""
    r = make_rule_result(
        rule_id="op.x.y", rule_name="X", description="d",
        findings=[],
    )
    assert r.sampled is False
    assert r.sample_info is None


def test_make_rule_result_passes_sampled_and_sample_info():
    """make_rule_result accepts and passes through sampled and sample_info kwargs."""
    r = make_rule_result(
        rule_id="op.x.y", rule_name="X", description="d",
        findings=[],
        sampled=True,
        sample_info="strategy=first-n; sampled=100; population=500000",
    )
    assert r.sampled is True
    assert r.sample_info == "strategy=first-n; sampled=100; population=500000"


class _IdRule:
    """Minimal rule shape for testing safe_run_rule."""
    RULE_ID = "op.test.id_rule"
    RULE_NAME = "Test rule"
    DESCRIPTION = "A rule used by the safe_run_rule tests."
    DEFAULT_SEVERITY = "warn"
    SOURCES = ("https://example.com/docs",)


def test_safe_run_rule_dispatches_with_class_attrs():
    """Success path: helper reads class-level identity and forwards to safe_run."""
    from rapid7_healthcheck.checks._op_rule import safe_run_rule

    rule = _IdRule()
    sentinel = make_rule_result(
        rule_id=rule.RULE_ID,
        rule_name=rule.RULE_NAME,
        description=rule.DESCRIPTION,
        findings=[],
        sources=rule.SOURCES,
        default_severity=rule.DEFAULT_SEVERITY,
    )

    result = safe_run_rule(rule, lambda: sentinel)

    # safe_run may stamp duration_ms via dataclasses.replace, producing a new
    # instance with the same field values — compare on identity-defining fields
    # rather than `is`, which would be coupled to the absence of replace().
    assert result.rule_id == sentinel.rule_id
    assert result.rule_name == sentinel.rule_name
    assert result.description == sentinel.description
    assert result.status == sentinel.status
    assert result.findings == sentinel.findings
    assert result.summary == sentinel.summary
    assert result.sources == sentinel.sources
    assert result.rule_id == "op.test.id_rule"
    assert result.rule_name == "Test rule"


def test_safe_run_rule_synthesizes_error_rule_on_exception():
    """Failure path: when fn raises, helper returns an error_rule keyed on the class identity."""
    from rapid7_healthcheck.checks._op_rule import safe_run_rule

    rule = _IdRule()

    def boom() -> RuleResult:
        raise RuntimeError("simulated failure")

    result = safe_run_rule(rule, boom)

    assert result.status == "error"
    assert result.rule_id == "op.test.id_rule"
    assert result.rule_name == "Test rule"
    assert result.description == "A rule used by the safe_run_rule tests."
    assert result.severity == "warn"  # DEFAULT_SEVERITY
    assert "simulated failure" in (result.error or "")


def test_op_check_rule_classes_declare_identity_constants():
    """Every op-check rule class declares the five identity class attributes.

    Class-level identity constants make rid/name/description drift between
    call site and method body structurally impossible. This test verifies
    every rule class in every op-check module has the full identity set.
    """
    from rapid7_healthcheck.checks import asset_coverage, data_quality, scan_engines, scan_activity

    expected_attrs = ("RULE_ID", "RULE_NAME", "DESCRIPTION", "DEFAULT_SEVERITY", "SOURCES")
    rule_classes_found = 0
    for module in (asset_coverage, data_quality, scan_engines, scan_activity):
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and name.endswith("Rule") and not name.startswith("_"):
                for attr in expected_attrs:
                    assert hasattr(obj, attr), f"{module.__name__}.{name} missing {attr}"
                rule_classes_found += 1
    # Sanity: we expect at least 19 op-check rule classes across the four modules.
    # (4 in asset_coverage, 5 in data_quality, 4 in scan_engines, 6 in scan_activity = 19)
    # If the count drops below 19, a rule class was deleted or renamed.
    assert rule_classes_found >= 19, (
        f"Expected >= 19 op-check rule classes, found {rule_classes_found}. "
        "A rule class may have been deleted or renamed."
    )
