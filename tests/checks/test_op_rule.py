from __future__ import annotations

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
