from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import ReportContext, render_report, write_report


def _ctx(results: list[CheckResult]) -> ReportContext:
    return ReportContext(
        title="Test Report",
        generated_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
        base_url_host="us.api.insight.rapid7.com",
        tool_version="0.1.0",
        config_path="config.yaml",
        results=results,
        thresholds_table=[("scan_engines.last_contact_warn_hours", "2")],
    )


def test_renders_pass_verdict_when_all_pass():
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert "Healthy" in html
    assert "Test Report" in html


def test_renders_warn_verdict_for_any_warn():
    r = CheckResult(
        name="X", description="x", status="warn",
        findings=[Finding(severity="warn", message="something")],
    )
    html = render_report(_ctx([r]))
    assert "Warnings" in html
    assert "something" in html


def test_renders_fail_verdict_for_any_fail():
    r = CheckResult(
        name="X", description="x", status="fail",
        findings=[Finding(severity="fail", message="boom")],
    )
    html = render_report(_ctx([r]))
    assert "Action required" in html


def test_error_status_includes_error_message():
    r = CheckResult(name="X", description="x", status="error", error="kaboom")
    html = render_report(_ctx([r]))
    assert "kaboom" in html


def test_skipped_status_explained():
    r = CheckResult(name="X", description="x", status="skipped")
    html = render_report(_ctx([r]))
    assert "skipped" in html.lower() or "disabled" in html.lower()


def test_no_external_resources():
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert "<script" not in html
    assert "https://cdn" not in html
    assert "//cdn" not in html


def test_write_report_uses_filename_pattern(tmp_path):
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    out = write_report(
        ctx,
        output_dir=tmp_path,
        filename_pattern="rapid7-health-{timestamp}.html",
    )
    assert out.parent == tmp_path
    assert out.name.startswith("rapid7-health-")
    assert out.suffix == ".html"
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_write_report_explicit_output_path(tmp_path):
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    explicit = tmp_path / "fixed.html"
    out = write_report(ctx, explicit_path=explicit)
    assert out == explicit
    assert explicit.exists()


def test_finding_details_rendered_as_pretty_json():
    r = CheckResult(
        name="X", description="x", status="warn",
        findings=[Finding(severity="warn", message="m", details={"k": "v"})],
    )
    html = render_report(_ctx([r]))
    assert "\"k\":" in html
    assert "\"v\"" in html
