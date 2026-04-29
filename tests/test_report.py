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


from rapid7_healthcheck.audit import RuleResult


def test_audit_section_renders_per_rule_table():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="rule one desc",
            severity="warn", status="warn",
            findings=[Finding(severity="warn", message="something off")],
            sources=["https://docs.rapid7.com/foo"],
        ),
        RuleResult(
            rule_id="r2", rule_name="Rule Two", description="rule two desc",
            severity="info", status="pass",
            sources=["https://docs.rapid7.com/bar"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="warn",
        findings=[Finding(severity="warn", message="something off")],
        summary={"rules_total": 2, "rules_warn": 1, "rules_pass": 1,
                 "rules_fail": 0, "rules_error": 0, "rules_skipped": 0},
        rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    assert "Rule One" in html
    assert "Rule Two" in html
    assert "rule one desc" in html
    assert "https://docs.rapid7.com/foo" in html
    assert "https://docs.rapid7.com/bar" in html
    assert 'href="https://docs.rapid7.com/foo"' in html
    assert "<script" not in html


def test_audit_section_shows_sampling_note():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="d",
            severity="warn", status="warn",
            findings=[Finding(severity="warn", message="m")],
            sampled=True, sample_info="checked 500 of 4200 assets",
            sources=["https://docs.rapid7.com/foo"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="warn", findings=[Finding(severity="warn", message="m")],
        summary={"rules_total": 1, "rules_warn": 1, "rules_pass": 0,
                 "rules_fail": 0, "rules_error": 0, "rules_skipped": 0},
        rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    assert "checked 500 of 4200 assets" in html


def test_audit_section_shows_rule_error():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="d",
            severity="fail", status="error",
            error="boom: KeyError 'sites'",
            sources=["https://docs.rapid7.com/foo"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="fail",
        summary={"rules_total": 1, "rules_warn": 0, "rules_pass": 0,
                 "rules_fail": 0, "rules_error": 1, "rules_skipped": 0},
        rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    assert "boom: KeyError" in html


def test_non_audit_check_unchanged_when_rule_results_none():
    cr = CheckResult(name="Scan Engines", description="d", status="pass", findings=[])
    html = render_report(_ctx([cr]))
    assert "Rule One" not in html


def test_duration_filter_formats_each_band():
    """Pure-function test of the duration formatter at every band boundary."""
    from rapid7_healthcheck.report import _format_duration

    # Sub-second
    assert _format_duration(0) == "0 ms"
    assert _format_duration(123) == "123 ms"
    assert _format_duration(999) == "999 ms"

    # 1s..60s -> "X.Y s"
    assert _format_duration(1000) == "1.0 s"
    assert _format_duration(4250) == "4.2 s"
    assert _format_duration(59999) == "60.0 s"  # rounds to boundary, still 's' band

    # 60s..3600s -> "Xm Ys"
    assert _format_duration(60000) == "1m 0s"
    assert _format_duration(134000) == "2m 14s"
    assert _format_duration(3599000) == "59m 59s"

    # 3600s+ -> "Xh Ym"
    assert _format_duration(3600000) == "1h 0m"
    assert _format_duration(3700000) == "1h 1m"
    assert _format_duration(45000000) == "12h 30m"

    # None passthrough
    assert _format_duration(None) == "-"


def test_audit_rule_duration_renders_human_readable():
    """A 4.25-second rule must render as '4.2 s', not '4250 ms'."""
    cr = CheckResult(
        name="Configuration Audit",
        description="audit",
        status="warn",
        findings=[],
        summary={
            "rules_total": 1, "rules_pass": 0, "rules_warn": 1,
            "rules_fail": 0, "rules_error": 0, "rules_skipped": 0,
        },
        duration_ms=5000,
        rule_results=[
            RuleResult(
                rule_id="slow_rule", rule_name="Slow Rule", description="d",
                severity="warn", status="warn", findings=[],
                duration_ms=4250,
            ),
        ],
    )
    html = render_report(_ctx([cr]))
    assert "4.2 s" in html
    assert "4250 ms" not in html
    # Audit umbrella row also rendered humanely.
    assert "5.0 s" in html


def test_check_level_duration_uses_filter_too():
    """A non-audit check's duration in the summary table also uses the filter."""
    cr = CheckResult(
        name="Slow Op Check", description="d", status="pass",
        findings=[], duration_ms=134000,
    )
    html = render_report(_ctx([cr]))
    assert "2m 14s" in html
    assert "134000 ms" not in html


def test_metrics_rollup_counts():
    from rapid7_healthcheck.report import _metrics
    from rapid7_healthcheck.audit import RuleResult
    cr = CheckResult(
        name="Audit", description="d", status="warn", duration_ms=2500,
        findings=[],
        rule_results=[
            RuleResult(rule_id="a", rule_name="A", description="d",
                       severity="fail", status="fail",
                       findings=[Finding(severity="fail", message="m")]),
            RuleResult(rule_id="b", rule_name="B", description="d",
                       severity="warn", status="warn",
                       findings=[Finding(severity="warn", message="m")],
                       sampled=True, sample_info="500/4200"),
            RuleResult(rule_id="c", rule_name="C", description="d",
                       severity="info", status="pass"),
            RuleResult(rule_id="d", rule_name="D", description="d",
                       severity="warn", status="skipped"),
        ],
    )
    m = _metrics([cr])
    assert m["rules_total"] == 4
    assert m["rules_fail"] == 1
    assert m["rules_warn"] == 1
    assert m["rules_pass"] == 1
    assert m["rules_skipped"] == 1
    assert m["rules_sampled"] == 1
    assert m["total_duration_ms"] == 2500
    assert m["findings_total"] == 2
    assert m["findings_fail"] == 1
    assert m["findings_warn"] == 1


def test_metrics_rollup_handles_check_without_rule_results():
    """Operational checks (scan_engines etc.) have no rule_results — they
    contribute findings but not rule counts."""
    from rapid7_healthcheck.report import _metrics
    cr = CheckResult(
        name="Scan Engines", description="d", status="warn", duration_ms=300,
        findings=[Finding(severity="warn", message="m")],
    )
    m = _metrics([cr])
    assert m["rules_total"] == 0
    assert m["findings_total"] == 1
    assert m["findings_warn"] == 1
    assert m["total_duration_ms"] == 300
