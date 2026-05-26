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
    # Inline JSON state blob is allowed. External script src is not.
    assert "<script src=" not in html
    assert "https://cdn" not in html
    assert "//cdn" not in html
    # No external stylesheets, fonts, images, iframes.
    assert "<link rel=\"stylesheet\"" not in html
    assert "@import url" not in html
    assert "<iframe" not in html


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
    assert "<script src=" not in html  # was: assert "<script" not in html


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
            RuleResult(rule_id="e", rule_name="E", description="d",
                       severity="fail", status="error", error="boom"),
        ],
    )
    m = _metrics([cr])
    assert m["rules_total"] == 5
    assert m["rules_fail"] == 1
    assert m["rules_warn"] == 1
    assert m["rules_pass"] == 1
    assert m["rules_skipped"] == 1
    assert m["rules_error"] == 1
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


def test_render_report_embeds_state_blob():
    """The rendered HTML must contain the state blob script tag."""
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert '<script id="report-state" type="application/json">' in html


def test_render_report_no_delta_when_no_prior():
    r = CheckResult(name="X", description="x", status="warn",
                    findings=[Finding(severity="warn", message="m")])
    html = render_report(_ctx([r]))
    # Delta strip section should not render when no prior state was passed.
    # Positive assertion: no "resolved" / "new fails" pill text.
    assert "resolved" not in html.lower()
    assert "new fails" not in html.lower()


def test_render_report_renders_delta_strip_when_prior_passed(tmp_path):
    """End-to-end: write a report, write a second one, second one must show delta."""
    from rapid7_healthcheck.audit import RuleResult
    r1 = CheckResult(
        name="Audit", description="d", status="fail",
        rule_results=[
            RuleResult(
                rule_id="r1", rule_name="R", description="d",
                severity="fail", status="fail",
                findings=[Finding(severity="fail", message="bad", details={"asset": "a"})],
            ),
        ],
    )
    ctx1 = _ctx([r1])
    p1 = tmp_path / "report-1.html"
    write_report(ctx1, explicit_path=p1)

    # Now run a second one in the same dir but using output_dir mode so it sees p1.
    # Move/copy p1 to look like a pattern match.
    import shutil
    pattern_p1 = tmp_path / "rapid7-2026-04-28_1000.html"
    shutil.move(str(p1), str(pattern_p1))

    r2 = CheckResult(name="Audit", description="d", status="pass",
                     rule_results=[], findings=[])  # all resolved
    ctx2 = _ctx([r2])
    out2 = write_report(
        ctx2, output_dir=tmp_path,
        filename_pattern="rapid7-{timestamp}.html",
        delta_max_age_days=30,
    )
    html = out2.read_text(encoding="utf-8")
    # Should mention the delta strip's "resolved" pill.
    assert "resolved" in html.lower()


from rapid7_healthcheck.report import InventoryTotals


def test_report_renders_inventory_strip_when_totals_present():
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    ctx.inventory_totals = InventoryTotals(
        total_assets=1234,
        total_sites=12,
        total_scan_engines=3,
        total_asset_groups_static=5,
        total_asset_groups_dynamic=2,
        total_scans=987,
    )
    html = render_report(ctx)
    # Match the rendered <section>, not the always-inlined CSS rule — mirrors
    # the rigor of the negative test below so a regression in the
    # {% if inventory_totals %} branch can't slip past.
    assert '<section class="inventory-totals"' in html
    assert "1234" in html
    assert "987" in html
    # Labels rendered
    assert "Asset Groups (static)" in html
    assert "Asset Groups (dynamic)" in html
    assert "Scan Engines" in html


def test_report_omits_inventory_strip_when_totals_is_none():
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    # explicitly None (which is the default)
    ctx.inventory_totals = None
    html = render_report(ctx)
    # The CSS rules for `.inventory-totals` are always inlined in <style>,
    # but the rendered <section> only appears when totals is non-None.
    assert '<section class="inventory-totals"' not in html
    assert "Asset Groups (static)" not in html


def test_report_renders_card_summary_when_present():
    """A rule with card_summary populated renders the standardized
    'N examined · N passed · N failed' header in the rule card."""
    rr = RuleResult(
        rule_id="op.x", rule_name="X", description="d",
        severity="warn", status="warn",
        findings=[], summary={}, sources=[],
        card_summary={"examined": 10, "passed": 7, "failed": 3},
    )
    cr = CheckResult(name="X", description="x", status="warn", rule_results=[rr])
    html = render_report(_ctx([cr]))
    # Match the rendered <div>, not the always-inlined CSS rule (which uses
    # the same class name).
    assert '<div class="rule-card-summary">' in html
    assert "<strong>10</strong> examined" in html
    assert "<strong>7</strong> passed" in html
    assert "<strong>3</strong> failed" in html


def test_report_omits_card_summary_when_none():
    """A rule with card_summary=None does NOT render the standardized header.

    Mirrors the inventory-totals positive/negative pair: match on the
    rendered <div class="rule-card-summary"> tag, not the always-inlined
    CSS rule."""
    rr = RuleResult(
        rule_id="op.x", rule_name="X", description="d",
        severity="warn", status="warn",
        findings=[], summary={"some_count": 5}, sources=[],
        card_summary=None,
    )
    cr = CheckResult(name="X", description="x", status="warn", rule_results=[rr])
    html = render_report(_ctx([cr]))
    # The CSS rules for `.rule-card-summary` are inlined in <style>, so a
    # substring match would false-positive. Match the rendered <div> instead.
    assert '<div class="rule-card-summary">' not in html
