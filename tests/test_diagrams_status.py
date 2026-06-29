from __future__ import annotations

import re

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.diagrams import (
    StatusRow,
    build_status_map_svg,
    extract_status_map,
)


def _rule(status: str) -> RuleResult:
    return RuleResult(
        rule_id=f"r-{status}",
        rule_name="r",
        description="x",
        severity="warn",
        status=status,
    )


def _check(name: str, *statuses: str) -> CheckResult:
    rules = [_rule(s) for s in statuses]
    return CheckResult(
        name=name,
        description="x",
        status="warn",
        rule_results=rules,
    )


# --- extract_status_map -----------------------------------------------------


def test_extract_one_row_per_check_with_rule_results():
    results = [
        _check("Scan Engines", "pass", "pass", "warn"),
        _check("Asset Coverage", "pass", "fail", "fail"),
    ]
    rows = extract_status_map(results)
    assert [r.check_name for r in rows] == ["Scan Engines", "Asset Coverage"]
    se = rows[0]
    assert se.rules_pass == 2 and se.rules_warn == 1 and se.rules_fail == 0


def test_extract_counts_error_and_skipped_separately():
    rows = extract_status_map([_check("X", "pass", "error", "skipped", "skipped")])
    row = rows[0]
    assert row.rules_pass == 1
    assert row.rules_error == 1
    assert row.rules_skipped == 2


def test_extract_skips_checks_without_rule_results():
    # A legacy/flat check (no rule_results) contributes no row.
    flat = CheckResult(name="Legacy", description="x", status="pass")
    rows = extract_status_map([flat, _check("Real", "pass")])
    assert [r.check_name for r in rows] == ["Real"]


def test_extract_returns_none_when_no_check_has_rule_results():
    flat = CheckResult(name="Legacy", description="x", status="pass")
    assert extract_status_map([flat]) is None


def test_extract_returns_none_for_empty_results():
    assert extract_status_map([]) is None


# --- build_status_map_svg ---------------------------------------------------


def _rows() -> list[StatusRow]:
    return [
        StatusRow("Scan Engines", rules_pass=6, rules_warn=2, rules_fail=0, rules_error=0, rules_skipped=1),
        StatusRow("Asset Coverage", rules_pass=3, rules_warn=0, rules_fail=5, rules_error=0, rules_skipped=0),
    ]


def test_status_svg_is_inline_and_themed():
    svg = build_status_map_svg(_rows())
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    assert "<script" not in svg and "src=" not in svg
    assert not re.search(r'(fill|stroke)="(#|rgb)', svg)
    assert 'class="dg-' in svg


def test_status_svg_shows_each_check_name():
    svg = build_status_map_svg(_rows())
    assert "Scan Engines" in svg
    assert "Asset Coverage" in svg


def test_status_svg_uses_status_segment_classes():
    svg = build_status_map_svg(_rows())
    # Pass/warn/fail segments use the report's status palette via dg- classes.
    assert "dg-seg-pass" in svg
    assert "dg-seg-warn" in svg
    assert "dg-seg-fail" in svg


def test_status_svg_omits_zero_width_segments():
    # A row with only passes must not emit a warn/fail BAR segment. (The legend
    # still lists every status as a key -- those are 11px swatches, not bars;
    # match the full-height bar segment to distinguish.)
    rows = [StatusRow("Clean", rules_pass=4, rules_warn=0, rules_fail=0, rules_error=0, rules_skipped=0)]
    svg = build_status_map_svg(rows)

    def bar_segment(cls: str) -> bool:
        # Bar segments carry the row height; legend swatches are 11px.
        return f'class="{cls}"' in svg and f'height="{26}"' in svg.split(f'class="{cls}"', 1)[1][:80]

    assert bar_segment("dg-seg-pass")
    assert not bar_segment("dg-seg-warn")
    assert not bar_segment("dg-seg-fail")


def test_status_svg_renders_skipped_and_error_distinctly():
    rows = [StatusRow("Mixed", rules_pass=1, rules_warn=0, rules_fail=0, rules_error=1, rules_skipped=2)]
    svg = build_status_map_svg(rows)
    assert "dg-seg-error" in svg
    assert "dg-seg-skipped" in svg


# --- report integration -----------------------------------------------------


def test_report_embeds_status_map_in_summary():
    from datetime import datetime, timezone

    from rapid7_healthcheck.report import ReportContext, render_report

    ctx = ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=[_check("Scan Engines", "pass", "warn")],
    )
    html = render_report(ctx)
    assert "Health status by check" in html  # the svg aria-label (unique to the figure)
    assert "dg-seg-pass" in html


def test_report_omits_status_map_when_no_rule_results():
    from datetime import datetime, timezone

    from rapid7_healthcheck.report import ReportContext, render_report

    ctx = ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=[CheckResult(name="Legacy", description="x", status="pass")],
    )
    html = render_report(ctx)
    # The figure's aria-label is unique to a rendered status map; the CSS
    # comment mentions "Health status map" regardless, so match the label.
    assert "Health status by check" not in html
