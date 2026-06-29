from __future__ import annotations

import re

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.diagrams import (
    CoverageData,
    build_coverage_svg,
    extract_coverage_counts,
)
from rapid7_healthcheck.report import InventoryTotals


def _inventory(total_assets: int = 12000) -> InventoryTotals:
    return InventoryTotals(
        total_assets=total_assets,
        total_sites=5,
        total_scan_engines=3,
        total_asset_groups_static=2,
        total_asset_groups_dynamic=1,
        total_scans=40,
    )


def _coverage_check(*rules: RuleResult) -> CheckResult:
    return CheckResult(
        name="Asset Coverage",
        description="x",
        status="warn",
        rule_results=list(rules),
    )


def _rule(rule_id: str, summary: dict) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        rule_name=rule_id,
        description="x",
        severity="warn",
        status="warn",
        summary=summary,
    )


# --- extract_coverage_counts ------------------------------------------------


def test_extract_pulls_counts_from_rule_summaries_and_inventory():
    check = _coverage_check(
        _rule("op.asset_coverage.stale_assets", {"stale_count": 3000, "stale_asset_days": 30}),
        _rule("op.asset_coverage.never_scanned_assets", {"unscanned_count": 800, "never_scanned_days": 90}),
        _rule("op.asset_coverage.agent_only_assets", {"agent_only_count": 400}),
        _rule("op.asset_coverage.ghost_assets", {"ghost_count": 120}),
    )
    data = extract_coverage_counts([check], _inventory(12000))
    assert data == CoverageData(
        total_assets=12000,
        stale=3000,
        never_scanned=800,
        agent_only=400,
        ghost=120,
        stale_days=30,
        never_scanned_days=90,
    )


def test_extract_returns_none_without_inventory():
    check = _coverage_check(
        _rule("op.asset_coverage.stale_assets", {"stale_count": 3000}),
    )
    assert extract_coverage_counts([check], None) is None


def test_extract_returns_none_when_total_assets_missing():
    # total_asset_count() can be unavailable -> InventoryTotals absent is the
    # signal; but a zero total is a real, drawable population (empty console).
    assert extract_coverage_counts([_coverage_check()], None) is None


def test_extract_returns_none_without_coverage_check():
    other = CheckResult(name="Scan Engines", description="x", status="pass")
    assert extract_coverage_counts([other], _inventory()) is None


def test_extract_returns_none_when_no_usable_band_counts():
    # Coverage check present but every band rule errored/skipped (no counts).
    check = _coverage_check(
        _rule("op.asset_coverage.stale_assets", {"stale_asset_days": 30}),  # no stale_count
    )
    assert extract_coverage_counts([check], _inventory()) is None


def test_extract_tolerates_missing_optional_bands():
    # Only stale present (never/agent/ghost rules skipped via threshold flags).
    check = _coverage_check(
        _rule("op.asset_coverage.stale_assets", {"stale_count": 3000, "stale_asset_days": 30}),
    )
    data = extract_coverage_counts([check], _inventory(12000))
    assert data is not None
    assert data.stale == 3000
    assert data.never_scanned is None
    assert data.agent_only is None
    assert data.ghost is None


# --- build_coverage_svg -----------------------------------------------------


def test_build_svg_is_inline_svg_with_no_external_refs():
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=800,
                        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90)
    svg = build_coverage_svg(data)
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    # The SVG xmlns is a namespace URN, not a fetched resource. What must NOT
    # appear is any externally-loaded asset (matches test_report's contract).
    assert "<script" not in svg
    assert 'src=' not in svg
    assert "//cdn" not in svg
    assert "@import" not in svg


def test_build_svg_uses_report_theme_vars_not_hardcoded_colors():
    # The cardinal rule: colors come from the report's CSS variables via dg-*
    # classes, never inline hex/rgb fills (those would not follow the toggle).
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=800,
                        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90)
    svg = build_coverage_svg(data)
    # No hardcoded color fills/strokes on shapes.
    assert not re.search(r'(fill|stroke)="(#|rgb)', svg)
    # Uses the dg- class system.
    assert 'class="dg-' in svg


def test_build_svg_renders_band_counts_and_total():
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=800,
                        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90)
    svg = build_coverage_svg(data)
    assert "12,000" in svg  # total, thousands-separated
    assert "3,000" in svg   # stale
    assert "800" in svg     # never-scanned
    assert ">30" in svg or "30d" in svg or "30 d" in svg  # threshold label shown


def test_build_svg_omits_absent_bands():
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=None,
                        agent_only=None, ghost=None, stale_days=30, never_scanned_days=None)
    svg = build_coverage_svg(data)
    assert "3,000" in svg
    # never-scanned / agent-only / ghost labels should not appear
    assert "never" not in svg.lower()
    assert "agent-only" not in svg.lower()
    assert "ghost" not in svg.lower()


def test_build_svg_labels_nested_subset_relationship():
    # never-scanned is a SUBSET of stale -- the figure must say so, not imply a
    # partition. We assert the subset glyph/word is present when both exist.
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=800,
                        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90)
    svg = build_coverage_svg(data)
    assert "⊆" in svg or "subset" in svg.lower() or "of stale" in svg.lower()


def test_build_svg_marks_cross_cutting_flags():
    # agent-only and ghost are cross-cutting, not bands -- labeled as flags.
    data = CoverageData(total_assets=12000, stale=3000, never_scanned=800,
                        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90)
    svg = build_coverage_svg(data)
    assert "agent-only" in svg.lower()
    assert "ghost" in svg.lower()


# --- report integration -----------------------------------------------------


def _full_coverage_results() -> list[CheckResult]:
    return [
        _coverage_check(
            _rule("op.asset_coverage.stale_assets", {"stale_count": 3000, "stale_asset_days": 30}),
            _rule("op.asset_coverage.never_scanned_assets", {"unscanned_count": 800, "never_scanned_days": 90}),
        )
    ]


def test_report_embeds_coverage_diagram_in_asset_coverage_section():
    from datetime import datetime, timezone

    from rapid7_healthcheck.report import ReportContext, render_report

    ctx = ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=_full_coverage_results(),
        inventory_totals=_inventory(12000),
    )
    html = render_report(ctx)
    # Match the coverage figure's aria-label specifically -- other diagrams
    # (e.g. the status map) also carry class="dg-figure".
    assert "Asset coverage threshold bands" in html
    # Themed via report vars -- the dg- CSS class block must be defined.
    assert ".dg-band-fail" in html


def test_report_omits_diagram_when_inventory_absent():
    from datetime import datetime, timezone

    from rapid7_healthcheck.report import ReportContext, render_report

    ctx = ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=_full_coverage_results(),
        inventory_totals=None,
    )
    html = render_report(ctx)
    # The coverage figure is omitted without inventory; assert on ITS label
    # (the status map may still render from the same results).
    assert "Asset coverage threshold bands" not in html
