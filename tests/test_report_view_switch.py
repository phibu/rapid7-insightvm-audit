"""The report's view switch: a CSS-only Findings/Diagrams split.

See CONTEXT.md "View switch" and docs/adr/0009. The switch is hidden-radio +
label tabs (no location.hash, works with JS off). All three diagrams live in
the Diagrams view; the Findings view is purely textual.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.report import InventoryTotals, ReportContext, render_report


def _rule(rule_id: str, summary: dict, status: str = "warn") -> RuleResult:
    return RuleResult(
        rule_id=rule_id, rule_name=rule_id, description="x",
        severity="warn", status=status, summary=summary,
    )


def _coverage_check() -> CheckResult:
    return CheckResult(
        name="Asset Coverage", description="x", status="warn",
        rule_results=[
            _rule("op.asset_coverage.stale_assets", {"stale_count": 3000, "stale_asset_days": 30}),
            _rule("op.asset_coverage.never_scanned_assets", {"unscanned_count": 800, "never_scanned_days": 90}),
        ],
    )


def _engines_check() -> CheckResult:
    return CheckResult(
        name="Scan Engines", description="x", status="warn",
        rule_results=[_rule("op.scan_engines.x", {}, status="pass")],
    )


def _inventory() -> InventoryTotals:
    return InventoryTotals(
        total_assets=12000, total_sites=5, total_scan_engines=3,
        total_asset_groups_static=2, total_asset_groups_dynamic=1, total_scans=40,
    )


def _topology():
    from rapid7_healthcheck.diagrams import EngineNode, TopologyData
    return TopologyData(
        engines=[EngineNode(10, "Engine A", None, 12, 8200, False)],
        orphan_site_count=3, unpaired_engines=[], total_paired_sites=12,
    )


def _ctx() -> ReportContext:
    return ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=[_coverage_check(), _engines_check()],
        inventory_totals=_inventory(),
        topology=_topology(),
    )


def _full_html() -> str:
    return render_report(_ctx())


# --- the view switch control ------------------------------------------------


def test_view_switch_uses_hidden_radio_not_hash():
    html = _full_html()
    # Two radios in one group; Findings is the default-checked view.
    radios = re.findall(r'<input[^>]*type="radio"[^>]*name="view"[^>]*>', html)
    assert len(radios) == 2, f"expected 2 view radios, got {len(radios)}"
    findings_radio = next(r for r in radios if "findings" in r.lower())
    assert "checked" in findings_radio, "Findings view must be default-checked"


def test_view_switch_has_no_target_anchors_for_views():
    # ADR-0009: the switch must NOT use location.hash (no <a href="#...view">).
    html = _full_html()
    assert 'href="#findings-view"' not in html
    assert 'href="#diagrams-view"' not in html


def test_both_view_labels_present():
    html = _full_html()
    assert re.search(r'<label[^>]*>[^<]*Findings', html)
    assert re.search(r'<label[^>]*>[^<]*Diagrams', html)


# --- diagrams live in the Diagrams view, not inline -------------------------


def test_all_three_diagrams_render():
    html = _full_html()
    assert "Asset coverage threshold bands" in html  # coverage aria-label
    assert "Scan engine topology" in html            # topology aria-label
    assert "Health status by check" in html          # status map aria-label


def test_diagrams_are_inside_the_diagrams_view():
    html = _full_html()
    # The Diagrams view container wraps all three figure aria-labels.
    m = re.search(r'<section class="[^"]*diagrams-view[^"]*".*?</section>', html, re.DOTALL)
    assert m, "diagrams-view section not found"
    panel = m.group(0)
    for label in ("Asset coverage threshold bands", "Scan engine topology", "Health status by check"):
        assert label in panel, f"{label} not inside the Diagrams view"


def test_check_sections_have_no_inline_diagram():
    # The coverage figure must NOT appear inside the Asset Coverage check section.
    html = _full_html()
    m = re.search(r'<section class="check"[^>]*>(?:(?!</section>).)*?Asset Coverage.*?</section>',
                  html, re.DOTALL)
    assert m, "Asset Coverage check section not found"
    assert "dg-figure" not in m.group(0), "diagram leaked into a check section"


def test_summary_has_no_inline_status_map():
    # The status map moved out of Summary into the Diagrams view.
    html = _full_html()
    # Between the Summary heading and the next section heading, no dg-figure.
    summary = re.search(r'<h2>Summary</h2>(.*?)(?:<h2>|<section)', html, re.DOTALL)
    assert summary, "Summary block not found"
    assert "dg-figure" not in summary.group(1)


# --- print + no-js contracts ------------------------------------------------


def test_no_external_resources_still_holds():
    html = _full_html()
    assert "<script src=" not in html
    assert "//cdn" not in html
    assert '<link rel="stylesheet"' not in html
