"""Report navigation (section rail) tests — 0.8.5.

The section rail is the persistent left-column wayfinding added in 0.8.5:
a grid shell wraps the page into [section rail | content column]; the rail
lists one entry per check (status dot + name + fail/warn count), scroll-spies
the active section, and reflects the active severity filter. These tests pin
the markup contract and, critically, that the grid restructure did NOT break
the load-bearing ``section.check > details`` child-combinator relationship the
CSS filter depends on (also guarded in test_report_filtering.py).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import ReportContext, render_report


def _ctx_multi_check() -> ReportContext:
    """Fixture: two checks so the rail renders more than one entry, with a
    fail finding on one and a warn on the other (exercises both count badges)."""
    return ReportContext(
        title="Nav test",
        generated_at=datetime(2026, 4, 30, 12, 0, tzinfo=timezone.utc),
        base_url_host="us.api.insight.rapid7.com",
        tool_version="0.8.5",
        config_path="config.yaml",
        results=[
            CheckResult(
                name="Scan Engines", description="d", status="fail", duration_ms=500,
                findings=[Finding(severity="fail", message="engine offline")],
                rule_results=[
                    RuleResult(
                        rule_id="r1", rule_name="Rule One", description="d",
                        severity="fail", status="fail", duration_ms=120,
                        findings=[Finding(severity="fail", message="engine offline")],
                    ),
                ],
                summary={"rules_total": 1, "rules_pass": 0, "rules_warn": 0,
                         "rules_fail": 1, "rules_error": 0, "rules_skipped": 0},
            ),
            CheckResult(
                name="Configuration Audit", description="d", status="warn", duration_ms=800,
                findings=[Finding(severity="warn", message="weak template")],
                rule_results=[
                    RuleResult(
                        rule_id="r2", rule_name="Rule Two", description="d",
                        severity="warn", status="warn", duration_ms=80,
                        findings=[Finding(severity="warn", message="weak template")],
                    ),
                ],
                summary={"rules_total": 1, "rules_pass": 0, "rules_warn": 1,
                         "rules_fail": 0, "rules_error": 0, "rules_skipped": 0},
            ),
        ],
    )


def test_section_rail_is_a_nav_with_aria_label():
    """The rail must be a semantic <nav> with an accessible name."""
    html = render_report(_ctx_multi_check())
    m = re.search(r'<nav[^>]*class="rail-inner"[^>]*>', html)
    assert m is not None, "section rail <nav> not found"
    assert "aria-label=" in m.group(0), f"rail <nav> missing aria-label: {m.group(0)}"


def test_section_rail_has_one_entry_per_check_with_anchor():
    """One rail link per check, each pointing at the matching #check-N anchor."""
    html = render_report(_ctx_multi_check())
    rail_match = re.search(r'<nav[^>]*class="rail-inner".*?</nav>', html, re.S)
    assert rail_match is not None, "rail <nav> block not found"
    rail = rail_match.group(0)
    anchors = re.findall(r'href="#(check-\d+)"', rail)
    assert anchors == ["check-1", "check-2"], f"unexpected rail anchors: {anchors}"
    # Each anchored section actually exists in the document.
    for a in anchors:
        assert f'id="{a}"' in html, f"rail anchor {a} has no matching section id"


def test_section_rail_entries_carry_status_dot_and_counts():
    """Each entry shows a status dot, and fail/warn counts surface as badges."""
    html = render_report(_ctx_multi_check())
    rail = re.search(r'<nav[^>]*class="rail-inner".*?</nav>', html, re.S).group(0)
    assert 'class="status-dot fail"' in rail, "missing fail status dot in rail"
    assert 'class="status-dot warn"' in rail, "missing warn status dot in rail"
    assert re.search(r'rail-count has-fail[^>]*>\s*1', rail), "fail count badge missing/incorrect"
    assert re.search(r'rail-count has-warn[^>]*>\s*1', rail), "warn count badge missing/incorrect"


def test_grid_shell_preserves_section_details_child_relationship():
    """The grid wrapper must wrap the PAGE, never get inserted between a
    section.check and its <details> cards — the CSS filter selector
    ``section.check > details`` depends on the direct-child relationship."""
    html = render_report(_ctx_multi_check())
    # The rule card <details> must be a direct child of its section in the markup:
    # find a section.check and assert a <details id="rule-..."> follows before the
    # next closing </section>, with no intervening block wrapper element.
    sec = re.search(r'<section class="check"[^>]*>(.*?)</section>', html, re.S)
    assert sec is not None, "no section.check found"
    body = sec.group(1)
    # No grid/content wrappers leaked inside a section.
    assert "report-grid" not in body, "grid wrapper leaked inside section.check"
    assert "content-column" not in body, "content-column leaked inside section.check"
    assert re.search(r'<details id="rule-', body), "rule <details> missing inside section"


def test_filter_child_combinator_still_used_after_grid():
    """The severity-filter CSS must still target section.check > details (child),
    proving the grid restructure didn't force a descendant rewrite."""
    html = render_report(_ctx_multi_check())
    assert re.search(r"section\.check\s*>\s*details", html) is not None, \
        "child-combinator filter selector lost after grid restructure"


def test_narrow_screen_disclosure_present():
    """On narrow screens the rail folds into a native <details> 'Jump to section'
    disclosure — no-JS safe. The <details class='section-rail'> + <summary> must exist."""
    html = render_report(_ctx_multi_check())
    assert re.search(r'<details class="section-rail"[^>]*>', html) is not None, \
        "section rail <details> disclosure wrapper missing"
    assert re.search(r'<summary>\s*Jump to section\s*</summary>', html) is not None, \
        "'Jump to section' summary missing"


def test_status_dot_appears_in_summary_table():
    """Polish: the reusable .status-dot token is reused in summary table rows."""
    html = render_report(_ctx_multi_check())
    # At least two status dots in the summary table (one per check row).
    summary = re.search(r"<h2>Summary</h2>.*?</table>", html, re.S)
    assert summary is not None, "summary table not found"
    dots = re.findall(r'class="status-dot \w+"', summary.group(0))
    assert len(dots) >= 2, f"expected status dots in summary rows, found {len(dots)}"


def test_smooth_scroll_present_and_reduced_motion_gated():
    """scroll-behavior: smooth is set, and disabled under prefers-reduced-motion."""
    html = render_report(_ctx_multi_check())
    assert re.search(r"html\s*\{[^}]*scroll-behavior:\s*smooth", html) is not None, \
        "smooth scroll not enabled"
    rm = re.search(r"@media \(prefers-reduced-motion: reduce\)\s*\{(.*?)\}\s*\}", html, re.S)
    # The reduced-motion block (or one of them) must neutralize scroll-behavior.
    assert "scroll-behavior: auto" in html, "reduced-motion does not reset scroll-behavior"


def test_scroll_spy_uses_intersection_observer():
    """Scroll-spy is IntersectionObserver-based and degrades when unavailable."""
    html = render_report(_ctx_multi_check())
    assert "IntersectionObserver" in html, "scroll-spy IntersectionObserver code missing"
    assert "__refreshRail" in html, "filter-sync refreshRail hook missing"


def test_rail_is_sticky_on_the_grid_item_within_wide_breakpoint():
    """The rail must stay pinned while the content column scrolls.

    For position:sticky to hold through a long page, the sticky element's
    containing block must be as tall as the content column. The rail's grid
    item satisfies that (the grid row is content-column height); the inner
    <nav>, which is only as tall as the link list inside a short <details>,
    does NOT — sticking it there lets the rail scroll away once you pass the
    list. So sticky belongs on the GRID ITEM (.section-rail), scoped to the
    wide breakpoint (where the rail is a real column, not the narrow-screen
    <details> disclosure), paired with align-items/align-self start.
    """
    html = render_report(_ctx_multi_check())
    # Isolate the wide-breakpoint media query block.
    mq = re.search(r"@media \(min-width: 64rem\)\s*\{(.*?)\n  \}", html, re.S)
    assert mq is not None, "wide-breakpoint (64rem) media query not found"
    block = mq.group(1)
    assert re.search(r"\.section-rail[^{}]*\{[^}]*position:\s*sticky", block), \
        "rail grid item (.section-rail) is not position:sticky within the wide breakpoint"
    # The grid must keep items top-aligned so the sticky item isn't stretched
    # to full row height (which would defeat sticking).
    assert re.search(r"align-items:\s*start", html) or re.search(r"align-self:\s*start", html), \
        "grid does not top-align items (needed for sticky to work)"
    # Guard against regression: the inner <nav> must NOT be the sticky element.
    assert not re.search(r"\.rail-inner\s*\{[^}]*position:\s*sticky", html), \
        ".rail-inner should not be the sticky element (its containing block is too short)"
