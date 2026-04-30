from __future__ import annotations

import re
from datetime import datetime, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import ReportContext, render_report


def _ctx_with_findings() -> ReportContext:
    """Fixture: a context with at least 2 audit rules and 2 findings.

    The filter bar renders all chips when at least one CheckResult has rule_results,
    so the fixture must include an audit-style check (not just operational).
    """
    return ReportContext(
        title="A11y test",
        generated_at=datetime(2026, 4, 30, 12, 0, tzinfo=timezone.utc),
        base_url_host="us.api.insight.rapid7.com",
        tool_version="0.2.0",
        config_path="config.yaml",
        results=[
            CheckResult(
                name="Audit", description="d", status="warn", duration_ms=1000,
                findings=[],
                rule_results=[
                    RuleResult(
                        rule_id="r1", rule_name="Rule One", description="d",
                        severity="fail", status="fail", duration_ms=120,
                        findings=[Finding(severity="fail", message="port 22 exposed")],
                    ),
                    RuleResult(
                        rule_id="r2", rule_name="Rule Two", description="d",
                        severity="warn", status="warn", duration_ms=80,
                        findings=[Finding(severity="warn", message="outdated agent")],
                    ),
                ],
                summary={"rules_total": 2, "rules_pass": 0, "rules_warn": 1,
                         "rules_fail": 1, "rules_error": 0, "rules_skipped": 0},
            ),
        ],
    )


def test_chips_have_aria_pressed():
    """Every filter chip must have aria-pressed for screen-reader state announcement."""
    html = render_report(_ctx_with_findings())
    chips = re.findall(r'<button[^>]*class="chip"[^>]*>', html)
    assert len(chips) >= 5, f"expected at least 5 chips (All + 4 severities), got {len(chips)}"
    for chip in chips:
        assert "aria-pressed=" in chip, f"chip missing aria-pressed: {chip}"


def test_theme_toggle_has_aria_label():
    """Icon-only theme button needs an aria-label for screen readers."""
    html = render_report(_ctx_with_findings())
    m = re.search(r'<button[^>]*class="theme-toggle"[^>]*>', html)
    assert m is not None, "theme-toggle button not found"
    assert 'aria-label="Theme:' in m.group(0), f"theme-toggle missing aria-label: {m.group(0)}"


def test_search_input_has_aria_label():
    """Search input needs an accessible name."""
    html = render_report(_ctx_with_findings())
    m = re.search(r'<input[^>]*class="filter-search"[^>]*>', html)
    assert m is not None, "filter-search input not found"
    assert "aria-label=" in m.group(0), f"filter-search missing aria-label: {m.group(0)}"


def test_focus_visible_rule_present():
    """Focus indicator CSS rule must exist with an outline declaration."""
    html = render_report(_ctx_with_findings())
    assert ":focus-visible" in html, "no :focus-visible selector found in CSS"
    assert re.search(r":focus-visible\s*\{[^}]*outline:", html) is not None, \
        ":focus-visible rule missing outline declaration"


def test_filter_bar_has_role_toolbar():
    """Filter bar wraps controls with role=toolbar for ARIA semantics."""
    html = render_report(_ctx_with_findings())
    assert 'role="toolbar"' in html, "filter bar missing role=toolbar"


def test_noscript_fallback_hides_interactive_chrome():
    """With JS off, .filter-bar and .theme-toggle must be hidden via .no-js."""
    html = render_report(_ctx_with_findings())
    assert 'class="no-js"' in html, "<html> element missing class=no-js"
    assert re.search(r"\.no-js\s+\.filter-bar", html) is not None, \
        ".no-js .filter-bar CSS rule missing"
    assert re.search(r"\.no-js\s+\.theme-toggle", html) is not None, \
        ".no-js .theme-toggle CSS rule missing"


def test_reduced_motion_media_query_present():
    """Users with prefers-reduced-motion get a no-transition path."""
    html = render_report(_ctx_with_findings())
    assert "@media (prefers-reduced-motion: reduce)" in html, \
        "prefers-reduced-motion media query missing"
