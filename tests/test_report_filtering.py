"""Regression tests for report filter-isolation behavior.

The 0.2.0 review caught a critical bug where descendant-combinator CSS
(``section.check details:not([data-severity="X"])``) was hiding inner
finding-``<details>`` elements alongside the outer rule cards. The fix
(commit a91f6d1) switched to a child combinator
``section.check > details`` so only the direct-child rule card is targeted.

These tests pin the fix structurally: every
``body[data-filter-severity="..."]`` rule in the rendered HTML must use
``section.check > details``, never bare ``section.check details``.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import ReportContext, render_report


def _minimal_context() -> ReportContext:
    return ReportContext(
        title="Filter test",
        generated_at=datetime(2026, 4, 30, 12, 0, tzinfo=timezone.utc),
        base_url_host="example.com",
        tool_version="0.2.1",
        config_path="config.yaml",
        results=[
            CheckResult(
                name="Audit", description="d", status="warn", duration_ms=1000,
                findings=[],
                rule_results=[
                    RuleResult(
                        rule_id="r1", rule_name="Rule One", description="d",
                        severity="fail", status="fail", duration_ms=120,
                        findings=[Finding(severity="fail", message="example finding")],
                    ),
                ],
                summary={"rules_total": 1, "rules_pass": 0, "rules_warn": 0,
                         "rules_fail": 1, "rules_error": 0, "rules_skipped": 0},
            ),
        ],
    )


def test_severity_filter_uses_child_combinator_not_descendant():
    """Every body[data-filter-severity=...] rule must use `section.check > details`,
    not bare `section.check details`. The bare descendant form was the bug fixed
    in a91f6d1 -- it would hide inner finding-details too."""
    html = render_report(_minimal_context())

    pattern = re.compile(
        r'body\[data-filter-severity="[a-z]+"\]\s+section\.check\s+(>\s*)?details'
    )
    matches = pattern.findall(html)

    assert matches, (
        "expected at least one body[data-filter-severity=...] section.check ... "
        "details rule in the rendered HTML; found none"
    )
    for combinator in matches:
        assert combinator.strip().startswith(">"), (
            "filter rule must use `section.check > details` (child combinator). "
            "The descendant form (no `>`) hides inner finding-details too -- "
            "regression of a91f6d1."
        )


def test_no_descendant_combinator_for_severity_filter():
    """Belt-and-suspenders: greppable assertion that the bug pattern is absent."""
    html = render_report(_minimal_context())
    bad = re.search(
        r'body\[data-filter-severity="[a-z]+"\]\s+section\.check\s+details',
        html,
    )
    assert bad is None, (
        "found descendant-combinator filter rule (no `>` between section.check "
        "and details). Regression of a91f6d1: the inner finding-details would "
        "be hidden alongside the outer rule card."
    )


def test_section_check_has_scroll_margin_top():
    """Hash-link scroll must respect the sticky filter bar height; otherwise
    the rule's heading is covered by the bar after a click on a summary tile.
    Static-HTML pin: section.check has scroll-margin-top set to clear the bar."""
    html = render_report(_minimal_context())
    pattern = re.compile(
        r'section\.check\s*\{[^}]*scroll-margin-top\s*:\s*\d+(?:\.\d+)?\s*(?:px|rem|em)\b',
        re.DOTALL,
    )
    assert pattern.search(html), (
        "expected `section.check { ... scroll-margin-top: <length> }` rule in the "
        "rendered HTML; without it, hash-link scrolls land under the sticky "
        "filter bar."
    )


def test_hash_link_autoexpand_iife_present():
    """Clicking a summary tile sets the URL hash to #rule-<id>. The browser
    scrolls (covered by scroll-margin-top), but the native <details> stays
    collapsed unless we open() it. Pin the inline IIFE that does so."""
    html = render_report(_minimal_context())
    assert "expandFromHash" in html, "expandFromHash IIFE missing"
    assert "hashchange" in html, "hashchange listener missing"
    assert "details.open = true" in html or "details.open=true" in html, (
        "expandFromHash IIFE must set details.open = true"
    )
