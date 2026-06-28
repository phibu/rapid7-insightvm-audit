"""Tests for ``build_card_views`` -- the per-rule-card view-model that pulls the
template's inline decisions back into pure Python (see CONTEXT.md "RuleCardView").

Each ``RuleCardView`` carries the three things the report template used to
decide itself: ``search_text`` (was the data-search-text Jinja slice the search
JS matched against), ``severity_css`` (was the 'fail if… else…' clamp), and
``changed`` (was the JS state-blob re-walk against the delta). The builder is
pure -- it reads the live results plus the delta the render already holds -- so
each card decision is unit-testable here, which the template never was.
"""
from __future__ import annotations

from datetime import datetime, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import (
    ReportContext,
    _severity_css,
    build_card_views,
    render_report,
)


def _check(rule_results):
    return CheckResult(
        name="Configuration Audit", description="d", status="warn",
        rule_results=rule_results,
    )


def test_view_built_per_rule_keyed_by_rule_id():
    rr = RuleResult(
        rule_id="r1", rule_name="Rule One", description="d",
        severity="warn", status="warn",
        findings=[Finding(severity="warn", message="m")],
    )
    views = build_card_views([_check([rr])], delta=None)
    assert set(views) == {"r1"}
    assert views["r1"].rule_id == "r1"


def test_severity_css_clamps_finding_severity():
    # The finding badge maps fail->fail, warn->warn, and everything else
    # (notably info) to the pass-styled badge -- the template ternary spelled
    # twice (lines 737, 817) is now this one filter.
    assert _severity_css("fail") == "fail"
    assert _severity_css("warn") == "warn"
    assert _severity_css("info") == "pass"
    assert _severity_css("anything-else") == "pass"


def test_search_text_is_lowercased_name_plus_messages():
    rr = RuleResult(
        rule_id="r1", rule_name="Stuck Scans", description="d",
        severity="warn", status="warn",
        findings=[
            Finding(severity="warn", message="Site ALPHA is stuck"),
            Finding(severity="warn", message="Site BETA is stuck"),
        ],
    )
    view = build_card_views([_check([rr])], delta=None)["r1"]
    assert view.search_text == "stuck scans site alpha is stuck site beta is stuck"


def test_search_text_no_findings_is_just_name():
    rr = RuleResult(
        rule_id="r1", rule_name="Empty Rule", description="d",
        severity="info", status="pass", findings=[],
    )
    view = build_card_views([_check([rr])], delta=None)["r1"]
    assert view.search_text == "empty rule"


def test_search_text_capped_at_200_chars():
    rr = RuleResult(
        rule_id="r1", rule_name="R", description="d",
        severity="warn", status="warn",
        findings=[Finding(severity="warn", message="x" * 500)],
    )
    view = build_card_views([_check([rr])], delta=None)["r1"]
    assert len(view.search_text) == 200


def _rrs(*ids):
    return [
        RuleResult(rule_id=i, rule_name=i.upper(), description="d",
                   severity="warn", status="warn",
                   findings=[Finding(severity="warn", message="m")])
        for i in ids
    ]


def test_changed_false_when_no_delta():
    views = build_card_views([_check(_rrs("r1", "r2"))], delta=None)
    assert views["r1"].changed is False
    assert views["r2"].changed is False


def test_changed_marks_rules_present_in_delta():
    delta = {
        "resolved": [{"signature": "s1", "rule_id": "r1"}],
        "new_fails": [{"signature": "s2", "rule_id": "r3"}],
        "severity_changed": [{"signature": "s3", "rule_id": "r2"}],
    }
    views = build_card_views([_check(_rrs("r1", "r2", "r4"))], delta=delta)
    assert views["r1"].changed is True   # resolved
    assert views["r2"].changed is True   # severity_changed
    assert views["r4"].changed is False  # untouched (r3 isn't even a current card)


def test_render_stamps_data_changed_server_side():
    # The full render path: with a prior where r1's fail is absent (so r1 is a
    # NEW fail in the delta), the rendered HTML must carry `data-changed` on
    # rule-r1 and not on rule-r2 -- computed in Python, no JS walk required.
    cr = CheckResult(
        name="Configuration Audit", description="d", status="fail",
        summary={"rules_total": 2, "rules_warn": 0, "rules_pass": 1,
                 "rules_fail": 1, "rules_error": 0, "rules_skipped": 0},
        rule_results=[
            RuleResult(rule_id="r1", rule_name="Stuck", description="d",
                       severity="fail", status="fail",
                       findings=[Finding(severity="fail", message="now failing")]),
            RuleResult(rule_id="r2", rule_name="Clean", description="d",
                       severity="info", status="pass"),
        ],
    )
    ctx = ReportContext(
        title="T", generated_at=datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc),
        base_url_host="console.example.com", tool_version="9.9.9",
        config_path="config.yaml", results=[cr],
    )
    prior = {
        "base_url_host": "console.example.com",
        "generated_at": "2026-06-25T12:00:00Z",
        "results": [{"name": "Configuration Audit", "status": "pass", "findings": [],
                     "rule_results": [{"rule_id": "r2", "findings": []}]}],
    }
    html = render_report(ctx, prior_state=prior)
    # r1 card carries data-changed; r2 card does not.
    r1 = html[html.index('id="rule-r1"'):html.index('id="rule-r2"')]
    r2 = html[html.index('id="rule-r2"'):]
    assert "data-changed" in r1
    assert "data-changed" not in r2[:r2.index(">")]


def test_rail_counts_use_findings_of_not_the_flat_mirror():
    # The rail must count fail/warn from the canonical findings_of walk
    # (rule_results xor top-level), not the r.findings flat mirror -- which can
    # drift. Here the mirror is deliberately empty while rule_results carries a
    # fail + a warn; the rail count must reflect rule_results.
    from rapid7_healthcheck.report import build_rail_counts
    cr = CheckResult(
        name="Audit", description="d", status="fail",
        findings=[],  # mirror intentionally empty
        rule_results=[
            RuleResult(rule_id="r1", rule_name="A", description="d",
                       severity="fail", status="fail",
                       findings=[Finding(severity="fail", message="m")]),
            RuleResult(rule_id="r2", rule_name="B", description="d",
                       severity="warn", status="warn",
                       findings=[Finding(severity="warn", message="m"),
                                 Finding(severity="info", message="ctx")]),
        ],
    )
    counts = build_rail_counts([cr])
    assert counts[0] == {"fail": 1, "warn": 1}
