from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.client import Rapid7ClientError


def _asset(host: str, asset_id: int = 1) -> dict:
    return {"id": asset_id, "hostName": host}


def _rule(result, rule_id: str):
    """Pull a RuleResult by its op.* rule_id."""
    return next(rr for rr in result.rule_results if rr.rule_id == rule_id)


def _paged_search_responder(stale: list[dict], never_scanned: list[dict], *, page_size: int = 500):
    """Build a post_one responder simulating the /api/3/assets/search envelope.

    Branches on the filter `value` (30 = stale, 90 = never-scanned in the
    default fixture) and slices `resources` by `params["page"]`, mirroring how
    the real endpoint paginates. `page.totalResources` always reports the full
    match count so the rule's bounded fetch can read the exact total from
    page 0 -- which is the whole point of the perf fix.
    """
    def _responder(json_body: dict, params: dict | None) -> dict:
        text = str(json_body)
        if "'value': 90" in text or '"value": 90' in text:
            rows = never_scanned
        elif "'value': 30" in text or '"value": 30' in text:
            rows = stale
        else:
            rows = []
        page = int((params or {}).get("page", 0))
        size = int((params or {}).get("size", page_size))
        start = page * size
        chunk = rows[start:start + size]
        total = len(rows)
        total_pages = (total + size - 1) // size if total else 0
        return {
            "resources": chunk,
            "page": {"totalResources": total, "totalPages": total_pages,
                     "number": page, "size": size},
        }
    return _responder


class _FakeSnapshot:
    """Minimal fake EnvSnapshot for op-check tests.

    Only implements the methods the asset_coverage rules touch. Add a method
    here when a new rule needs new snapshot data.
    """

    def __init__(
        self,
        *,
        sites: list[dict] | None = None,
        asset_groups: list[dict] | None = None,
        member_counts: dict[int, int | None] | None = None,
        total_asset_count: int = 0,
    ):
        self._sites = sites or []
        self._asset_groups = asset_groups or []
        self._member_counts = member_counts or {}
        self._total_asset_count = total_asset_count

    def sites(self): return self._sites
    def asset_groups(self): return self._asset_groups
    def total_asset_count(self): return self._total_asset_count

    def asset_group_member_count(self, group_id: int) -> int | None:
        """Test stub. Return the registered count, or raise so test
        authors notice they forgot to register a fallback."""
        if group_id not in self._member_counts:
            raise AssertionError(
                f"_FakeSnapshot.asset_group_member_count({group_id}) not registered"
            )
        return self._member_counts[group_id]


def test_all_assets_fresh(fake_client, app_config):
    # Default post_one stub returns an empty envelope (totalResources=0) for
    # every search, so both stale and never-scanned see zero matches.
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=_FakeSnapshot())
    assert result.status == "pass"
    assert _rule(result, "op.asset_coverage.stale_assets").summary["stale_count"] == 0
    assert _rule(result, "op.asset_coverage.never_scanned_assets").summary["unscanned_count"] == 0


def test_stale_assets_warn(fake_client, app_config):
    """Stale: last scan older than stale_asset_days but newer than never_scanned_days."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    stale = [_asset(f"old-{i}", i) for i in range(3)]
    fc.set_post_one_responder(
        "/api/3/assets/search", _paged_search_responder(stale, []),
    )

    result = AssetCoverageCheck().run(fc, app_config, snapshot=_FakeSnapshot())
    assert result.status == "warn"
    stale_rule = _rule(result, "op.asset_coverage.stale_assets")
    assert stale_rule.status == "warn"
    assert stale_rule.summary["stale_count"] == 3


def test_never_scanned_assets_fail(fake_client, app_config):
    """Effectively-never-scanned: last scan older than never_scanned_days."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    never_scanned = [_asset(f"never-{i}", i) for i in range(2)]
    fc.set_post_one_responder(
        "/api/3/assets/search", _paged_search_responder([], never_scanned),
    )
    result = AssetCoverageCheck().run(fc, app_config)
    assert result.status == "fail"
    ns = _rule(result, "op.asset_coverage.never_scanned_assets")
    assert ns.status == "fail"
    assert ns.summary["unscanned_count"] == 2


def test_unscanned_check_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import AssetCoverageThresholds
    new_thresholds = replace(
        app_config.thresholds,
        asset_coverage=AssetCoverageThresholds(
            stale_asset_days=30,
            flag_unscanned_assets=False,
            never_scanned_days=90,
        ),
    )
    cfg = replace(app_config, thresholds=new_thresholds)

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    result = AssetCoverageCheck().run(fc, cfg, snapshot=_FakeSnapshot())
    assert result.status == "pass"
    search_calls = [
        c for c in fc.calls
        if c[0] == "post_one" and c[1] == "/api/3/assets/search"
    ]
    # never_scanned is skipped (off); stale_assets and ghost_assets each issue
    # one search POST. Bounded fetch over an empty result set is one POST
    # per rule, so 2 total.
    assert len(search_calls) == 2
    # The never-scanned rule should be skipped.
    ns = _rule(result, "op.asset_coverage.never_scanned_assets")
    assert ns.status == "skipped"


def test_per_asset_findings_stale(fake_client, app_config):
    """Stale path returns 25 assets -- emit one Finding per asset so the report's
    Findings column reflects the true count."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"host-{i}", i) for i in range(25)]
    fc.set_post_one_responder(
        "/api/3/assets/search", _paged_search_responder(stale, []),
    )
    result = AssetCoverageCheck().run(fc, app_config, snapshot=_FakeSnapshot())
    stale_rule = _rule(result, "op.asset_coverage.stale_assets")
    # One Finding per stale asset; below the cap, no rollup.
    assert len(stale_rule.findings) == 25
    assert stale_rule.summary["stale_count"] == 25
    for f in stale_rule.findings:
        assert f.severity == "warn"
        assert "stale asset" in f.message.lower()
        assert f.details["asset_id"] is not None
        assert f.details["stale_asset_days"] == 30


def test_per_asset_findings_capped_with_rollup(fake_client, app_config):
    """When affected assets exceed the per-item cap, emit cap + 1 rollup finding.

    Keeps the report bounded while still letting summary["stale_count"] reflect
    the true affected-asset count.
    """
    from rapid7_healthcheck.checks.asset_coverage import _PER_ITEM_FINDING_CAP
    from tests.conftest import FakeRapid7Client

    fc = FakeRapid7Client()
    overflow = _PER_ITEM_FINDING_CAP + 17
    stale = [_asset(f"host-{i}", i) for i in range(overflow)]
    fc.set_post_one_responder(
        "/api/3/assets/search", _paged_search_responder(stale, []),
    )
    result = AssetCoverageCheck().run(fc, app_config, snapshot=_FakeSnapshot())
    stale_rule = _rule(result, "op.asset_coverage.stale_assets")
    assert len(stale_rule.findings) == _PER_ITEM_FINDING_CAP + 1
    # Exact count comes from page.totalResources, not len() of a fetched list.
    assert stale_rule.summary["stale_count"] == overflow
    rollup = stale_rule.findings[-1]
    assert "more asset" in rollup.message.lower()
    assert rollup.details["remainder"] == 17
    assert rollup.details["total"] == overflow
    assert rollup.details["cap"] == _PER_ITEM_FINDING_CAP
    # The rule fetched only the bounded head -- not all `overflow` rows.
    # cap (500) == page size (500), so exactly one search POST.
    search_calls = [
        c for c in fc.calls
        if c[0] == "post_one" and c[1] == "/api/3/assets/search"
        and ("'value': 30" in str(c[3]) or '"value": 30' in str(c[3]))
    ]
    assert len(search_calls) == 1


def test_uses_is_earlier_than_operator_with_threshold(fake_client, app_config):
    """Regression guard: filter must use is-earlier-than with the configured
    never_scanned_days value, not the invalid is-empty operator."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured_filters: list[dict] = []

    def _responder(json_body: dict, params: dict | None) -> dict:
        captured_filters.append(json_body)
        return {"resources": [], "page": {"totalResources": 0, "totalPages": 0}}

    fc.set_post_one_responder("/api/3/assets/search", _responder)
    AssetCoverageCheck().run(fc, app_config)

    # stale + never-scanned (both last-scan-date) + ghost_assets (operating-system).
    assert len(captured_filters) == 3
    # The regression guards stale and never_scanned: those two send a
    # single-filter body keyed on last-scan-date. They must use is-earlier-than;
    # neither may use is-empty.
    single_lsd_filters = [
        f for f in captured_filters
        if len(f["filters"]) == 1 and f["filters"][0]["field"] == "last-scan-date"
    ]
    assert len(single_lsd_filters) == 2
    for f in single_lsd_filters:
        ops = [filt["operator"] for filt in f["filters"]]
        assert "is-empty" not in ops, f"is-empty operator must not be used: {f}"
        assert all(op == "is-earlier-than" for op in ops), f"unexpected operator: {f}"
    # never_scanned filter uses 90 (default).
    never_scanned = [f for f in single_lsd_filters if f["filters"][0]["value"] == 90]
    assert len(never_scanned) == 1


# ----- R1: dead_asset_groups -----


def test_r1_dead_asset_groups_all_populated(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[
        {"id": 1, "name": "Prod Servers", "type": "dynamic", "assets": 250},
        {"id": 2, "name": "Workstations", "type": "static", "assets": 50},
    ])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "pass"
    assert rule.summary["dead_groups_count"] == 0


def test_r1_dead_asset_groups_some_empty(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[
        {"id": 1, "name": "Prod Servers", "type": "dynamic", "assets": 250},
        {"id": 2, "name": "Decommissioned", "type": "static", "assets": 0},
        {"id": 3, "name": "Old Pilot", "type": "dynamic", "assets": 0},
    ])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "warn"
    assert rule.summary["dead_groups_count"] == 2
    # One Finding per dead group → Findings column reflects the true count.
    assert len(rule.findings) == 2
    names = {f.details["group_name"] for f in rule.findings}
    assert names == {"Decommissioned", "Old Pilot"}
    # card_summary populated (F1 sub2): 3 groups examined, 2 dead, 1 alive.
    assert rule.card_summary == {"examined": 3, "passed": 1, "failed": 2}
    # Aggregate-style sibling rules (stale, never-scanned, agent-only) leave card_summary=None.
    assert _rule(result, "op.asset_coverage.stale_assets").card_summary is None


def test_r1_dead_asset_groups_no_groups(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "pass"
    assert rule.summary["dead_groups_count"] == 0


def test_r1_dead_asset_groups_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_dead_asset_groups=False,
            ),
        ),
    )
    snap = _FakeSnapshot(asset_groups=[{"id": 1, "name": "g", "type": "static", "assets": 0}])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "skipped"


def test_r1_dead_asset_groups_errors_when_snapshot_missing(fake_client, app_config):
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "error"
    # An error RuleResult carries no findings -- the reason lives in summary,
    # consistent with the error_rule() helper. A spurious warn-severity
    # finding inside an error rule would pollute flatten_findings / the
    # delta signature index.
    assert rule.findings == []
    assert rule.summary.get("error") == "snapshot required"


def test_r1_dead_asset_groups_missing_inline_alive_via_fallback(fake_client, app_config):
    """Regression: groups with missing inline `assets` count must NOT be
    flagged as dead when the per-id fallback reveals members."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 10, "name": "Dynamic Prod", "type": "dynamic"},  # no `assets` key
            {"id": 11, "name": "Dynamic Workstations", "type": "dynamic"},  # no `assets` key
        ],
        member_counts={10: 42, 11: 0},
    )
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    # Only group 11 is truly dead -- group 10 has 42 members per fallback.
    assert rule.summary["dead_groups_count"] == 1
    assert rule.summary["groups_with_missing_count"] == 2
    assert rule.summary["fallback_calls_made"] == 2
    assert rule.summary["fallback_cap_reached"] is False
    assert rule.summary["fallback_errors"] == 0
    dead_names = {f.details["group_name"] for f in rule.findings if f.severity == "warn"}
    assert dead_names == {"Dynamic Workstations"}


def test_r1_dead_asset_groups_fallback_cap_reached(fake_client, app_config):
    """When more missing-inline groups than the cap, emit info finding and
    set fallback_cap_reached=True. Groups beyond the cap are not resolved."""
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                dead_groups_fallback_cap=2,
            ),
        ),
    )
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "g1", "type": "dynamic"},  # missing inline
            {"id": 2, "name": "g2", "type": "dynamic"},  # missing inline
            {"id": 3, "name": "g3", "type": "dynamic"},  # missing inline, beyond cap
        ],
        member_counts={1: 0, 2: 5},  # group 3 not registered (rule must not call it)
    )
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["groups_with_missing_count"] == 3
    assert rule.summary["fallback_calls_made"] == 2
    assert rule.summary["fallback_cap_reached"] is True
    # Only group 1 was both within cap AND zero-membership.
    assert rule.summary["dead_groups_count"] == 1
    # Cap-tail info finding present.
    assert any(
        f.severity == "info" and "fallback skipped" in f.message
        for f in rule.findings
    )


def test_r1_dead_asset_groups_fallback_error(fake_client, app_config):
    """When the fallback returns None (HTTP error), surface an info finding
    and do NOT flag the group as dead."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 5, "name": "broken-group", "type": "dynamic"},
        ],
        member_counts={5: None},  # simulate accessor returning None
    )
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["dead_groups_count"] == 0
    assert rule.summary["fallback_errors"] == 1
    # Info finding emitted for the unresolvable group.
    assert any(
        f.severity == "info" and f.details.get("group_id") == 5
        for f in rule.findings
    )
    # No warn-severity finding for that group.
    assert not any(
        f.severity == "warn" and (f.details or {}).get("group_id") == 5
        for f in rule.findings
    )


def test_r1_dead_asset_groups_fallback_cap_zero_disables_fallback(fake_client, app_config):
    """cap=0: missing-inline groups are not resolved and not flagged as dead.
    Different from the pre-fix bug, which flagged every missing-inline group."""
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                dead_groups_fallback_cap=0,
            ),
        ),
    )
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "missing-inline", "type": "dynamic"},  # no assets key
            {"id": 2, "name": "explicit-zero", "type": "static", "assets": 0},
        ],
        member_counts={},  # cap=0 means no fallback calls; nothing to register
    )
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    # Only the explicit-zero group is flagged dead. The missing-inline group
    # is NOT flagged (and not resolved).
    assert rule.summary["dead_groups_count"] == 1
    assert rule.summary["groups_with_missing_count"] == 1
    assert rule.summary["fallback_calls_made"] == 0
    # cap_reached is True when missing > calls (cap=0, missing=1).
    assert rule.summary["fallback_cap_reached"] is True
    dead_names = {
        f.details["group_name"] for f in rule.findings
        if f.severity == "warn" and "group_name" in (f.details or {})
    }
    assert dead_names == {"explicit-zero"}


def test_r1_dead_asset_groups_non_numeric_inline_treated_as_missing(fake_client, app_config):
    """If a console returns a non-numeric `assets` value, treat as missing
    (route through fallback) rather than crashing or false-flagging."""
    snap = _FakeSnapshot(
        asset_groups=[
            {"id": 1, "name": "weird", "type": "dynamic", "assets": "n/a"},
        ],
        member_counts={1: 7},
    )
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    assert rule.summary["dead_groups_count"] == 0
    assert rule.summary["groups_with_missing_count"] == 1
    assert rule.summary["fallback_calls_made"] == 1


# ----- R4: agent_only_assets (server-side site-id membership, #32) -----
# Rewritten from the old sampled/per-asset-GET version. The rule now computes
# the EXACT set of agent-site assets that belong to no scan site, server-side
# via POST /api/3/assets/search with site-id filters (count from
# page.totalResources, example rows bounded). No sampling, no per-asset GET.


def _agent_site_responder(agent_only_rows: list[dict], *, page_size: int = 500):
    """Responder for the agent-only query: returns rows only when the body
    carries a `site-id` `in` filter (the membership query the rule issues).
    Paginates and reports the full count in page.totalResources.
    """
    def _responder(json_body: dict, params: dict | None) -> dict:
        text = str(json_body)
        rows = agent_only_rows if "site-id" in text and "'in'" in text.replace('"', "'") else []
        page = int((params or {}).get("page", 0))
        size = int((params or {}).get("size", page_size))
        chunk = rows[page * size: page * size + size]
        total = len(rows)
        total_pages = (total + size - 1) // size if total else 0
        return {
            "resources": chunk,
            "page": {"totalResources": total, "totalPages": total_pages,
                     "number": page, "size": size},
        }
    return _responder


def _r4_app_config(app_config, *, agent_site_name: str = "Rapid7 Insight Agents"):
    """app_config with the agent-only flag on and a configurable agent site name."""
    asset_coverage = replace(
        app_config.thresholds.asset_coverage,
        flag_agent_only_assets=True,
        agent_site_name=agent_site_name,
    )
    thresholds = replace(app_config.thresholds, asset_coverage=asset_coverage)
    return replace(app_config, thresholds=thresholds)


_AGENT_SITE = {"id": 7, "name": "Rapid7 Insight Agents"}
_SCAN_SITE_A = {"id": 1, "name": "DC Scan"}
_SCAN_SITE_B = {"id": 2, "name": "DMZ Scan"}


def test_r4_exact_count_from_metadata(fake_client, app_config):
    """The gap count is the exact page.totalResources, not a sample/estimate."""
    rows = [_asset(f"agent-only-{i}", i) for i in range(12)]
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder(rows))
    snap = _FakeSnapshot(sites=[_AGENT_SITE, _SCAN_SITE_A, _SCAN_SITE_B])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "warn"
    assert rule.summary["agent_only_count"] == 12
    assert rule.summary["agent_site_id"] == 7
    assert rule.summary["scan_sites"] == 2
    # New rule is not sampled.
    assert rule.sampled is False
    # Old sampled keys are gone.
    assert "agent_only_count_sampled" not in rule.summary
    assert "estimated_outsiders_fleetwide" not in rule.summary


def test_r4_zero_gap_passes(fake_client, app_config):
    """No agent-only assets → pass with an info note, no warn findings."""
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder([]))
    snap = _FakeSnapshot(sites=[_AGENT_SITE, _SCAN_SITE_A])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "pass"
    assert rule.summary["agent_only_count"] == 0


def test_r4_example_rows_bounded_with_rollup(fake_client, app_config):
    """More than the per-item cap → capped example rows + one rollup finding;
    the rollup reflects the true total from metadata."""
    from rapid7_healthcheck.checks.asset_coverage import _PER_ITEM_FINDING_CAP
    n = _PER_ITEM_FINDING_CAP + 40
    rows = [_asset(f"a-{i}", i) for i in range(n)]
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder(rows))
    snap = _FakeSnapshot(sites=[_AGENT_SITE, _SCAN_SITE_A])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.summary["agent_only_count"] == n
    # capped per-asset findings + one rollup
    assert len(rule.findings) == _PER_ITEM_FINDING_CAP + 1
    assert rule.findings[-1].details["remainder"] == 40


def test_r4_no_scan_sites_all_agent_assets_are_gap(fake_client, app_config):
    """When the agent site is the only site, every agent asset is agent-only;
    the rule queries site-id in [agent] with no not-in clause."""
    rows = [_asset("lonely", 1)]
    # Responder returns rows whenever a site-id 'in' filter is present.
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder(rows))
    snap = _FakeSnapshot(sites=[_AGENT_SITE])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.summary["agent_only_count"] == 1
    assert rule.summary["scan_sites"] == 0


def test_r4_no_agent_site_passes_with_note(fake_client, app_config):
    """No site matches the configured agent-site name → info pass, no query."""
    snap = _FakeSnapshot(sites=[_SCAN_SITE_A, _SCAN_SITE_B])
    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "pass"
    assert rule.summary["agent_site_id"] is None
    assert any("no site named" in f.message.lower() or "not found" in f.message.lower()
               for f in rule.findings)


def test_r4_agent_site_name_is_configurable(fake_client, app_config):
    """A renamed agent site is found via the agent_site_name knob."""
    rows = [_asset("x", 1)]
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder(rows))
    custom = {"id": 99, "name": "Agents - EU"}
    snap = _FakeSnapshot(sites=[custom, _SCAN_SITE_A])

    cfg = _r4_app_config(app_config, agent_site_name="Agents - EU")
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.summary["agent_site_id"] == 99
    assert rule.summary["agent_only_count"] == 1


def test_r4_skipped_when_flag_off(fake_client, app_config):
    """flag_agent_only_assets defaults to False -- rule must skip."""
    snap = _FakeSnapshot(sites=[_AGENT_SITE, _SCAN_SITE_A])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_error_when_snapshot_none(fake_client, app_config):
    """flag on + snapshot=None → error status with a clear summary message."""
    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=None)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "error"
    assert rule.findings == []
    assert rule.summary.get("error") == "snapshot required"


def test_r4_rule_id_preserved(fake_client, app_config):
    """Drift guard: rule_id stable for delta-blob signature continuity."""
    fake_client.set_post_one_responder("/api/3/assets/search", _agent_site_responder([]))
    snap = _FakeSnapshot(sites=[_AGENT_SITE, _SCAN_SITE_A])
    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.rule_id == "op.asset_coverage.agent_only_assets"


# ----- integration: shape, rollup, backwards-compat -----

def test_run_returns_four_rule_results(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert len(result.rule_results) == 5
    rule_ids = [r.rule_id for r in result.rule_results]
    assert rule_ids == [
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
        "op.asset_coverage.ghost_assets",
    ]


def test_check_status_rolls_up_to_warn_when_any_rule_warns(fake_client, app_config):
    """A non-empty stale_assets rule (warn severity) drives the check to warn."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"stale-{i}", i) for i in range(3)]
    fc.set_post_one_responder(
        "/api/3/assets/search", _paged_search_responder(stale, []),
    )
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    assert result.status == "warn"


def test_check_status_pass_when_all_rules_pass(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert result.status == "pass"


def test_optional_snapshot_kwarg_is_backwards_compatible(fake_client, app_config):
    """Calling without snapshot still works for client-only rules; snapshot-needing rules return error."""
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    # Client-only rules complete normally
    assert _rule(result, "op.asset_coverage.stale_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.never_scanned_assets").status == "pass"
    # Snapshot-dependent rules error cleanly (don't crash)
    assert _rule(result, "op.asset_coverage.dead_asset_groups").status == "error"
    # R4 is skipped because flag_agent_only_assets=False by default -- toggle check fires before snapshot check
    assert _rule(result, "op.asset_coverage.agent_only_assets").status == "skipped"


def test_per_rule_failure_isolated_other_rules_still_run(fake_client, app_config):
    """If one asset-coverage rule's API call raises, the other three rules
    still produce output. Mirrors the data_quality 0.2.8 regression test.

    Triggers the failure on _stale_assets's bounded asset search via the
    rule's filter (last-scan-date is-earlier-than stale_asset_days). The
    stale_asset_days value is derived from app_config at runtime so the
    test stays correct if the fixture default ever changes.
    """
    stale_days = app_config.thresholds.asset_coverage.stale_asset_days

    def _responder(json_body: dict, params: dict | None) -> dict:
        # Match _stale_assets specifically: single filter, last-scan-date
        # is-earlier-than stale_asset_days.
        filters = json_body.get("filters", [])
        if (
            len(filters) == 1
            and filters[0].get("field") == "last-scan-date"
            and filters[0].get("operator") == "is-earlier-than"
            and filters[0].get("value") == stale_days
        ):
            raise Rapid7ClientError("Read timed out", status_code=None)
        return {"resources": [], "page": {"totalResources": 0, "totalPages": 0}}

    fake_client.set_post_one_responder("/api/3/assets/search", _responder)
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    # All 5 rules produce a RuleResult (the failing one as 'error', the
    # others normally).
    assert len(result.rule_results) == 5
    stale = _rule(result, "op.asset_coverage.stale_assets")
    assert stale.status == "error"
    assert "Read timed out" in (stale.error or "")

    # Other rules still ran -- exact status depends on fake_client setup, but
    # they must not be 'error' from the same exception.
    for rid in (
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
        "op.asset_coverage.ghost_assets",
    ):
        rr = _rule(result, rid)
        assert rr.status in ("pass", "warn", "fail", "skipped"), \
            f"Rule {rid} should not be 'error' from another rule's failure; got {rr.status}"


from rapid7_healthcheck.checks import Finding
from rapid7_healthcheck.checks.asset_coverage import _capped_findings_with_rollup


def _make_finding(item):
    return Finding(severity="warn", message=f"item {item['id']}", details={"id": item["id"]})


def test_capped_helper_under_cap_no_rollup():
    items = [{"id": i} for i in range(3)]
    out = _capped_findings_with_rollup(
        items, _make_finding, severity="warn", label="thing", cap=10,
    )
    assert len(out) == 3
    assert all("more thing" not in f.message for f in out)


def test_capped_helper_at_cap_no_rollup():
    items = [{"id": i} for i in range(5)]
    out = _capped_findings_with_rollup(
        items, _make_finding, severity="warn", label="thing", cap=5,
    )
    assert len(out) == 5
    assert all("more thing" not in f.message for f in out)


def test_capped_helper_over_cap_emits_rollup():
    items = [{"id": i} for i in range(7)]
    out = _capped_findings_with_rollup(
        items, _make_finding, severity="warn", label="thing", cap=5,
    )
    assert len(out) == 6
    rollup = out[-1]
    assert rollup.severity == "warn"
    assert "+ 2 more thing(s)" in rollup.message
    assert rollup.details == {"remainder": 2, "total": 7, "cap": 5}


def test_capped_helper_rollup_details_extra_merges():
    items = [{"id": i} for i in range(3)]
    out = _capped_findings_with_rollup(
        items, _make_finding, severity="warn", label="asset", cap=2,
        rollup_details_extra={"sample_strategy": "first-n"},
    )
    rollup = out[-1]
    assert rollup.details == {
        "remainder": 1, "total": 3, "cap": 2,
        "sample_strategy": "first-n",
    }


def test_capped_helper_cap_zero_emits_only_rollup():
    items = [{"id": i} for i in range(3)]
    out = _capped_findings_with_rollup(
        items, _make_finding, severity="warn", label="thing", cap=0,
    )
    # No head findings, just one rollup covering all items.
    assert len(out) == 1
    assert out[0].details == {"remainder": 3, "total": 3, "cap": 0}
    assert "+ 3 more thing(s)" in out[0].message


def test_rule_identity_matches_method_constants(fake_client, app_config):
    """Drift guard: the rule_id strings duplicated in run()'s safe_run()
    wrappers must match the rule_id each rule method emits internally.

    Without this guard, if a rule method's rule_id changes but the
    wrapper's stays the same, the report renders the wrapper's stale
    identity for the success path and the method's new identity for the
    error path -- confusing operators and breaking delta-blob signatures.
    """
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    expected_rule_ids = {
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
        "op.asset_coverage.ghost_assets",
    }
    actual_rule_ids = {rr.rule_id for rr in result.rule_results}
    assert actual_rule_ids == expected_rule_ids


# ----- F1: ghost_assets -----


def _ghost_responder(resources: list[dict], *, total: int | None = None):
    """Build a post_one responder for the `operating-system is-empty` filter
    (the ghost_assets server-side query); empty envelope otherwise.

    Paginates by ``params["page"]`` / ``params["size"]`` the way the real
    endpoint does, because ``GhostAssetsRule`` now fetches via
    ``_bounded_asset_search`` (which reads ``page.totalResources`` /
    ``page.totalPages`` and loops). ``total`` overrides the reported
    ``totalResources`` so a test can simulate "more OS-empty assets exist
    than were returned in this page" (partial detection) without
    materializing the full list -- pass ``total > len(resources)``.
    """
    reported_total = len(resources) if total is None else total

    def _responder(json_body: dict, params: dict | None) -> dict:
        filters = json_body.get("filters", [])
        if (
            len(filters) == 1
            and filters[0].get("field") == "operating-system"
            and filters[0].get("operator") == "is-empty"
        ):
            page = int((params or {}).get("page", 0))
            size = int((params or {}).get("size", 500))
            start = page * size
            chunk = resources[start:start + size]
            total_pages = (reported_total + size - 1) // size if reported_total else 0
            return {
                "resources": chunk,
                "page": {"totalResources": reported_total, "totalPages": total_pages,
                         "number": page, "size": size},
            }
        # last-scan-date filters (stale / never-scanned) → empty.
        return {"resources": [], "page": {"totalResources": 0, "totalPages": 0}}
    return _responder


def test_ghost_assets_emits_finding_when_asset_lacks_both_os_and_hostname(fake_client, app_config):
    """Server-side: OS is-empty. Client-side: hostName empty narrows further."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([
            {"id": 1, "hostName": None, "ip": "10.0.0.1"},   # ghost
            {"id": 2, "hostName": "foo", "ip": "10.0.0.2"},  # not ghost (has hostname)
        ]),
    )
    result = AssetCoverageCheck().run(fc, app_config, snapshot=_FakeSnapshot(total_asset_count=1000))
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.status == "fail"
    assert rule.summary["ghost_count"] == 1
    assert rule.summary["os_empty_total"] == 2
    assert rule.summary["os_empty_examined"] == 2
    assert rule.summary["ghost_detection_partial"] is False
    assert len(rule.findings) == 1
    f = rule.findings[0]
    assert f.severity == "fail"
    assert f.details["id"] == 1
    assert f.details["ip"] == "10.0.0.1"


def test_ghost_assets_skipped_when_flag_disabled(fake_client, app_config):
    """flag_ghost_assets=False → skipped_rule (status=skipped, no POST)."""
    from rapid7_healthcheck.config import AssetCoverageThresholds
    new_thresholds = replace(
        app_config.thresholds,
        asset_coverage=AssetCoverageThresholds(
            stale_asset_days=30,
            flag_unscanned_assets=True,
            never_scanned_days=90,
            flag_ghost_assets=False,
        ),
    )
    cfg = replace(app_config, thresholds=new_thresholds)

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    # Even if the responder would return ghosts, the rule must not call it.
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([{"id": 99, "hostName": None}]),
    )
    result = AssetCoverageCheck().run(fc, cfg)
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.status == "skipped"
    # No OS-is-empty POST was issued.
    os_calls = [
        c for c in fc.calls
        if c[0] == "post_one" and c[1] == "/api/3/assets/search"
        and "operating-system" in str(c[3])
    ]
    assert os_calls == []


def test_ghost_assets_bounded_fetch_caps_at_per_item_cap_and_discloses_partial(fake_client, app_config):
    """When more OS-empty assets exist than the bounded fetch returns, the rule
    inspects only the first cap rows for missing hostnames, reports ghost_count
    as a lower bound, flags ghost_detection_partial, and emits an info
    disclosure. card_summary is suppressed because passed would over-count."""
    from rapid7_healthcheck.checks.asset_coverage import _PER_ITEM_FINDING_CAP
    from tests.conftest import FakeRapid7Client

    fc = FakeRapid7Client()
    overflow = _PER_ITEM_FINDING_CAP + 10  # 510 OS-empty assets exist
    # All have empty hostName → every fetched row is a ghost.
    ghost_candidates = [
        {"id": i, "hostName": None, "ip": f"10.0.0.{i % 254 + 1}"}
        for i in range(overflow)
    ]
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder(ghost_candidates, total=overflow),
    )
    result = AssetCoverageCheck().run(
        fc, app_config, snapshot=_FakeSnapshot(total_asset_count=50_000)
    )
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.status == "fail"
    # Only the bounded head was inspected → ghost_count is the cap, not 510.
    assert rule.summary["ghost_count"] == _PER_ITEM_FINDING_CAP
    assert rule.summary["os_empty_total"] == overflow
    assert rule.summary["os_empty_examined"] == _PER_ITEM_FINDING_CAP
    assert rule.summary["ghost_detection_partial"] is True
    # cap fail-findings + 1 info partial-disclosure (no per-item rollup, since
    # ghosts == fetched head == cap, so nothing was omitted from findings).
    fail_findings = [f for f in rule.findings if f.severity == "fail"]
    info_findings = [f for f in rule.findings if f.severity == "info"]
    assert len(fail_findings) == _PER_ITEM_FINDING_CAP
    assert len(info_findings) == 1
    disclosure = info_findings[0]
    assert "lower bound" in disclosure.message
    assert disclosure.details["os_empty_total"] == overflow
    assert disclosure.details["os_empty_examined"] == _PER_ITEM_FINDING_CAP
    # Standardized card line suppressed when partial -- passed would over-count.
    assert rule.card_summary is None


def test_ghost_assets_handles_empty_candidates(fake_client, app_config):
    """Empty candidate set → 0 findings, status=pass, complete card_summary."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([]),
    )
    result = AssetCoverageCheck().run(
        fc, app_config, snapshot=_FakeSnapshot(total_asset_count=1000)
    )
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.status == "pass"
    assert rule.findings == []
    assert rule.summary["ghost_count"] == 0
    assert rule.summary["os_empty_total"] == 0
    assert rule.summary["os_empty_examined"] == 0
    assert rule.summary["ghost_detection_partial"] is False
    # Complete + snapshot present → honest card line over the full population.
    assert rule.card_summary == {"examined": 1000, "passed": 1000, "failed": 0}


def test_ghost_assets_whitespace_only_hostname_counts_as_empty(fake_client, app_config):
    """A whitespace-only hostName should be treated as empty (strip())."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([{"id": 1, "hostName": "   ", "ip": "10.0.0.5"}]),
    )
    result = AssetCoverageCheck().run(
        fc, app_config, snapshot=_FakeSnapshot(total_asset_count=1000)
    )
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.summary["ghost_count"] == 1
    assert len(rule.findings) == 1


def test_ghost_assets_card_summary_uses_total_asset_count_as_denominator(fake_client, app_config):
    """Complete detection + snapshot present: card_summary's 'examined' is the
    deployment-wide total_asset_count() (the honest denominator), not the
    OS-empty candidate pool. 'failed' is the ghost count; 'passed' is the
    remainder of the full population."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([
            {"id": 1, "hostName": None, "ip": "10.0.0.1"},   # ghost
            {"id": 2, "hostName": None, "ip": "10.0.0.2"},   # ghost
            {"id": 3, "hostName": "named", "ip": "10.0.0.3"},  # OS-empty but named → not ghost
        ]),
    )
    result = AssetCoverageCheck().run(
        fc, app_config, snapshot=_FakeSnapshot(total_asset_count=50_000)
    )
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.summary["ghost_count"] == 2
    assert rule.summary["ghost_detection_partial"] is False
    # examined is the full population (50k), NOT the 3-asset OS-empty pool.
    assert rule.card_summary == {"examined": 50_000, "passed": 49_998, "failed": 2}


def test_ghost_assets_without_snapshot_reports_ghosts_but_no_card_summary(fake_client, app_config):
    """Snapshot absent (test fakes / edge cases): the rule cannot read the
    honest denominator, so card_summary is suppressed -- but ghost findings are
    still reported and the rule does NOT error out."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_post_one_responder(
        "/api/3/assets/search",
        _ghost_responder([
            {"id": 1, "hostName": None, "ip": "10.0.0.1"},   # ghost
            {"id": 2, "hostName": "foo", "ip": "10.0.0.2"},  # not ghost
        ]),
    )
    # No snapshot= kwarg → GhostAssetsRule.run receives snapshot=None.
    result = AssetCoverageCheck().run(fc, app_config)
    rule = _rule(result, "op.asset_coverage.ghost_assets")
    assert rule.status == "fail"          # ghost still detected and flagged
    assert rule.status != "error"
    assert rule.summary["ghost_count"] == 1
    assert rule.summary["ghost_detection_partial"] is False
    assert rule.card_summary is None      # suppressed -- no honest denominator
    assert len([f for f in rule.findings if f.severity == "fail"]) == 1
    assert rule.findings[0].severity == "fail"
    assert rule.findings[0].details["id"] == 1
