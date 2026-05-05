from __future__ import annotations

from dataclasses import replace
from ipaddress import ip_network

from rapid7_healthcheck.audit.snapshot import IncludedTargets
from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.client import Rapid7ClientError


def _asset(host: str, asset_id: int = 1) -> dict:
    return {"id": asset_id, "hostName": host}


def _rule(result, rule_id: str):
    """Pull a RuleResult by its op.* rule_id."""
    return next(rr for rr in result.rule_results if rr.rule_id == rule_id)


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
        agent_asset_ids: set[int] | None = None,
        agents_unavailable: bool = False,
        flip_unavailable_on_sample_call: bool = False,
        included_targets=None,
        full_scan: bool = False,
        sample_size: int = 500,
        sample_ids: list[int] | None = None,
        total_agents: int | None = None,
        member_counts: dict[int, int | None] | None = None,
    ):
        self._sites = sites or []
        self._asset_groups = asset_groups or []
        self._agent_asset_ids = agent_asset_ids or set()
        self._agents_unavailable = agents_unavailable
        self._flip_unavailable_on_sample_call = flip_unavailable_on_sample_call
        self._included_targets = included_targets
        self.full_scan = full_scan
        self.sample_size = sample_size
        self._sample_ids = sample_ids or []
        self._total_agents = total_agents if total_agents is not None else len(self._sample_ids)
        self._member_counts = member_counts or {}

    def sites(self): return self._sites
    def asset_groups(self): return self._asset_groups
    def agent_asset_ids(self): return self._agent_asset_ids
    def is_agents_unavailable(self): return self._agents_unavailable
    def all_included_targets(self): return self._included_targets

    def agent_asset_ids_sampled(self) -> tuple[list[int], int]:
        if self._flip_unavailable_on_sample_call and not self._agents_unavailable:
            self._agents_unavailable = True
            return [], 0
        if self._agents_unavailable:
            return [], 0
        return list(self._sample_ids), self._total_agents

    def asset_group_member_count(self, group_id: int) -> int | None:
        """Test stub. Return the registered count, or raise so test
        authors notice they forgot to register a fallback."""
        if group_id not in self._member_counts:
            raise AssertionError(
                f"_FakeSnapshot.asset_group_member_count({group_id}) not registered"
            )
        return self._member_counts[group_id]


def test_all_assets_fresh(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=_FakeSnapshot())
    assert result.status == "pass"
    assert _rule(result, "op.asset_coverage.stale_assets").summary["stale_count"] == 0
    assert _rule(result, "op.asset_coverage.never_scanned_assets").summary["unscanned_count"] == 0


def test_stale_assets_warn(fake_client, app_config):
    """Stale: last scan older than stale_asset_days but newer than never_scanned_days."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    stale = [_asset(f"old-{i}", i) for i in range(3)]
    unscanned: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        fc.calls.append(("paginate_post", path, params, json_body))
        text = str(json_body)
        # Both filters now use is-earlier-than; differentiate by value.
        # stale_asset_days=30, never_scanned_days=90 in default fixture.
        if "'value': 90" in text or '"value": 90' in text:
            yield from unscanned
        elif "'value': 30" in text or '"value": 30' in text:
            yield from stale
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]

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

    def paginate_post(path, json_body, params=None, page_size=500):
        fc.calls.append(("paginate_post", path, params, json_body))
        text = str(json_body)
        if "'value': 90" in text or '"value": 90' in text:
            yield from never_scanned
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
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
    fc.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fc, cfg, snapshot=_FakeSnapshot())
    assert result.status == "pass"
    paginate_post_calls = [c for c in fc.calls if c[0] == "paginate_post"]
    # never_scanned is skipped (off); only stale_assets remains as a paginate_post caller.
    assert len(paginate_post_calls) == 1
    # The never-scanned rule should be skipped.
    ns = _rule(result, "op.asset_coverage.never_scanned_assets")
    assert ns.status == "skipped"


def test_per_asset_findings_stale(fake_client, app_config):
    """Stale path returns 25 assets — emit one Finding per asset so the report's
    Findings column reflects the true count."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"host-{i}", i) for i in range(25)]

    def paginate_post(path, json_body, params=None, page_size=500):
        fc.calls.append(("paginate_post", path, params, json_body))
        text = str(json_body)
        if "'value': 90" in text or '"value": 90' in text:
            yield from []
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]
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

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "'value': 90" in text or '"value": 90' in text:
            yield from []
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config, snapshot=_FakeSnapshot())
    stale_rule = _rule(result, "op.asset_coverage.stale_assets")
    assert len(stale_rule.findings) == _PER_ITEM_FINDING_CAP + 1
    assert stale_rule.summary["stale_count"] == overflow
    rollup = stale_rule.findings[-1]
    assert "more asset" in rollup.message.lower()
    assert rollup.details["remainder"] == 17
    assert rollup.details["total"] == overflow
    assert rollup.details["cap"] == _PER_ITEM_FINDING_CAP


def test_uses_is_earlier_than_operator_with_threshold(fake_client, app_config):
    """Regression guard: filter must use is-earlier-than with the configured
    never_scanned_days value, not the invalid is-empty operator."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured_filters: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured_filters.append(json_body)
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    AssetCoverageCheck().run(fc, app_config)

    assert len(captured_filters) == 2  # stale + never-scanned
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
    fake_client.set_paginate_post("/api/3/assets/search", [])  # other rules
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
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "warn"
    assert rule.summary["dead_groups_count"] == 2
    # One Finding per dead group → Findings column reflects the true count.
    assert len(rule.findings) == 2
    names = {f.details["group_name"] for f in rule.findings}
    assert names == {"Decommissioned", "Old Pilot"}


def test_r1_dead_asset_groups_no_groups(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[])
    fake_client.set_paginate_post("/api/3/assets/search", [])
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
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "skipped"


def test_r1_dead_asset_groups_errors_when_snapshot_missing(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "error"
    assert "snapshot" in (rule.findings[0].message if rule.findings else "")


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
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")

    # Only group 11 is truly dead — group 10 has 42 members per fallback.
    assert rule.summary["dead_groups_count"] == 1
    assert rule.summary["groups_with_missing_count"] == 2
    assert rule.summary["fallback_calls_made"] == 2
    assert rule.summary["fallback_cap_reached"] is False
    assert rule.summary["fallback_errors"] == 0
    dead_names = {f.details["group_name"] for f in rule.findings if f.severity == "warn"}
    assert dead_names == {"Dynamic Workstations"}


# ----- R4: agent_only_assets (sampled, unconditional) -----
# Replaces the old full-enumeration tests. Rule now runs unconditionally
# regardless of audit.full_scan, samples up to audit.sample_size agents
# in API default order, and reports a directional estimate.


def _r4_targets(*cidrs: str) -> IncludedTargets:
    """Build an IncludedTargets covering the given CIDR blocks."""
    return IncludedTargets(networks=[ip_network(c, strict=False) for c in cidrs], literals=set())


def _r4_app_config(app_config, *, sample_size: int = 100, full_scan: bool = False):
    """Return an app_config with R4 flag on and configurable sample/full_scan."""
    audit = replace(app_config.audit, full_scan=full_scan, sample_size=sample_size)
    asset_coverage = replace(app_config.thresholds.asset_coverage, flag_agent_only_assets=True)
    thresholds = replace(app_config.thresholds, asset_coverage=asset_coverage)
    return replace(app_config, audit=audit, thresholds=thresholds)


def test_r4_runs_unconditionally(fake_client, app_config):
    """No full_scan setup; rule still produces real (non-skipped) findings."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[100, 101],
        total_agents=500_000,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_get("/api/3/assets/100", {"ip": "10.0.0.5", "hostName": "in-scope.local"})
    fake_client.set_get("/api/3/assets/101", {"ip": "192.168.1.5", "hostName": "outside.local"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    cfg = _r4_app_config(app_config, full_scan=False)
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "warn"
    assert rule.summary["agent_only_count_sampled"] == 1
    assert rule.summary["total_agents"] == 500_000


def test_r4_directional_summary_shape(fake_client, app_config):
    """All new summary keys present; old `agent_only_count` is gone."""
    sample_ids = list(range(100, 200))
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=sample_ids,
        total_agents=10_000,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    for aid in sample_ids:
        fake_client.set_get(f"/api/3/assets/{aid}", {"ip": "192.168.1.5", "hostName": f"h-{aid}"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config, sample_size=100), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    s = rule.summary
    assert s["agent_only_count_sampled"] == 100
    assert s["sample_size"] == 100
    assert s["sample_size_configured"] == 100
    assert s["sampled_fetched"] == 100
    assert s["total_agents"] == 10_000
    assert s["sampled_outside_scope_pct"] == 100.0
    assert s["estimated_outsiders_fleetwide"] == 10_000
    assert "agent_only_count" not in s


def test_r4_sample_info_set(fake_client, app_config):
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[1],
        total_agents=500,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_get("/api/3/assets/1", {"ip": "10.0.0.5", "hostName": "x"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.sampled is True
    assert rule.sample_info is not None
    assert "strategy=first-n" in rule.sample_info
    assert "population=500" in rule.sample_info


def test_r4_per_asset_404_excluded_from_denominator(fake_client, app_config):
    """30 of 100 IDs return 404 → percentage and extrapolation use 70 as denom."""
    sample_ids = list(range(100))
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=sample_ids,
        total_agents=10_000,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    for aid in sample_ids:
        if aid < 30:
            fake_client.set_get_raises(f"/api/3/assets/{aid}", Rapid7ClientError("404 at /api/3/assets/x", status_code=404))
        else:
            fake_client.set_get(f"/api/3/assets/{aid}", {"ip": "192.168.1.5", "hostName": f"h-{aid}"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    s = rule.summary
    assert s["sample_size"] == 100
    assert s["sampled_fetched"] == 70
    assert s["agent_only_count_sampled"] == 70
    assert s["sampled_outside_scope_pct"] == 100.0
    assert s["estimated_outsiders_fleetwide"] == 10_000


def test_r4_summary_finding_at_index_0(fake_client, app_config):
    """findings[0] is the directional summary; per-outsider findings follow."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[100, 101, 102],
        total_agents=3,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_get("/api/3/assets/100", {"ip": "10.0.0.5", "hostName": "inside-1"})
    fake_client.set_get("/api/3/assets/101", {"ip": "192.168.1.5", "hostName": "outside-1"})
    fake_client.set_get("/api/3/assets/102", {"ip": "10.0.0.6", "hostName": "inside-2"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert len(rule.findings) == 2  # summary + 1 outsider
    assert "Sampled" in rule.findings[0].message
    assert "outside-1" in rule.findings[1].message
    assert all("inside" not in f.message for f in rule.findings[1:])


def test_r4_truncation_rollup(fake_client, app_config):
    """Outsiders > 500 → truncation rollup finding."""
    from rapid7_healthcheck.checks.asset_coverage import _PER_ITEM_FINDING_CAP
    n = _PER_ITEM_FINDING_CAP + 50  # 550
    sample_ids = list(range(n))
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=sample_ids,
        total_agents=n,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    for aid in sample_ids:
        fake_client.set_get(f"/api/3/assets/{aid}", {"ip": "192.168.1.5", "hostName": f"h-{aid}"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    cfg = _r4_app_config(app_config, sample_size=n)
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    # 1 summary + 500 per-outsider + 1 rollup = 502
    assert len(rule.findings) == 1 + _PER_ITEM_FINDING_CAP + 1
    rollup = rule.findings[-1]
    assert "more asset(s)" in rollup.message
    assert rollup.details["remainder"] == 50


def test_r4_skipped_when_flag_off(fake_client, app_config):
    """flag_agent_only_assets defaults to False — rule must skip and not call client.get."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[1],
        total_agents=1,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])

    # Default app_config has flag off; do NOT call _r4_app_config.
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "skipped"


def test_r4_skipped_when_agents_unavailable(fake_client, app_config):
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[],
        total_agents=0,
        agents_unavailable=True,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "skipped"
    assert "agents endpoint unavailable" in rule.rule_name


def test_r4_unavailable_endpoint_detected_via_sample_call(fake_client, app_config):
    """Regression: ensure is_agents_unavailable() guard fires AFTER the
    sampled accessor primes the flag. Previously the guard ran before
    priming, so a 404 console would silently report "No Insight Agents
    deployed" instead of the correct skip."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[],
        total_agents=0,
        agents_unavailable=False,            # initial state — like a real fresh snapshot
        flip_unavailable_on_sample_call=True,  # accessor flips it (simulates 404)
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "skipped"
    assert "agents endpoint unavailable" in rule.rule_name
    # NOT the empty-fleet pass path:
    assert not any("No Insight Agents" in f.message for f in rule.findings)


def test_r4_empty_fleet_pass(fake_client, app_config):
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[],
        total_agents=0,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "pass"
    assert rule.summary["total_agents"] == 0
    assert rule.summary["agent_only_count_sampled"] == 0
    assert any("No Insight Agents" in f.message for f in rule.findings)


def test_r4_rule_id_preserved(fake_client, app_config):
    """Drift guard: rule_id must remain stable for delta-blob signature continuity."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[1],
        total_agents=1,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_get("/api/3/assets/1", {"ip": "10.0.0.5", "hostName": "x"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.rule_id == "op.asset_coverage.agent_only_assets"


def test_r4_error_when_snapshot_none(fake_client, app_config):
    """flag on + snapshot=None → error status with a clear summary message."""
    cfg = _r4_app_config(app_config)
    # Wire the always-runs prerequisites so the call doesn't blow up earlier.
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=None)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "error"
    assert rule.summary["agent_only_count_sampled"] == 0
    assert rule.summary.get("error") == "snapshot required"


def test_r4_error_when_targets_none(fake_client, app_config):
    """flag on + included_targets=None → indeterminate, error status."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[1],
        total_agents=1,
        included_targets=None,  # explicit
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "error"
    assert rule.summary["agent_only_count_sampled"] == 0
    assert rule.summary.get("error") == "no targets"


def test_r4_all_in_scope_pass(fake_client, app_config):
    """Sample fully in-scope → status pass, summary finding info-severity, no per-outsider findings."""
    snap = _FakeSnapshot(
        asset_groups=[],
        sample_ids=[100, 101, 102],
        total_agents=300,
        included_targets=_r4_targets("10.0.0.0/24"),
    )
    fake_client.set_get("/api/3/assets/100", {"ip": "10.0.0.5", "hostName": "h-100"})
    fake_client.set_get("/api/3/assets/101", {"ip": "10.0.0.6", "hostName": "h-101"})
    fake_client.set_get("/api/3/assets/102", {"ip": "10.0.0.7", "hostName": "h-102"})
    fake_client.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fake_client, _r4_app_config(app_config), snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")

    assert rule.status == "pass"
    assert rule.summary["agent_only_count_sampled"] == 0
    assert rule.summary["sampled_fetched"] == 3
    assert rule.summary["sampled_outside_scope_pct"] == 0.0
    assert rule.summary["estimated_outsiders_fleetwide"] == 0
    # Only the directional summary finding; no per-outsider findings.
    assert len(rule.findings) == 1
    assert rule.findings[0].severity == "info"
    assert "Sampled" in rule.findings[0].message


# ----- integration: shape, rollup, backwards-compat -----

def test_run_returns_four_rule_results(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert len(result.rule_results) == 4
    rule_ids = [r.rule_id for r in result.rule_results]
    assert rule_ids == [
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
    ]


def test_check_status_rolls_up_to_warn_when_any_rule_warns(fake_client, app_config):
    """A non-empty stale_assets rule (warn severity) drives the check to warn."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"stale-{i}", i) for i in range(3)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        # Stale rule's filter uses stale_asset_days (30 in default fixture);
        # never-scanned uses never_scanned_days (90). Yield assets only for stale.
        if "'value': 30" in text or '"value": 30' in text:
            yield from stale
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    assert result.status == "warn"


def test_check_status_pass_when_all_rules_pass(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert result.status == "pass"


def test_optional_snapshot_kwarg_is_backwards_compatible(fake_client, app_config):
    """Calling without snapshot still works for client-only rules; snapshot-needing rules return error."""
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    # Client-only rules complete normally
    assert _rule(result, "op.asset_coverage.stale_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.never_scanned_assets").status == "pass"
    # Snapshot-dependent rules error cleanly (don't crash)
    assert _rule(result, "op.asset_coverage.dead_asset_groups").status == "error"
    # R4 is skipped because flag_agent_only_assets=False by default — toggle check fires before snapshot check
    assert _rule(result, "op.asset_coverage.agent_only_assets").status == "skipped"


def test_per_rule_failure_isolated_other_rules_still_run(fake_client, app_config):
    """If one asset-coverage rule's API call raises, the other three rules
    still produce output. Mirrors the data_quality 0.2.8 regression test.

    Triggers the failure on _stale_assets's paginate_post via the rule's
    filter (last-scan-date is-earlier-than stale_asset_days). The
    stale_asset_days value is derived from app_config at runtime so the
    test stays correct if the fixture default ever changes.
    """
    stale_days = app_config.thresholds.asset_coverage.stale_asset_days

    def paginate_post(path, json_body, params=None, page_size=500):
        if path == "/api/3/assets/search":
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
        yield from []

    fake_client.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    # All 4 rules produce a RuleResult (the failing one as 'error', the
    # others normally).
    assert len(result.rule_results) == 4
    stale = _rule(result, "op.asset_coverage.stale_assets")
    assert stale.status == "error"
    assert "Read timed out" in (stale.error or "")

    # Other rules still ran — exact status depends on fake_client setup, but
    # they must not be 'error' from the same exception.
    for rid in (
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
    ):
        rr = _rule(result, rid)
        assert rr.status in ("pass", "warn", "fail", "skipped"), \
            f"Rule {rid} should not be 'error' from another rule's failure; got {rr.status}"


def test_rule_identity_matches_method_constants(fake_client, app_config):
    """Drift guard: the rule_id strings duplicated in run()'s safe_run()
    wrappers must match the rule_id each rule method emits internally.

    Without this guard, if a rule method's rule_id changes but the
    wrapper's stays the same, the report renders the wrapper's stale
    identity for the success path and the method's new identity for the
    error path — confusing operators and breaking delta-blob signatures.
    """
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)

    expected_rule_ids = {
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.agent_only_assets",
    }
    actual_rule_ids = {rr.rule_id for rr in result.rule_results}
    assert actual_rule_ids == expected_rule_ids
