from __future__ import annotations

import re

from rapid7_healthcheck.diagrams import (
    EngineNode,
    TopologyData,
    build_topology,
    build_topology_svg,
)


class _FakeSnapshot:
    """Minimal snapshot stand-in: returns canned lists, records nothing else.

    build_topology reads sites_by_engine(), scan_engines(), scan_engine_pools(),
    and site_asset_count() -- all already cached in a real run, so no new API.
    The base site→engine grouping comes from the snapshot's SitePairing
    accessor (CONTEXT.md "SitePairing"), not a re-derivation here.
    """

    def __init__(self, *, sites, engines, pools, asset_counts):
        self._sites = sites
        self._engines = engines
        self._pools = pools
        self._asset_counts = asset_counts
        self.asset_count_calls = 0

    def sites(self):
        return self._sites

    def sites_by_engine(self):
        from rapid7_healthcheck.audit.snapshot import SitePairing
        by_engine: dict[int, list[int]] = {}
        orphans: list[int] = []
        for site in self._sites:
            target = site.get("scanEngine")
            if not target:
                orphans.append(site["id"])
                continue
            by_engine.setdefault(target, []).append(site["id"])
        return SitePairing(by_engine=by_engine, orphan_site_ids=orphans)

    def scan_engines(self):
        return self._engines

    def scan_engine_pools(self):
        return self._pools

    def site_asset_count(self, site_id):
        self.asset_count_calls += 1
        return self._asset_counts.get(site_id, 0)


# --- build_topology ---------------------------------------------------------


def test_build_topology_direct_pairing_counts_sites_and_load():
    snap = _FakeSnapshot(
        sites=[
            {"id": 1, "scanEngine": 10},
            {"id": 2, "scanEngine": 10},
            {"id": 3, "scanEngine": 11},
        ],
        engines=[
            {"id": 10, "name": "Engine A"},
            {"id": 11, "name": "Engine B"},
        ],
        pools=[],
        asset_counts={1: 4000, 2: 5000, 3: 1000},
    )
    topo = build_topology(snap)
    by_name = {e.name: e for e in topo.engines}
    assert by_name["Engine A"].site_count == 2
    assert by_name["Engine A"].asset_load == 9000
    assert by_name["Engine B"].site_count == 1
    assert by_name["Engine B"].asset_load == 1000


def test_build_topology_orphan_sites_counted():
    snap = _FakeSnapshot(
        sites=[
            {"id": 1, "scanEngine": 10},
            {"id": 2},               # no scanEngine -> orphan
            {"id": 3, "scanEngine": None},  # explicit None -> orphan
        ],
        engines=[{"id": 10, "name": "Engine A"}],
        pools=[],
        asset_counts={1: 100},
    )
    topo = build_topology(snap)
    assert topo.orphan_site_count == 2


def test_build_topology_unpaired_engine_has_no_sites_and_no_pool():
    snap = _FakeSnapshot(
        sites=[{"id": 1, "scanEngine": 10}],
        engines=[
            {"id": 10, "name": "Engine A"},
            {"id": 11, "name": "Engine B"},  # no sites, no pool -> unpaired
        ],
        pools=[],
        asset_counts={1: 100},
    )
    topo = build_topology(snap)
    assert "Engine B" in topo.unpaired_engines
    assert "Engine A" not in topo.unpaired_engines


def test_build_topology_engine_in_pool_with_sites_is_not_unpaired():
    # Engine B has no DIRECT sites but is a pool member; the pool is paired
    # (a site points at the pool). B is paired-via-pool, not unpaired.
    snap = _FakeSnapshot(
        sites=[{"id": 1, "scanEngine": 99}],  # 99 = the pool id
        engines=[
            {"id": 10, "name": "Engine A"},
            {"id": 11, "name": "Engine B"},
        ],
        pools=[{"id": 99, "name": "Pool Prod", "engines": [11]}],
        asset_counts={1: 100},
    )
    topo = build_topology(snap)
    assert "Engine B" not in topo.unpaired_engines


def test_build_topology_pool_membership_recorded():
    snap = _FakeSnapshot(
        sites=[{"id": 1, "scanEngine": 10}],
        engines=[{"id": 10, "name": "Engine A"}, {"id": 11, "name": "Engine B"}],
        pools=[{"id": 99, "name": "Pool Prod", "engines": [11]}],
        asset_counts={1: 100},
    )
    topo = build_topology(snap)
    by_name = {e.name: e for e in topo.engines}
    assert by_name["Engine B"].pool_name == "Pool Prod"
    assert by_name["Engine A"].pool_name is None


def test_build_topology_overloaded_flag_uses_threshold():
    snap = _FakeSnapshot(
        sites=[
            {"id": 1, "scanEngine": 10},
            {"id": 2, "scanEngine": 10},
        ],
        engines=[{"id": 10, "name": "Engine A"}],
        pools=[],
        asset_counts={1: 6000, 2: 6000},  # 12000 total, >2 sites
    )
    topo = build_topology(snap, overload_threshold=5000)
    assert topo.engines[0].overloaded is True


def test_build_topology_returns_none_when_no_engines():
    snap = _FakeSnapshot(sites=[], engines=[], pools=[], asset_counts={})
    assert build_topology(snap) is None


# --- build_topology_svg -----------------------------------------------------


def _topo() -> TopologyData:
    return TopologyData(
        engines=[
            EngineNode(engine_id=10, name="Engine A", pool_name="Pool Prod",
                       site_count=12, asset_load=8200, overloaded=False),
            EngineNode(engine_id=11, name="Engine C", pool_name=None,
                       site_count=41, asset_load=22000, overloaded=True),
        ],
        orphan_site_count=3,
        unpaired_engines=["Engine D"],
        total_paired_sites=53,
    )


def test_topology_svg_is_inline_and_themed():
    svg = build_topology_svg(_topo())
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    assert "<script" not in svg and "src=" not in svg
    assert not re.search(r'(fill|stroke)="(#|rgb)', svg)
    assert 'class="dg-' in svg


def test_topology_svg_shows_engine_names_and_loads():
    svg = build_topology_svg(_topo())
    assert "Engine A" in svg
    assert "Engine C" in svg
    assert "8,200" in svg
    assert "22,000" in svg


def test_topology_svg_flags_overloaded_engine():
    svg = build_topology_svg(_topo())
    # The overloaded engine renders with the fail class; healthy with neutral.
    assert "dg-engine-fail" in svg


def test_topology_svg_surfaces_orphan_and_unpaired():
    svg = build_topology_svg(_topo())
    assert "orphan" in svg.lower()
    assert "3" in svg
    assert "unpaired" in svg.lower()
    assert "Engine D" in svg


def test_topology_svg_groups_pool_members():
    svg = build_topology_svg(_topo())
    assert "Pool Prod" in svg


# --- report integration -----------------------------------------------------


def _ctx_with_topology(topology):
    from datetime import datetime, timezone

    from rapid7_healthcheck.checks import CheckResult
    from rapid7_healthcheck.report import ReportContext

    return ReportContext(
        title="T",
        generated_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
        base_url_host="h",
        tool_version="0.1.0",
        config_path="c.yaml",
        results=[CheckResult(name="Scan Engines", description="x", status="warn")],
        topology=topology,
    )


def test_report_renders_topology_figure():
    # Location (the Diagrams view) is asserted in test_report_view_switch;
    # this just confirms the figure renders end-to-end through the report.
    from rapid7_healthcheck.report import render_report

    html = render_report(_ctx_with_topology(_topo()))
    assert "Scan engine topology" in html  # the svg aria-label
    assert ".dg-engine-fail" in html       # topology css present


def test_report_omits_topology_when_absent():
    from rapid7_healthcheck.report import render_report

    html = render_report(_ctx_with_topology(None))
    assert "Scan engine topology" not in html
