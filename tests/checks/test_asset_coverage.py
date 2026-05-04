from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck


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
        included_targets=None,
        full_scan: bool = False,
        sample_size: int = 500,
    ):
        self._sites = sites or []
        self._asset_groups = asset_groups or []
        self._agent_asset_ids = agent_asset_ids or set()
        self._agents_unavailable = agents_unavailable
        self._included_targets = included_targets
        self.full_scan = full_scan
        self.sample_size = sample_size

    def sites(self): return self._sites
    def asset_groups(self): return self._asset_groups
    def agent_asset_ids(self): return self._agent_asset_ids
    def is_agents_unavailable(self): return self._agents_unavailable
    def all_included_targets(self): return self._included_targets


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
    # Only the stale query should have run.
    assert len(paginate_post_calls) == 1
    # The never-scanned rule should be skipped.
    ns = _rule(result, "op.asset_coverage.never_scanned_assets")
    assert ns.status == "skipped"


def test_top_10_examples_in_finding_details(fake_client, app_config):
    """Stale path returns 25 assets — only first 10 surface as examples."""
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
    result = AssetCoverageCheck().run(fc, app_config)
    stale_finding = next(f for f in result.findings if "stale" in f.message.lower())
    assert stale_finding.details is not None
    examples = stale_finding.details["examples"]
    assert len(examples) == 10
    assert stale_finding.details["total"] == 25


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
    # Both must use is-earlier-than; neither may use is-empty.
    for f in captured_filters:
        ops = [filt["operator"] for filt in f["filters"]]
        assert "is-empty" not in ops, f"is-empty operator must not be used: {f}"
        assert all(op == "is-earlier-than" for op in ops), f"unexpected operator: {f}"
    # never_scanned filter uses 90 (default).
    never_scanned = [f for f in captured_filters if f["filters"][0]["value"] == 90]
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
    finding = rule.findings[0]
    examples = finding.details["examples"]
    assert len(examples) == 2
    names = {e["group_name"] for e in examples}
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
