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


# ----- R4: agent_only_assets -----

def _enable_r4_via_full_scan(app_config):
    """Helper: flip the toggle on AND set audit.full_scan=True."""
    from dataclasses import replace
    return replace(
        app_config,
        audit=replace(app_config.audit, full_scan=True),
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_agent_only_assets=True,
            ),
        ),
    )


def test_r4_skipped_by_default(fake_client, app_config):
    """Default config has flag_agent_only_assets=false — rule must be skipped."""
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_skipped_when_full_scan_off_even_if_toggle_on(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        audit=replace(app_config.audit, full_scan=False),
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_agent_only_assets=True,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[], agent_asset_ids={1, 2, 3})
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_skipped_when_agents_endpoint_unavailable(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[], agents_unavailable=True)
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_pass_when_no_agents(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids=set(),
        included_targets=IncludedTargets(),
    )
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "pass"
    assert rule.summary["agent_only_count"] == 0


def test_r4_pass_when_all_agents_inside_targets(fake_client, app_config):
    from ipaddress import ip_network
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    cfg = _enable_r4_via_full_scan(app_config)

    asset_details = {
        100: {"id": 100, "ip": "10.0.0.5", "hostName": "agent-a"},
        101: {"id": 101, "ip": "10.0.0.6", "hostName": "agent-b"},
    }

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def get(path, params=None):
        if path.startswith("/api/3/assets/"):
            aid = int(path.split("/")[-1])
            return asset_details[aid]
        raise AssertionError(f"unexpected GET: {path}")

    fc.get = get  # type: ignore[assignment]
    fc.set_paginate_post("/api/3/assets/search", [])

    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids={100, 101},
        included_targets=IncludedTargets(networks=[ip_network("10.0.0.0/24")], literals=set()),
    )
    result = AssetCoverageCheck().run(fc, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "pass"
    assert rule.summary["agent_only_count"] == 0


def test_r4_warn_when_agents_outside_targets(fake_client, app_config):
    from ipaddress import ip_network
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    cfg = _enable_r4_via_full_scan(app_config)

    asset_details = {
        200: {"id": 200, "ip": "172.16.0.1", "hostName": "outside-1"},
        201: {"id": 201, "ip": "172.16.0.2", "hostName": "outside-2"},
        202: {"id": 202, "ip": "10.0.0.5", "hostName": "inside"},
    }

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def get(path, params=None):
        if path.startswith("/api/3/assets/"):
            aid = int(path.split("/")[-1])
            return asset_details[aid]
        raise AssertionError(f"unexpected GET: {path}")

    fc.get = get  # type: ignore[assignment]
    fc.set_paginate_post("/api/3/assets/search", [])

    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids={200, 201, 202},
        included_targets=IncludedTargets(networks=[ip_network("10.0.0.0/24")], literals=set()),
    )
    result = AssetCoverageCheck().run(fc, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "warn"
    assert rule.summary["agent_only_count"] == 2
    # One Finding per agent-only asset → Findings column reflects the true count.
    assert len(rule.findings) == 2
    hostnames = {f.details["hostname"] for f in rule.findings}
    assert hostnames == {"outside-1", "outside-2"}


def test_r4_errors_when_snapshot_missing(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg)  # no snapshot
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "error"


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

    Triggers the failure on _stale_assets's paginate_post (the rule's
    filter uses {"value": stale_asset_days} == 30 in the default fixture).
    """
    from rapid7_healthcheck.client import Rapid7ClientError

    def paginate_post(path, json_body, params=None, page_size=500):
        if path == "/api/3/assets/search":
            # Match _stale_assets specifically: single filter, last-scan-date
            # is-earlier-than 30 (the default stale_asset_days).
            filters = json_body.get("filters", [])
            if (
                len(filters) == 1
                and filters[0].get("field") == "last-scan-date"
                and filters[0].get("operator") == "is-earlier-than"
                and filters[0].get("value") == 30
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
