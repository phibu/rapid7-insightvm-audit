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
    # never_scanned is skipped (off); stale, unauth_only, and no_services_detected still run.
    assert len(paginate_post_calls) == 3
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

    assert len(captured_filters) == 4  # stale + never-scanned + unauth_only + no_services_detected
    # The regression guards stale and never_scanned: those two send a
    # single-filter body keyed on last-scan-date. They must use is-earlier-than;
    # neither may use is-empty. Other rules' bodies (R2's vulnerability-assessed,
    # R3's two-filter service-count + is-within-the-last) are intentionally
    # excluded from this guard — they use different fields/operators by design.
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


# ----- R2: unauth_only_assets -----

def test_r2_unauth_only_assets_pass_when_empty(fake_client, app_config):
    """No assets match the vulnerability-assessed=false filter → pass."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []  # empty for every call

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "pass"
    assert rule.summary["unauth_only_count"] == 0


def test_r2_unauth_only_assets_fail_with_examples(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    unauth = [_asset(f"unauth-{i}", i) for i in range(15)]

    def paginate_post(path, json_body, params=None, page_size=500):
        # R2 is the only rule whose filter is vulnerability-assessed=False.
        text = str(json_body)
        if "vulnerability-assessed" in text:
            yield from unauth
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "fail"
    assert rule.summary["unauth_only_count"] == 15
    # One Finding per unauth-only asset → Findings column reflects the true count.
    assert len(rule.findings) == 15
    for f in rule.findings:
        assert f.severity == "fail"
        assert "unauthenticated-only" in f.message.lower()


def test_r2_unauth_only_assets_uses_correct_filter_body(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    AssetCoverageCheck().run(fc, app_config, snapshot=snap)

    unauth_bodies = [b for b in captured if any(
        f.get("field") == "vulnerability-assessed" for f in b.get("filters", [])
    )]
    assert len(unauth_bodies) == 1
    body = unauth_bodies[0]
    assert body["match"] == "all"
    f = body["filters"][0]
    assert f == {"field": "vulnerability-assessed", "operator": "is", "value": False}


def test_r2_unauth_only_assets_handles_400_filter_unsupported(fake_client, app_config):
    """If the console rejects the filter (older API version), report as error
    via status_code branching — never substring-match the message."""
    from tests.conftest import FakeRapid7Client
    from rapid7_healthcheck.client import Rapid7ClientError
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "vulnerability-assessed" in text:
            err = Rapid7ClientError("400 Bad Request: filter field not supported")
            err.status_code = 400
            raise err
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "error"
    # Other rules still completed
    assert _rule(result, "op.asset_coverage.stale_assets").status in ("pass", "warn", "fail")


def test_r2_unauth_only_assets_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_unauth_only_assets=False,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "skipped"


# ----- R3: no_services_detected -----

def test_r3_no_services_detected_pass_when_empty(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "pass"
    assert rule.summary["no_services_count"] == 0


def test_r3_no_services_detected_warn_with_results(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    silent_assets = [_asset(f"silent-{i}", i) for i in range(7)]

    def paginate_post(path, json_body, params=None, page_size=500):
        # R3 is the rule whose body has BOTH service-count AND last-scan-date filters.
        fields = [f.get("field") for f in json_body.get("filters", [])]
        if "service-count" in fields and "last-scan-date" in fields:
            yield from silent_assets
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "warn"
    assert rule.summary["no_services_count"] == 7


def test_r3_no_services_detected_uses_two_filter_body(fake_client, app_config):
    """Body must combine service-count==0 AND last-scan-date is-within stale_asset_days."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    AssetCoverageCheck().run(fc, app_config, snapshot=snap)

    r3_bodies = [
        b for b in captured
        if {"service-count", "last-scan-date"} <= {f.get("field") for f in b.get("filters", [])}
    ]
    assert len(r3_bodies) == 1
    body = r3_bodies[0]
    assert body["match"] == "all"
    assert len(body["filters"]) == 2
    sc_filter = next(f for f in body["filters"] if f["field"] == "service-count")
    assert sc_filter == {"field": "service-count", "operator": "is", "value": 0}
    ls_filter = next(f for f in body["filters"] if f["field"] == "last-scan-date")
    assert ls_filter["operator"] == "is-within-the-last"
    # Default fixture has stale_asset_days=30
    assert ls_filter["value"] == app_config.thresholds.asset_coverage.stale_asset_days


def test_r3_no_services_detected_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_no_services_detected=False,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "skipped"


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

def test_run_returns_six_rule_results(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert len(result.rule_results) == 6
    rule_ids = [r.rule_id for r in result.rule_results]
    assert rule_ids == [
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.unauth_only_assets",
        "op.asset_coverage.no_services_detected",
        "op.asset_coverage.agent_only_assets",
    ]


def test_check_status_rolls_up_to_fail_when_any_rule_fails(fake_client, app_config):
    """One fail rule (R2 unauth_only) drives the check to fail."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        if "vulnerability-assessed" in str(json_body):
            yield from [_asset(f"unauth-{i}", i) for i in range(3)]
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    assert result.status == "fail"


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
    assert _rule(result, "op.asset_coverage.unauth_only_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.no_services_detected").status == "pass"
    # Snapshot-dependent rules error cleanly (don't crash)
    assert _rule(result, "op.asset_coverage.dead_asset_groups").status == "error"
    # R4 is skipped because flag_agent_only_assets=False by default — toggle check fires before snapshot check
    assert _rule(result, "op.asset_coverage.agent_only_assets").status == "skipped"
