from __future__ import annotations

from rapid7_healthcheck.audit.rules.single_engine_overload import SingleEngineOverloadRule


def _site(site_id, name, engine_id): return {"id": site_id, "name": name, "scanEngine": engine_id}


def test_pass_when_each_engine_serves_one_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 200)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}, {"id": 200, "name": "E2"}])
    fake_snapshot.set_site_asset_count(1, 5000)
    fake_snapshot.set_site_asset_count(2, 5000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_finding_when_one_engine_exceeds_threshold_across_sites(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 4000)
    fake_snapshot.set_site_asset_count(2, 3000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500,
                                        {"asset_count_threshold": 5000})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["total_assets"] == 7000
    assert sorted(r.findings[0].details["sites"]) == [1, 2]
    # engine_name alongside engine_id so UI renderers can show name first
    assert r.findings[0].details["engine_id"] == 100
    assert r.findings[0].details["engine_name"] == "E1"


def test_threshold_default_5000(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 2000)
    fake_snapshot.set_site_asset_count(2, 2000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_engine_with_one_site_never_flagged(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 100000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500,
                                        {"asset_count_threshold": 100})
    assert r.status == "pass"
