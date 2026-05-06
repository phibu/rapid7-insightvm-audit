from __future__ import annotations

from rapid7_healthcheck.audit.rules.local_engine_production_scope import (
    LocalEngineProductionScopeRule,
)


def _site(site_id, name, engine_id):
    return {"id": site_id, "name": name, "scanEngine": engine_id}


def test_pass_when_no_local_engine(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "remote-eng-001", "address": "scan-eng.acme.com"},
    ])
    fake_snapshot.set_site_asset_count(1, 50000)
    r = LocalEngineProductionScopeRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.summary["engines_examined"] == 0


def test_pass_when_local_engine_below_threshold(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "Local scan engine", "address": "localhost"},
    ])
    fake_snapshot.set_site_asset_count(1, 250)
    r = LocalEngineProductionScopeRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.summary["engines_examined"] == 1
    assert r.summary["engines_flagged"] == 0


def test_warn_when_local_engine_carries_production_scope_by_address(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Big", 100), _site(2, "Big2", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "renamed-by-operator", "address": "127.0.0.1"},
    ])
    fake_snapshot.set_site_asset_count(1, 800)
    fake_snapshot.set_site_asset_count(2, 600)
    r = LocalEngineProductionScopeRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["total_assets"] == 1400
    assert r.summary["sites_examined"] == 2


def test_warn_when_local_engine_carries_production_scope_by_default_name(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Big", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "Local scan engine", "address": "scan-eng.example.com"},
    ])
    fake_snapshot.set_site_asset_count(1, 1500)
    r = LocalEngineProductionScopeRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_additional_local_names_override(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Big", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "console-host-engine", "address": "console.example.com"},
    ])
    fake_snapshot.set_site_asset_count(1, 1500)
    r = LocalEngineProductionScopeRule().run(
        fake_snapshot, "warn", False, 500,
        {"additional_local_names": ["console-host-engine"]},
    )
    assert r.status == "warn"


def test_threshold_override(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100)])
    fake_snapshot.set_scan_engines([
        {"id": 100, "name": "Local scan engine", "address": "localhost"},
    ])
    fake_snapshot.set_site_asset_count(1, 800)
    r_default = LocalEngineProductionScopeRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    assert r_default.status == "pass"  # 800 <= 1000 default
    r_strict = LocalEngineProductionScopeRule().run(
        fake_snapshot, "warn", False, 500, {"asset_count_threshold": 500},
    )
    assert r_strict.status == "warn"
