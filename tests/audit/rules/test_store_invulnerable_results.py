from __future__ import annotations

from rapid7_healthcheck.audit.rules.store_invulnerable_results import StoreInvulnerableResultsRule


def _site(site_id, name, tpl_id): return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_setting_disabled(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "T",
                                               "enableScanLog": False})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_finding_when_setting_enabled_via_enable_scan_log(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "enableScanLog": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "info"
    assert "Bloated" in r.findings[0].message


def test_finding_when_severity_overridden_to_warn(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "enableScanLog": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_alternate_field_name(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "storeInvulnerableResults": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1


def test_diagnostic_when_no_known_field_present(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Foo"})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert any("could not locate" in f.message.lower() for f in r.findings)
