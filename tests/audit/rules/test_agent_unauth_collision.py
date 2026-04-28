from __future__ import annotations

from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
    AgentUnauthCollisionRule,
)


def _site(site_id, tpl_id, name="S"):
    return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_site_has_credentials(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_pass_when_template_has_no_vuln_checks(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-disc")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_fail_when_unauth_site_has_agent_assets(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdLinux")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}, {"id": 101}, {"id": 102}], total=3)
    fake_snapshot.set_asset_history(100, [{"type": "AGENT-IMPORT", "date": "..."}])
    fake_snapshot.set_asset_history(101, [{"type": "AGENT-IMPORT", "date": "..."}])
    fake_snapshot.set_asset_history(102, [{"type": "SCAN", "date": "..."}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    f = r.findings[0]
    assert "ProdLinux" in f.message
    assert f.details["agent_count"] == 2


def test_pass_when_no_agent_assets(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}], total=1)
    fake_snapshot.set_asset_history(100, [{"type": "SCAN"}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_sampling_recorded(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}], total=4200)
    fake_snapshot.set_asset_history(100, [{"type": "AGENT-IMPORT"}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.sampled
    assert "of 4200" in (r.sample_info or "")
