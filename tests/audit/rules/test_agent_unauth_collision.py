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


def test_uses_cheap_agent_signal_when_available(fake_snapshot):
    """Assets with agent.agentId in their record must NOT trigger asset_history calls."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    # asset 1: has cheap signal (agent.agentId present)
    # asset 2: no cheap signal — falls back to asset_history
    fake_snapshot.set_asset_sample(1, [
        {"id": 1, "agent": {"agentId": "abc-123"}},
        {"id": 2},
    ], total=2)
    # Only asset 2 needs history; asset 1's cheap signal is True so it counts directly.
    fake_snapshot.set_asset_history(2, [{"type": "AGENT-IMPORT"}])

    history_calls: list[int] = []
    _orig_history = fake_snapshot.asset_history

    def _tracking_history(asset_id: int):
        history_calls.append(asset_id)
        return _orig_history(asset_id)

    fake_snapshot.asset_history = _tracking_history

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert history_calls == [2], (
        f"asset_history should only be called for assets without the cheap signal; "
        f"called for: {history_calls}"
    )
    assert r.status == "fail"
    assert r.findings[0].details["agent_count"] == 2
