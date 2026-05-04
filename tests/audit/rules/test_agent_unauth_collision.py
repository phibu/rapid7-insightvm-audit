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
    fake_snapshot.set_asset_sample(1, [
        {"id": 100, "history": [{"type": "AGENT-IMPORT", "date": "..."}]},
        {"id": 101, "history": [{"type": "AGENT-IMPORT", "date": "..."}]},
        {"id": 102, "history": [{"type": "SCAN", "date": "..."}]},
    ], total=3)
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
    fake_snapshot.set_asset_sample(1, [{"id": 100, "history": [{"type": "SCAN"}]}], total=1)
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_sampling_recorded(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100, "history": [{"type": "AGENT-IMPORT"}]}], total=4200)
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
    # asset 1: has cheap signal (agent.agentId present) — counted directly, no fallback
    # asset 2: no cheap signal — fallback reads inline history from the asset record
    fake_snapshot.set_asset_sample(1, [
        {"id": 1, "agent": {"agentId": "abc-123"}},
        {"id": 2, "history": [{"type": "AGENT-IMPORT"}]},
    ], total=2)

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    assert r.findings[0].details["agent_count"] == 2


def test_does_not_call_asset_history_endpoint(fake_snapshot):
    """The rule must read history from the inline asset record, never call the
    (nonexistent) GET /api/3/assets/{id}/history endpoint."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    # Two assets, both WITHOUT cheap agent signal:
    #   asset 10: inline history with AGENT-IMPORT → should be counted
    #   asset 11: inline history with only SCAN    → should NOT be counted
    fake_snapshot.set_asset_sample(1, [
        {"id": 10, "history": [{"type": "AGENT-IMPORT", "date": "2024-01-01"}]},
        {"id": 11, "history": [{"type": "SCAN", "date": "2024-01-01"}]},
    ], total=2)

    # Replace asset_history with a bomb — any call is a regression.
    def _boom(asset_id: int):
        raise AssertionError(
            f"rule called snapshot.asset_history({asset_id}) — "
            "GET /api/3/assets/{{id}}/history does not exist; fix regression"
        )
    fake_snapshot.asset_history = _boom

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    assert r.findings[0].details["agent_count"] == 1


def test_short_circuits_on_first_agent_match(fake_snapshot):
    """Site with 50 assets where only the 3rd is agent-managed. Rule must
    consume exactly 3 items from the iterator and then break."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])

    # Build a list of 50 assets where only the 3rd has an agent.
    assets = []
    for i in range(50):
        if i == 2:
            assets.append({"id": 100 + i, "agent": {"agentId": "abc"}})
        else:
            assets.append({"id": 100 + i})
    fake_snapshot.set_site_assets_iter(1, assets)
    fake_snapshot.set_site_asset_count(1, 50)

    # Wrap iter_site_assets to count how many items the RULE consumes.
    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    # Rule consumed assets 100, 101, 102 only (broke after finding agent on 102).
    assert consumed == [100, 101, 102]
    f = [f for f in r.findings if f.severity == "fail"][0]
    assert f.details["examined"] == 3
    assert f.details["short_circuited"] is True
