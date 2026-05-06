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
    fake_snapshot.set_agents([{"id": 100, "agentId": "a"}, {"id": 101, "agentId": "b"}])
    fake_snapshot.set_site_asset_count(1, 3)
    fake_snapshot.set_site_assets_iter(1, [
        {"id": 100},
        {"id": 101},
        {"id": 102},
    ])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    f = r.findings[0]
    assert "ProdLinux" in f.message
    assert f.details["examined"] >= 1


def test_pass_when_no_agent_assets(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 999, "agentId": "z"}])
    fake_snapshot.set_site_asset_count(1, 1)
    fake_snapshot.set_site_assets_iter(1, [{"id": 100}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_sampling_recorded(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 100, "agentId": "a"}])
    fake_snapshot.set_site_asset_count(1, 4200)
    fake_snapshot.set_site_assets_iter(1, [{"id": 100}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.summary["per_site_cap"] == 500
    assert r.findings[0].details["total_assets"] == 4200


def test_skipped_when_agents_endpoint_unavailable(fake_snapshot):
    """Console without /api/3/agents → rule skips with an info finding rather
    than silently producing a clean pass."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([], unavailable=True)

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "skipped"
    assert any("agents" in f.message.lower() for f in r.findings)
    assert r.summary["agent_asset_ids"] == 0


def test_uses_agent_inventory_set(fake_snapshot):
    """First asset in site iteration matches the agent inventory by id → flagged
    after a single asset, no need to read history or full asset payloads."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 1, "agentId": "abc-123"}])
    fake_snapshot.set_site_asset_count(1, 2)
    fake_snapshot.set_site_assets_iter(1, [
        {"id": 1},
        {"id": 2},
    ])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    assert r.findings[0].details["examined"] == 1
    assert r.findings[0].details["short_circuited"] is True


def test_short_circuits_on_first_agent_match(fake_snapshot):
    """Site with 50 assets where only the 3rd is in the agent inventory.
    Rule must consume exactly 3 items from the iterator and then break."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 102, "agentId": "abc"}])

    assets = [{"id": 100 + i} for i in range(50)]
    fake_snapshot.set_site_assets_iter(1, assets)
    fake_snapshot.set_site_asset_count(1, 50)

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    assert consumed == [100, 101, 102]
    f = [f for f in r.findings if f.severity == "fail"][0]
    assert f.details["examined"] == 3
    assert f.details["short_circuited"] is True


def test_per_site_cap_no_agent_truncates(fake_snapshot):
    """Site with 1000 assets, none in agent inventory, sample_size=100. Rule
    consumes exactly 100, no per-site fail finding, site appears in the
    aggregate info finding's truncated_sites list."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 99999, "agentId": "elsewhere"}])
    fake_snapshot.set_site_asset_count(1, 1000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert len(consumed) == 100
    fail_findings = [f for f in r.findings if f.severity == "fail"]
    assert fail_findings == []
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert info_findings[0].details["truncated_site_count"] == 1
    assert info_findings[0].details["truncated_sites"][0]["site_id"] == 1
    assert r.summary["sites_truncated"] == 1
    assert r.summary["per_site_cap"] == 100


def test_full_scan_disables_cap(fake_snapshot):
    """full_scan=True → no cap, all 1000 assets consumed, no truncation."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 99999, "agentId": "elsewhere"}])
    fake_snapshot.set_site_asset_count(1, 1000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", True, 100, {})

    assert len(consumed) == 1000
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert info_findings == []
    assert r.summary["sites_truncated"] == 0
    assert r.summary["per_site_cap"] is None


def test_aggregate_info_finding_caps_at_20(fake_snapshot):
    """25 truncated sites → info finding's truncated_sites list is capped at 20,
    but the count in the message reflects the true total."""
    sites = [_site(i, "tpl-vuln", f"Site{i}") for i in range(1, 26)]
    fake_snapshot.set_sites(sites)
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 99999, "agentId": "elsewhere"}])
    for s in sites:
        sid = s["id"]
        fake_snapshot.set_site_credentials(sid, [])
        fake_snapshot.set_site_asset_count(sid, 200)
        fake_snapshot.set_site_assets_iter(sid, [{"id": i} for i in range(200)])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert info_findings[0].details["truncated_site_count"] == 25
    assert len(info_findings[0].details["truncated_sites"]) == 20
    assert "25 sites" in info_findings[0].message


def test_truncated_aggregate_does_not_lift_status(fake_snapshot):
    """Only truncated sites, no fail findings → status is 'pass', not 'info'."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 99999, "agentId": "elsewhere"}])
    fake_snapshot.set_site_asset_count(1, 1000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert r.status == "pass"


def test_short_circuit_in_full_scan_mode(fake_snapshot):
    """full_scan=True still short-circuits on first agent — pagination consumed
    exactly 1 item even with 5000 total assets."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Huge")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 0, "agentId": "yes"}])
    fake_snapshot.set_site_asset_count(1, 5000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(5000)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", True, 100, {})

    assert consumed == [0]
    assert r.status == "fail"


def test_cap_and_short_circuit_interact_correctly(fake_snapshot):
    """sample_size=100, agent on the 50th asset → consumed=50, site flagged
    (short-circuit wins over cap)."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Mid")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 49, "agentId": "found"}])
    fake_snapshot.set_site_asset_count(1, 500)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(500)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert len(consumed) == 50
    assert r.status == "fail"
    fail_findings = [f for f in r.findings if f.severity == "fail"]
    assert fail_findings[0].details["examined"] == 50


def test_regression_flags_when_site_payload_lacks_agent_and_history_fields(fake_snapshot):
    """Regression test for the silent-0-findings bug that motivated the
    /api/3/agents-driven refactor.

    Site-asset listings (/api/3/sites/{id}/assets) frequently OMIT the `agent`
    block and the `history` array — the fields are reliably populated only on
    /api/3/assets/{id} and /api/3/agents. The pre-refactor rule detected agent
    presence inline from the site-asset payload and silently produced 0
    findings on real consoles. This test asserts the rule still flags the site
    when those inline signals are absent, by relying on the agent inventory
    set instead. DO NOT 'simplify' detection back to inline asset fields.
    """
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Prod")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([{"id": 555, "agentId": "real"}])
    fake_snapshot.set_site_asset_count(1, 1)
    # Asset payload as it commonly looks on the site-asset listing in the wild:
    # has id + hostName, no `agent` block, no `history` array.
    fake_snapshot.set_site_assets_iter(1, [
        {"id": 555, "hostName": "host-555.example.com", "ip": "10.0.0.5"},
    ])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"


def test_agent_id_via_links_href(fake_snapshot):
    """Agent payload without top-level `id` but with a `links` entry pointing
    at /api/3/assets/{id} — the snapshot accessor must extract the id."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Linked")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_agents([
        {"agentId": "x", "links": [{"rel": "Asset", "href": "/api/3/assets/777"}]},
    ])
    fake_snapshot.set_site_asset_count(1, 2)
    fake_snapshot.set_site_assets_iter(1, [{"id": 777}, {"id": 778}])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert r.findings[0].details["examined"] == 1


def test_oversize_inventory_skips_with_default_cap():
    """When agent_count exceeds the default 50000 cap, rule skips."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def __init__(self):
            self.agent_asset_ids_called = False

        def is_agents_unavailable(self):
            return False

        def agent_count(self):
            return 60000

        def agent_asset_ids(self):
            self.agent_asset_ids_called = True
            return set()

        def sites(self):  # pragma: no cover - main loop must not run
            raise AssertionError("sites() should not be called when oversize")

    snap = _FakeSnapshot()
    rule_config: dict = {}
    result = AgentUnauthCollisionRule().run(
        snap, severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "info"
    assert finding.details["inventory_oversize"] is True
    assert finding.details["agent_count"] == 60000
    assert finding.details["max_agents_cap"] == 50000
    assert "max_agents" in finding.message
    assert "Security Console" in finding.message
    assert snap.agent_asset_ids_called is False
    assert result.summary["agent_count"] == 60000
    assert result.summary["max_agents_cap"] == 50000


def test_oversize_inventory_respects_explicit_max_agents_knob():
    """rule_config.knobs.max_agents overrides the default."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 5000
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = {"max_agents": 1000}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert result.findings[0].details["max_agents_cap"] == 1000


def test_inventory_at_cap_runs_strict_greater_than():
    """Boundary: agent_count == max_agents runs the main loop (strict >)."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 50000  # exactly equal to cap
        def agent_asset_ids(self): return set()
        def sites(self):
            sites_called.append(True)
            return []

    rule_config = {"max_agents": 50000}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert sites_called == [True]
    assert result.status == "pass"


def test_max_agents_zero_always_skips():
    """Sentinel: max_agents=0 means any non-empty fleet skips."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 1
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = {"max_agents": 0}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    assert result.findings[0].details["inventory_oversize"] is True


def test_max_agents_zero_with_empty_fleet_runs():
    """Edge case: max_agents=0 AND agent_count=0 means strict 0 > 0 is False."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 0
        def agent_asset_ids(self): return set()
        def sites(self):
            sites_called.append(True)
            return []

    rule_config = {"max_agents": 0}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert sites_called == [True]
    assert result.status == "pass"


def test_404_path_wins_over_oversize_path():
    """When agents endpoint is 404, the existing 404 finding fires
    regardless of agent_count / max_agents."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    class _FakeSnapshot:
        def is_agents_unavailable(self): return True
        def agent_count(self): return 999999
        def agent_asset_ids(self): return set()
        def sites(self): raise AssertionError("should not run")

    rule_config = {"max_agents": 100}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert result.status == "skipped"
    finding = result.findings[0]
    assert finding.details.get("agents_endpoint_unavailable") is True
    assert finding.details.get("inventory_oversize") is None


def test_below_cap_runs_main_loop_unchanged():
    """Regression: when below the cap, behavior matches pre-change baseline."""
    from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
        AgentUnauthCollisionRule,
    )

    sites_called = []

    class _FakeSnapshot:
        def is_agents_unavailable(self): return False
        def agent_count(self): return 100
        def agent_asset_ids(self): return set()
        def sites(self):
            sites_called.append(True)
            return []

    rule_config: dict = {}
    result = AgentUnauthCollisionRule().run(
        _FakeSnapshot(), severity="fail", full_scan=False, sample_size=100,
        rule_config=rule_config,
    )

    assert sites_called == [True]
    assert result.status == "pass"
    assert result.findings == []
