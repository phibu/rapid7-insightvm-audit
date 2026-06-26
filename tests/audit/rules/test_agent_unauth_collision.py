from __future__ import annotations

from rapid7_healthcheck.audit.rules.agent_unauth_collision import AgentUnauthCollisionRule
from tests.audit.conftest import FakeSnapshot


def _vuln_template():
    return {"id": "tpl-vuln", "name": "Full audit", "vulnerabilityEnabled": True}


def _make_snapshot(*, sites, templates, creds, agent_site_name="Rapid7 Insight Agents", agent_site_id=9):
    snap = FakeSnapshot()
    snap.set_sites(sites)
    for tid, tpl in templates.items():
        snap.set_scan_template(tid, tpl)
    for sid, c in creds.items():
        snap.set_site_credentials(sid, c)
    if agent_site_id is not None:
        snap.set_agent_site_id(agent_site_name, agent_site_id)
    return snap


def test_no_agent_site_is_info_pass():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
        agent_site_id=None,  # no agent site registered
    )
    snap.set_shared_credentials([])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "Rapid7 Insight Agents" in result.findings[0].message


def test_unauth_candidate_overlapping_agent_site_is_flagged():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},  # no creds -> unauthenticated
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 4})  # site 1 overlaps agent site by 4 assets
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "fail"
    fails = [f for f in result.findings if f.severity == "fail"]
    assert len(fails) == 1
    assert "Prod" in fails[0].message
    assert "4" in fails[0].message
    assert fails[0].details["overlap_count"] == 4
    assert fails[0].details["site_id"] == 1
    assert fails[0].details["agent_site_id"] == 9


def test_unauth_candidate_no_overlap_is_info_pass():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 0})
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert all(f.severity == "info" for f in result.findings)


def test_credentialed_site_is_not_a_candidate():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: [{"enabled": True}]},  # has a credential -> authenticated -> not a candidate
    )
    snap.set_shared_credentials([])
    # No overlaps registered; site 1 must never be queried.
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert result.summary["candidates_examined"] == 0


def test_non_vuln_template_site_is_not_a_candidate():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-disc"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-disc": {"id": "tpl-disc", "name": "Discovery", "vulnerabilityEnabled": False}},
        creds={1: []},
    )
    snap.set_shared_credentials([])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"
    assert result.summary["candidates_examined"] == 0


def test_failed_candidate_query_is_disclosed_not_flagged():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 2, "name": "Stage", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: [], 2: []},
    )
    snap.set_shared_credentials([])
    # Site 1 overlaps; site 2's query failed.
    snap.set_candidate_agent_overlaps({1: 2}, failed=[2])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "fail"  # site 1 still flagged
    fails = [f for f in result.findings if f.severity == "fail"]
    infos = [f for f in result.findings if f.severity == "info"]
    assert len(fails) == 1 and fails[0].details["site_id"] == 1
    assert any("could not be checked" in f.message.lower() for f in infos)
    assert result.summary["candidates_failed"] == 1


def test_custom_agent_site_name_knob():
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 7, "name": "My Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: []},
        agent_site_name="My Agents",
        agent_site_id=7,
    )
    snap.set_shared_credentials([])
    snap.set_candidate_agent_overlaps({1: 1})
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {"agent_site_name": "My Agents"})
    fails = [f for f in result.findings if f.severity == "fail"]
    assert len(fails) == 1
    assert fails[0].details["agent_site_id"] == 7


def test_all_candidates_fail_their_query_is_disclosed_not_silent_pass():
    """When EVERY candidate's overlap query errors, the rule discloses the
    outage (info finding) and stays pass -- it must NOT report a clean pass
    with no findings (which would hide that nothing was actually checked)."""
    snap = _make_snapshot(
        sites=[{"id": 1, "name": "Prod", "scanTemplate": "tpl-vuln"},
               {"id": 2, "name": "Stage", "scanTemplate": "tpl-vuln"},
               {"id": 9, "name": "Rapid7 Insight Agents"}],
        templates={"tpl-vuln": _vuln_template()},
        creds={1: [], 2: []},
    )
    snap.set_shared_credentials([])
    # No counts; both candidates land in failed.
    snap.set_candidate_agent_overlaps({}, failed=[1, 2])
    result = AgentUnauthCollisionRule().run(snap, "fail", True, 500, {})
    assert result.status == "pass"  # info-only -> pass
    fails = [f for f in result.findings if f.severity == "fail"]
    infos = [f for f in result.findings if f.severity == "info"]
    assert fails == []
    # The outage is disclosed -- not a silent empty pass.
    assert any("could not be checked" in f.message.lower() for f in infos)
    assert result.summary["candidates_failed"] == 2
    assert result.summary["candidates_flagged"] == 0


def test_default_severity_is_fail():
    assert AgentUnauthCollisionRule.default_severity == "fail"
