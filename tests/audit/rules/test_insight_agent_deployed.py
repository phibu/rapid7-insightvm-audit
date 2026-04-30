"""Tests for InsightAgentDeployedRule."""
from __future__ import annotations

from rapid7_healthcheck.audit.rules.insight_agent_deployed import InsightAgentDeployedRule


def test_zero_agents_emits_finding_at_configured_severity():
    """When no agents are deployed, emit one finding at the configured severity."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"  # info severity → status pass
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert ("no insight agent" in result.findings[0].message.lower()
            or "0" in result.findings[0].message)
    assert result.summary["agents_total"] == 0


def test_nonzero_agents_passes_with_no_finding():
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents(
        [{"agentId": "abc", "id": 1}, {"agentId": "def", "id": 2}],
        total=2,
    )

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["agents_total"] == 2


def test_unavailable_endpoint_self_skips_with_info():
    """If /api/3/agents 404'd, the rule self-skips with an info finding."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0, unavailable=True)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "skipped"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert ("unavailable" in result.findings[0].message.lower()
            or "404" in result.findings[0].message)


def test_zero_agents_at_warn_severity_status_warn():
    """When configured severity is warn, zero-agents finding bumps status to warn."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "warn"
    assert result.findings[0].severity == "warn"
