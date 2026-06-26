"""Tests for InsightAgentDeployedRule (Insight Agent Fleet Coverage)."""
from __future__ import annotations

from rapid7_healthcheck.audit.rules.insight_agent_deployed import InsightAgentDeployedRule


def test_zero_agents_emits_finding_at_configured_severity():
    """When no agents are deployed, emit one finding at the configured severity."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"  # info severity → status pass
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "no insight agent" in result.findings[0].message.lower()
    assert result.summary["agents_total"] == 0
    assert result.summary["assets_total"] == 100


def test_zero_agents_at_warn_severity_status_warn():
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "warn"
    assert result.findings[0].severity == "warn"


def test_full_coverage_passes_with_no_finding():
    """Agents == assets → 100% coverage → pass with no findings."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents(
        [{"agentId": "a", "id": 1}, {"agentId": "b", "id": 2}],
        total=2,
    )
    snapshot.set_total_asset_count(2)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["agents_total"] == 2
    assert result.summary["assets_total"] == 2
    assert result.summary["coverage_percent"] == 100.0


def test_partial_coverage_below_threshold_emits_finding_at_configured_severity():
    """50% coverage with default 70% threshold → one finding.

    The finding inherits the configured severity (not a hardcoded "warn"):
    with the rule's default ``info`` severity the finding must NOT escalate
    status away from ``pass`` (CLAUDE.md: info findings never escalate).
    """
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([{"agentId": str(i), "id": i} for i in range(50)], total=50)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "50.0%" in result.findings[0].message
    assert result.summary["coverage_percent"] == 50.0


def test_partial_coverage_below_threshold_warns_when_configured_warn():
    """When the operator overrides severity to ``warn``, partial coverage
    escalates the rule status to ``warn``."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([{"agentId": str(i), "id": i} for i in range(50)], total=50)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "50.0%" in result.findings[0].message


def test_partial_coverage_above_threshold_passes():
    """80% coverage with default 70% threshold → pass with no findings."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([{"agentId": str(i), "id": i} for i in range(80)], total=80)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["coverage_percent"] == 80.0


def test_custom_threshold_via_rule_config():
    """warn_below_percent in rule_config overrides the default."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([{"agentId": str(i), "id": i} for i in range(80)], total=80)
    snapshot.set_total_asset_count(100)

    result = InsightAgentDeployedRule().run(
        snapshot,
        severity="warn",
        full_scan=False,
        sample_size=10,
        rule_config={"warn_below_percent": 90},
    )

    assert result.status == "warn"
    assert "90%" in result.findings[0].message


def test_unavailable_endpoint_self_skips_without_finding():
    """If /api/3/agents was unavailable (404/504), the rule self-skips cleanly.
    The reason now lives in summary (rendered as the skipped-box message)
    rather than as a finding, so filter chips and counts treat the rule as
    skipped, not a hidden info hit."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0, unavailable=True)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    assert result.status == "skipped"
    assert result.findings == []
    assert "could not be enumerated" in result.summary["reason"]
    assert result.summary["endpoint_available"] is False


def test_zero_assets_skips_coverage_math():
    """If the asset inventory is empty, coverage math is meaningless;
    rule should not divide by zero, and coverage_percent is omitted."""
    from tests.audit.conftest import FakeSnapshot
    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)
    snapshot.set_total_asset_count(0)

    result = InsightAgentDeployedRule().run(
        snapshot, severity="info", full_scan=False, sample_size=10, rule_config={}
    )

    # Zero agents + zero assets → still emits the "no agents deployed" finding
    # (the configurable severity branch). coverage_percent must not be present.
    assert "coverage_percent" not in result.summary
    assert result.summary["agents_total"] == 0


def test_fleet_coverage_uses_count_not_body_fetch():
    """insight_agent_deployed reads agent_count() and never fetches agent
    bodies via agents()."""
    from tests.audit.conftest import FakeSnapshot

    snap = FakeSnapshot()
    # set_agents([], total=40) sets the count agent_count() returns WITHOUT a
    # body sample (FakeSnapshot has no set_agent_count; agent_count() reads
    # _agents_total, which set_agents populates). is_agents_unavailable() stays
    # False (unavailable defaults to False).
    snap.set_agents([], total=40)
    snap.set_total_asset_count(100)  # for coverage math

    called = {"agents": 0, "agent_count": 0}
    orig_count = snap.agent_count
    snap.agent_count = lambda: (called.__setitem__("agent_count", called["agent_count"] + 1), orig_count())[1]

    def _boom():
        called["agents"] += 1
        raise AssertionError("agents() must not be called by fleet-coverage rule")

    snap.agents = _boom

    rule = InsightAgentDeployedRule()
    result = rule.run(snap, "info", True, 500, {})

    assert called["agents"] == 0
    assert called["agent_count"] >= 1
    # Coverage math unchanged: 40/100 = 40% -> below default 70% threshold -> one warn finding.
    assert result.summary["agents_total"] == 40
    assert result.summary["coverage_percent"] == 40.0
