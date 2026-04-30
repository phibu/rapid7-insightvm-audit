"""Tests for InsightAgentVersionCurrencyRule."""
from __future__ import annotations


def _agent_with_version(host: str, version_str: str, agent_id: str = "x") -> dict:
    return {
        "id": hash(host) & 0xFFFF,
        "agentId": agent_id,
        "hostName": host,
        "software": [
            {"vendor": "Rapid7", "product": "Insight Agent", "version": version_str},
        ],
    }


def test_uniform_fleet_no_findings():
    """All agents on the same version → no drift findings."""
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([
        _agent_with_version("h1", "4.0.12.14"),
        _agent_with_version("h2", "4.0.12.14"),
        _agent_with_version("h3", "4.0.12.14"),
    ], total=3)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["agents_examined"] == 3
    assert result.summary["agents_drifted"] == 0


def test_drifted_agents_flagged():
    """Agents more than version_drift_minor behind newest are flagged."""
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([
        _agent_with_version("h1", "4.5.0.0"),  # newest
        _agent_with_version("h2", "4.4.0.0"),  # 1 minor behind — within threshold
        _agent_with_version("h3", "4.2.0.0"),  # 3 minor behind — flagged
        _agent_with_version("h4", "3.9.0.0"),  # cross-major — flagged
    ], total=4)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "warn"
    assert result.summary["agents_drifted"] == 2
    drifted_hosts = sorted([f.details["hostName"] for f in result.findings])
    assert drifted_hosts == ["h3", "h4"]
    for f in result.findings:
        assert "observed_version" in f.details
        assert "newest_version" in f.details


def test_unparseable_version_counted_separately():
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    fleet = [
        _agent_with_version("h1", "4.0.12.14"),
        {"id": 2, "agentId": "y", "hostName": "h2", "software": [
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "weird"},
        ]},
        {"id": 3, "agentId": "z", "hostName": "h3", "software": []},  # no agent software
    ]
    snapshot.set_agents(fleet, total=3)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    # Only h1 has a parseable version — single-agent fleet → can't compare.
    assert result.status == "skipped"
    assert result.summary["agents_unparseable"] == 2
    assert result.summary["agents_examined"] == 1


def test_empty_fleet_self_skips():
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "skipped"
    assert ("no insight agent" in result.findings[0].message.lower()
            or "no agents" in result.findings[0].message.lower())


def test_unavailable_endpoint_self_skips():
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([], total=0, unavailable=True)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "skipped"
    assert ("unavailable" in result.findings[0].message.lower()
            or "404" in result.findings[0].message)


def test_single_parseable_agent_self_skips():
    """Need at least 2 parseable versions to compare."""
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([_agent_with_version("h1", "4.0.0.0")], total=1)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "skipped"
