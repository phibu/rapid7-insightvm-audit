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
        assert "reference_version" in f.details


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


def test_pinned_mode_exact_match_passes():
    """Single agent on the pinned version should pass with no findings,
    summary.reference_mode == 'pinned', no behind/ahead counts."""
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    fake_snapshot = FakeSnapshot()
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.1.0.2", agent_id="a"),
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "pass"
    assert r.summary["reference_mode"] == "pinned"
    assert r.summary["reference_version"] == "4.1.0.2"
    assert r.summary["agents_drifted"] == 0
    assert r.summary["agents_ahead_of_pin"] == 0


def test_pinned_mode_behind_flagged(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["drift_direction"] == "behind"
    assert r.summary["agents_drifted"] == 1
    assert r.summary["agents_ahead_of_pin"] == 0


def test_pinned_mode_ahead_flagged(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.2.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["drift_direction"] == "ahead"
    assert "ahead of pinned" in r.findings[0].message
    assert r.summary["agents_ahead_of_pin"] == 1
    assert r.summary["agents_drifted"] == 1


def test_pinned_mode_mixed_behind_match_ahead(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("behind-h", "4.0.0.0", agent_id="a"),
        _agent_with_version("match-h",  "4.1.0.2", agent_id="b"),
        _agent_with_version("ahead-h",  "4.2.0.0", agent_id="c"),
    ], total=3)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert r.summary["agents_drifted"] == 2
    assert r.summary["agents_ahead_of_pin"] == 1
    directions = sorted(f.details["drift_direction"] for f in r.findings)
    assert directions == ["ahead", "behind"]


def test_pinned_mode_unparseable_pin_skipped(fake_snapshot):
    """Bad pinned_version → skipped with a clear info finding; no agent
    pagination happens (we never get to snapshot.agents())."""
    # Deliberately do NOT set any agents — proves the rule short-circuits.
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "garbage"},
    )
    assert r.status == "skipped"
    assert len(r.findings) == 1
    assert "garbage" in r.findings[0].message
    assert r.findings[0].details["pinned_version_raw"] == "garbage"


def test_latest_known_mode_behind(fake_snapshot):
    """Agent at 3.0.0.0 vs constant 4.1.0.2 = many minor behind, threshold default 1
    → flagged."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "3.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["reference_mode"] == "latest_known"
    assert r.summary["reference_version"] == "4.1.0.2"
    assert "behind known-current" in r.findings[0].message


def test_latest_known_mode_within_threshold(fake_snapshot):
    """Agent at 4.0.0.0 with version_drift_minor=5 → within tolerance, pass."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"use_latest_known": True, "version_drift_minor": 5},
    )
    assert r.status == "pass"


def test_pinned_mode_single_agent_not_skipped(fake_snapshot):
    """Pinned mode with one parseable agent must NOT trip the >=2 skip."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert r.summary["agents_examined"] == 1


def test_latest_known_mode_single_agent_not_skipped(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "3.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["agents_examined"] == 1


def test_pinned_takes_precedence_over_latest_known(fake_snapshot):
    """Both knobs set → pinned wins, reference_mode == 'pinned'."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"pinned_version": "4.1.0.2", "use_latest_known": True},
    )
    assert r.summary["reference_mode"] == "pinned"


def test_fleet_newest_default_mode_unchanged(fake_snapshot):
    """No new knobs → fleet-newest mode, summary keys present."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
        _agent_with_version("h2", "4.5.0.0", agent_id="b"),
    ], total=2)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    assert r.summary["reference_mode"] == "fleet_newest"
    assert r.summary["reference_version"] == "4.5.0.0"
