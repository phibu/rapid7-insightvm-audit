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


def _drift_findings(findings):
    """Filter out the trailing 'no-agent' and 'unparseable' info findings —
    only keep the per-version drift findings."""
    return [
        f for f in findings
        if "observed_version" in f.details
    ]


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
    snapshot.set_total_asset_count(3)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "pass"
    assert _drift_findings(result.findings) == []
    assert result.summary["agents_examined"] == 3
    assert result.summary["agents_drifted"] == 0
    assert result.summary["versions_drifted"] == 0
    assert result.summary["versions_observed"] == 1


def test_drifted_versions_aggregated_per_version():
    """Drift is reported per version, not per agent."""
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    snapshot.set_agents([
        _agent_with_version("h1", "4.5.0.0"),  # newest
        _agent_with_version("h2", "4.4.0.0"),  # 1 minor behind — within threshold
        _agent_with_version("h3", "4.2.0.0"),  # 3 minor behind — flagged
        _agent_with_version("h4", "4.2.0.0"),  # same bucket as h3
        _agent_with_version("h5", "3.9.0.0"),  # cross-major — flagged
    ], total=5)
    snapshot.set_total_asset_count(5)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.status == "warn"
    drift = _drift_findings(result.findings)
    # Two distinct drifted versions: 4.2.0.0 (with 2 assets) and 3.9.0.0 (1 asset)
    assert len(drift) == 2
    by_version = {f.details["observed_version"]: f for f in drift}
    assert by_version["4.2.0.0"].details["asset_count"] == 2
    assert by_version["3.9.0.0"].details["asset_count"] == 1
    assert result.summary["versions_drifted"] == 2
    assert result.summary["agents_drifted"] == 3
    # Findings should not contain a hostName field anymore — aggregate, not per-system
    for f in drift:
        assert "hostName" not in f.details


def test_unparseable_versions_collapsed_to_single_finding():
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    snapshot = FakeSnapshot()
    fleet = [
        _agent_with_version("h1", "4.0.12.14"),
        _agent_with_version("h2", "4.5.0.0"),  # need >=2 parseable for fleet_newest
        {"id": 3, "agentId": "y", "hostName": "h3", "software": [
            {"vendor": "Rapid7", "product": "Insight Agent", "version": "weird"},
        ]},
        {"id": 4, "agentId": "z", "hostName": "h4", "software": []},  # no agent software
    ]
    snapshot.set_agents(fleet, total=4)
    snapshot.set_total_asset_count(4)

    result = InsightAgentVersionCurrencyRule().run(
        snapshot, severity="warn", full_scan=False, sample_size=10,
        rule_config={"version_drift_minor": 1},
    )

    assert result.summary["agents_unparseable"] == 2
    # Single info finding for unparseable bucket
    unparseable = [
        f for f in result.findings
        if f.details.get("agent_count") == 2 and "sample_host_names" in f.details
    ]
    assert len(unparseable) == 1
    assert unparseable[0].severity == "info"


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
    """Need at least 2 parseable versions to compare in fleet_newest mode."""
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
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    from tests.audit.conftest import FakeSnapshot

    fake_snapshot = FakeSnapshot()
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.1.0.2", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
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
        _agent_with_version("h2", "4.0.0.0", agent_id="b"),
    ], total=2)
    fake_snapshot.set_total_asset_count(2)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    drift = _drift_findings(r.findings)
    # One bucket (4.0.0.0) with 2 assets
    assert len(drift) == 1
    assert drift[0].details["drift_direction"] == "behind"
    assert drift[0].details["asset_count"] == 2
    assert r.summary["agents_drifted"] == 2
    assert r.summary["versions_drifted"] == 1
    assert r.summary["agents_ahead_of_pin"] == 0


def test_pinned_mode_ahead_flagged(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.2.0.0", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    drift = _drift_findings(r.findings)
    assert len(drift) == 1
    assert drift[0].details["drift_direction"] == "ahead"
    assert "ahead of pinned" in drift[0].message
    assert r.summary["agents_ahead_of_pin"] == 1
    assert r.summary["agents_drifted"] == 1


def test_pinned_mode_mixed_behind_match_ahead(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("behind-h", "4.0.0.0", agent_id="a"),
        _agent_with_version("match-h",  "4.1.0.2", agent_id="b"),
        _agent_with_version("ahead-h",  "4.2.0.0", agent_id="c"),
    ], total=3)
    fake_snapshot.set_total_asset_count(3)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    drift = _drift_findings(r.findings)
    assert r.summary["agents_drifted"] == 2
    assert r.summary["agents_ahead_of_pin"] == 1
    assert r.summary["versions_drifted"] == 2
    directions = sorted(f.details["drift_direction"] for f in drift)
    assert directions == ["ahead", "behind"]


def test_pinned_mode_unparseable_pin_skipped(fake_snapshot):
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "garbage"},
    )
    assert r.status == "skipped"
    assert len(r.findings) == 1
    assert "garbage" in r.findings[0].message
    assert r.findings[0].details["pinned_version_raw"] == "garbage"


def test_latest_known_mode_behind(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "3.0.0.0", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["reference_mode"] == "latest_known"
    assert r.summary["reference_version"] == "4.1.0.2"
    drift = _drift_findings(r.findings)
    assert len(drift) == 1
    assert "behind known-current" in drift[0].message
    assert drift[0].details["asset_count"] == 1


def test_latest_known_mode_within_threshold(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"use_latest_known": True, "version_drift_minor": 5},
    )
    assert r.status == "pass"


def test_pinned_mode_single_agent_not_skipped(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
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
    fake_snapshot.set_total_asset_count(1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["agents_examined"] == 1


def test_pinned_takes_precedence_over_latest_known(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
    ], total=1)
    fake_snapshot.set_total_asset_count(1)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"pinned_version": "4.1.0.2", "use_latest_known": True},
    )
    assert r.summary["reference_mode"] == "pinned"


def test_fleet_newest_default_mode_unchanged(fake_snapshot):
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.0.0.0", agent_id="a"),
        _agent_with_version("h2", "4.5.0.0", agent_id="b"),
    ], total=2)
    fake_snapshot.set_total_asset_count(2)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    assert r.summary["reference_mode"] == "fleet_newest"
    assert r.summary["reference_version"] == "4.5.0.0"


def test_no_agent_finding_when_assets_exceed_agent_population(fake_snapshot):
    """Total assets > assets-with-agent should produce a 'No Agent' info finding."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.5.0.0", agent_id="a"),
        _agent_with_version("h2", "4.5.0.0", agent_id="b"),
    ], total=2)
    fake_snapshot.set_total_asset_count(10)  # 8 assets without an agent
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    no_agent = [
        f for f in r.findings
        if "have no Insight Agent installed" in f.message
    ]
    assert len(no_agent) == 1
    assert no_agent[0].severity == "info"
    assert no_agent[0].details["asset_count"] == 8
    assert no_agent[0].details["total_assets"] == 10
    assert r.summary["assets_without_agent"] == 8
    assert r.summary["assets_with_agent"] == 2
    assert r.summary["assets_total"] == 10


def test_no_agent_finding_suppressed_when_zero(fake_snapshot):
    """When every asset has an agent, the 'No Agent' finding is suppressed."""
    fake_snapshot.set_agents([
        _agent_with_version("h1", "4.5.0.0", agent_id="a"),
        _agent_with_version("h2", "4.5.0.0", agent_id="b"),
    ], total=2)
    fake_snapshot.set_total_asset_count(2)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    no_agent = [
        f for f in r.findings
        if "have no Insight Agent installed" in f.message
    ]
    assert no_agent == []
    assert r.summary["assets_without_agent"] == 0


def test_asset_ids_capped_in_finding_details(fake_snapshot):
    """Per-version asset_ids_sample is capped at 50 with truncated flag."""
    # 60 agents on 4.0.0.0, 1 newer at 4.5.0.0 → all 60 get bucketed and flagged.
    agents = [_agent_with_version(f"h{i}", "4.0.0.0", agent_id=f"a{i}") for i in range(60)]
    agents.append(_agent_with_version("newer", "4.5.0.0", agent_id="ax"))
    fake_snapshot.set_agents(agents, total=61)
    fake_snapshot.set_total_asset_count(61)
    from rapid7_healthcheck.audit.rules.insight_agent_version_currency import InsightAgentVersionCurrencyRule
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"version_drift_minor": 1},
    )
    drift = _drift_findings(r.findings)
    # Find the 4.0.0.0 bucket
    big = next(f for f in drift if f.details["observed_version"] == "4.0.0.0")
    assert big.details["asset_count"] == 60
    assert len(big.details["asset_ids_sample"]) == 50
    assert big.details["asset_ids_truncated"] is True
