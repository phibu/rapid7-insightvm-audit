from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rapid7_healthcheck.checks.scan_engines import (
    EngineMissingLastRefreshRule,
    EngineUnpairedRule,
    ScanEnginesCheck,
    _build_pooled_sites_index,
)


def _rule(result, rule_id: str):
    for r in result.rule_results:
        if r.rule_id == rule_id:
            return r
    raise AssertionError(f"rule_id {rule_id!r} not in {[r.rule_id for r in result.rule_results]}")


def _now_iso(offset_hours: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return t.isoformat().replace("+00:00", "Z")


@pytest.fixture(autouse=True)
def _default_empty_scan_engine_pools(fake_client):
    """Module-scoped autouse: pre-register an empty /api/3/scan_engine_pools.

    EngineUnpairedRule consults snapshot.scan_engine_pools() to honor
    pool-mediated pairing; the snapshot's FakeRapid7Client raises on
    unregistered paths, so every ScanEnginesCheck integration test
    needed a manual registration. The autouse default lets new tests
    skip this boilerplate. Tests that need a non-empty pool listing
    call `fake_client.set_get("/api/3/scan_engine_pools", ...)` which
    overwrites the default registration.
    """
    fake_client.set_get("/api/3/scan_engine_pools", {"resources": []})


def test_all_engines_healthy(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "engine-a", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},
                {"id": 2, "name": "engine-b", "status": "active",
                 "lastRefreshedDate": _now_iso(1), "sites": [11]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["engines_total"] == 2
    assert result.summary["engines_healthy"] == 2
    assert all(not r.findings for r in result.rule_results)


def test_engine_warn_when_last_contact_exceeds_warn_hours(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "warm", "status": "active",
                 "lastRefreshedDate": _now_iso(3), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    last_contact = _rule(result, "op.scan_engines.last_contact")
    assert any(f.severity == "warn" and "warm" in f.message for f in last_contact.findings)
    assert result.summary["engines_warn"] == 1


def test_engine_fail_when_last_contact_exceeds_fail_hours(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "stale", "status": "active",
                 "lastRefreshedDate": _now_iso(48), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "fail"
    last_contact = _rule(result, "op.scan_engines.last_contact")
    assert any(f.severity == "fail" and "stale" in f.message for f in last_contact.findings)
    assert result.summary["engines_fail"] == 1


@pytest.mark.parametrize(
    "status,expected_status,expected_severity",
    [
        ("incompatible-version", "fail", "fail"),
        ("not-responding", "fail", "fail"),
        ("pending-authorization", "warn", "warn"),
        ("unknown", "warn", "warn"),
    ],
)
def test_bad_status_engine_is_flagged(
    status, expected_status, expected_severity, fake_client, app_config
):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": f"engine-{status}", "status": status,
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == expected_status
    bad = _rule(result, "op.scan_engines.bad_status")
    assert any(f.severity == expected_severity and status in f.message
               for f in bad.findings)


def test_engine_with_no_sites_is_warn(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "lonely", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": []},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    unpaired = _rule(result, "op.scan_engines.unpaired")
    assert any("not paired" in f.message.lower() for f in unpaired.findings)


def test_unpaired_engine_finding_includes_identification_details(fake_client, app_config):
    # Operators need more than the engine ID to act on an unpaired engine.
    # Surface address, port, status, and version info in the finding's details
    # so the report renders something actionable.
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {
                    "id": 7,
                    "name": "lonely",
                    "address": "engine.example.com",
                    "port": 40814,
                    "status": "active",
                    "productVersion": "6.6.250",
                    "contentVersion": "1.2.3",
                    "serialNumber": "ABC-123",
                    "lastRefreshedDate": _now_iso(0),
                    "sites": [],
                },
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    unpaired_rule = _rule(result, "op.scan_engines.unpaired")
    unpaired = [f for f in unpaired_rule.findings if "not paired" in f.message.lower()]
    assert len(unpaired) == 1
    d = unpaired[0].details
    assert d["id"] == 7
    assert d["name"] == "lonely"
    assert d["address"] == "engine.example.com"
    assert d["port"] == 40814
    assert d["host"] == "engine.example.com:40814"
    assert d["status"] == "active"
    assert d["product_version"] == "6.6.250"
    assert d["content_version"] == "1.2.3"
    assert d["serial_number"] == "ABC-123"
    assert d["last_refreshed"] is not None


def test_missing_last_refresh_skips_local_engine_by_name():
    rule = EngineMissingLastRefreshRule()
    result = rule.run([
        {"id": 1, "name": "Local scan engine", "status": "active",
         "lastRefreshedDate": None, "address": "192.168.1.1"},
    ])
    assert result.findings == []


def test_missing_last_refresh_skips_local_engine_by_loopback():
    rule = EngineMissingLastRefreshRule()
    result = rule.run([
        {"id": 1, "name": "renamed-local", "status": "active",
         "lastRefreshedDate": None, "address": "127.0.0.1"},
    ])
    assert result.findings == []


def test_missing_last_refresh_still_flags_distributed_engine():
    rule = EngineMissingLastRefreshRule()
    result = rule.run([
        {"id": 2, "name": "engine-01", "status": "active",
         "lastRefreshedDate": None, "address": "10.0.0.5"},
    ])
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"


def test_missing_last_refreshed_is_warn(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "no-ts", "status": "active",
                 "lastRefreshedDate": None, "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    missing = _rule(result, "op.scan_engines.missing_last_refresh")
    assert any("no lastRefreshedDate" in f.message for f in missing.findings)


def test_double_warn_engine_counted_once(fake_client, app_config):
    # An engine can produce both an age-warn AND a no-pairing-warn.
    # The summary should count the engine once, not the findings.
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {
                    "id": 1,
                    "name": "double-warn",
                    "status": "active",
                    "lastRefreshedDate": _now_iso(3),  # warn (>= 2h)
                    "sites": [],                        # warn (no pairing)
                },
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    # Two findings (one per rule), one engine
    last_contact = _rule(result, "op.scan_engines.last_contact")
    unpaired = _rule(result, "op.scan_engines.unpaired")
    assert len(last_contact.findings) == 1
    assert len(unpaired.findings) == 1
    assert result.summary["engines_total"] == 1
    assert result.summary["engines_warn"] == 1
    assert result.summary["engines_fail"] == 0
    assert result.summary["engines_healthy"] == 0


def test_summary_counts_partition_engines(fake_client, app_config):
    # total = healthy + warn + fail, always.
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "ok", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},          # healthy
                {"id": 2, "name": "warn-only", "status": "active",
                 "lastRefreshedDate": _now_iso(3), "sites": [10]},          # warn
                {"id": 3, "name": "double-warn", "status": "active",
                 "lastRefreshedDate": _now_iso(3), "sites": []},            # warn (worst sev)
                {"id": 4, "name": "stale-fail", "status": "active",
                 "lastRefreshedDate": _now_iso(48), "sites": [10]},         # fail
                {"id": 5, "name": "off", "status": "not-responding",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},          # fail
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    s = result.summary
    assert s["engines_total"] == 5
    assert s["engines_healthy"] == 1
    assert s["engines_warn"] == 2
    assert s["engines_fail"] == 2
    assert s["engines_total"] == s["engines_healthy"] + s["engines_warn"] + s["engines_fail"]


def test_engine_fetch_failure_isolated_into_error_rules(fake_client, app_config):
    """If the /api/3/scan_engines GET raises, the check must NOT propagate.
    It returns a CheckResult whose four rule cards are all `error`, and the
    count summary falls back to zeros instead of crashing."""
    from rapid7_healthcheck.client import Rapid7ClientError

    fake_client.set_get_raises(
        "/api/3/scan_engines",
        Rapid7ClientError("503 at /api/3/scan_engines", status_code=503),
    )

    # Must not raise.
    result = ScanEnginesCheck().run(fake_client, app_config)

    assert result.status in ("fail", "error")
    assert len(result.rule_results) == 4
    assert all(rr.status == "error" for rr in result.rule_results)
    assert len({rr.rule_id for rr in result.rule_results}) == 4
    assert result.summary["engines_total"] == 0


# --- EngineUnpairedRule pool-awareness ---------------------------------


def test_unpaired_skips_engine_paired_via_pool():
    rule = EngineUnpairedRule()
    pooled_idx = {2: {10, 11}}  # engine 2 is in a pool with sites 10,11
    result = rule.run(
        [{"id": 2, "name": "engine-pool", "status": "active",
          "sites": [], "address": "10.0.0.5"}],
        pooled_idx,
    )
    assert result.findings == []


def test_unpaired_flags_engine_with_no_pool_and_no_sites():
    rule = EngineUnpairedRule()
    result = rule.run(
        [{"id": 3, "name": "lonely", "status": "active",
          "sites": [], "address": "10.0.0.6"}],
        {},
    )
    assert len(result.findings) == 1


def test_unpaired_can_be_called_without_pool_index():
    rule = EngineUnpairedRule()
    result = rule.run(
        [{"id": 3, "name": "lonely", "status": "active",
          "sites": [], "address": "10.0.0.6"}],
    )
    assert len(result.findings) == 1  # same as passing {}


def test_unpaired_skips_engine_with_direct_sites_even_without_pool():
    rule = EngineUnpairedRule()
    result = rule.run(
        [{"id": 4, "name": "direct", "status": "active",
          "sites": [99], "address": "10.0.0.7"}],
        {},
    )
    assert result.findings == []


def test_build_pooled_sites_index_unions_per_engine():
    pools = [
        {"id": 1, "engines": [10], "sites": [100, 101]},
        {"id": 2, "engines": [10, 11], "sites": [200]},
    ]
    idx = _build_pooled_sites_index(pools)
    assert idx[10] == {100, 101, 200}
    assert idx[11] == {200}


def test_build_pooled_sites_index_handles_missing_keys():
    pools = [
        {"id": 1},  # no engines, no sites
        {"id": 2, "engines": [], "sites": []},
    ]
    idx = _build_pooled_sites_index(pools)
    assert idx == {}


def test_build_pooled_sites_index_filters_bool_engine_ids():
    # bool is a subclass of int in Python; a corrupt payload with True/False
    # in `engines` must not be treated as engine_id=1/0. Defense in depth.
    pools = [{"id": 1, "engines": [True, False, 5], "sites": [100]}]
    idx = _build_pooled_sites_index(pools)
    assert idx == {5: {100}}


def test_unpaired_skips_engine_paired_only_via_pool_in_check(fake_client, app_config):
    """End-to-end: ScanEnginesCheck wires snapshot.scan_engine_pools() into
    the unpaired rule. An engine with empty `sites` but a pool membership
    must NOT be flagged."""
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 7, "name": "pool-only", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": []},
            ]
        },
    )
    fake_client.set_get(
        "/api/3/scan_engine_pools",
        {"resources": [
            {"id": 1, "name": "prod-pool", "engines": [7], "sites": [100]},
        ]},
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    unpaired = _rule(result, "op.scan_engines.unpaired")
    assert unpaired.findings == []
    # And the rollup considers this engine healthy.
    assert result.summary["engines_healthy"] == 1
    assert result.summary["engines_warn"] == 0
