from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rapid7_healthcheck.checks.scan_engines import ScanEnginesCheck


def _now_iso(offset_hours: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return t.isoformat().replace("+00:00", "Z")


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
    assert result.findings == []


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
    assert any(f.severity == "warn" and "warm" in f.message for f in result.findings)
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
    bad = next(rr for rr in result.rule_results
               if rr.rule_id == "op.scan_engines.bad_status")
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
    assert any("not paired" in f.message.lower() for f in result.findings)


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
    unpaired = [f for f in result.findings if "not paired" in f.message.lower()]
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
    # Two findings, one engine
    assert len(result.findings) == 2
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
