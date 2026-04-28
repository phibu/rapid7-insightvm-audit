from __future__ import annotations

from datetime import datetime, timedelta, timezone

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


def test_inactive_engine_is_fail(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "off", "status": "inactive",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "fail"


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
