from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck


def _iso(days_ago: float = 0, hours_ago: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return t.isoformat().replace("+00:00", "Z")


def _site_scan(status: str, days_ago: float = 0, hours_ago: float = 0):
    return {"status": status, "startTime": _iso(days_ago, hours_ago), "id": 1}


def _rule(result, rule_id: str):
    return next(rr for rr in result.rule_results if rr.rule_id == rule_id)


def test_all_sites_healthy(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=1)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "pass"
    overdue = _rule(result, "op.scan_activity.sites_overdue_scans")
    assert overdue.summary["sites_total"] == 1
    assert overdue.summary["sites_with_recent_scans"] == 1


def test_site_with_no_recent_scan_warns(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Stale"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=10)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    # 10 days > 7 (warn) but < 14 (fail) → warn
    assert result.status == "warn"


def test_site_with_no_scan_in_fail_window_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "VeryStale"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=30)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "fail"


def test_stuck_scan_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("running", hours_ago=48)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "fail"
    assert _rule(result, "op.scan_activity.stuck_scans").summary["stuck_count"] == 1


def test_failed_scan_in_recent_window_warns(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {
            "resources": [
                _site_scan("finished", days_ago=1),
                _site_scan("failed", days_ago=2),
            ],
            "page": {"totalPages": 1},
        },
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert _rule(result, "op.scan_activity.recent_failed_scans").summary["failed_count"] == 1


def test_site_with_zero_scans_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Empty"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [], "page": {"totalPages": 0}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    # Never scanned at all → fail
    assert result.status == "fail"
