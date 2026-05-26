from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck


def _snap(fake_client) -> EnvSnapshot:
    """Build a real EnvSnapshot over the test's fake client."""
    return EnvSnapshot(fake_client, full_scan=False, sample_size=500)


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
                _site_scan("error", days_ago=2),
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
    # card_summary populated for site-level rules (F1 sub2): 1 site, 1 flagged.
    never = _rule(result, "op.scan_activity.sites_never_scanned")
    assert never.card_summary == {"examined": 1, "passed": 0, "failed": 1}
    # Stuck/recent-failed/recent-unknown have ambiguous denominators — None.
    assert _rule(result, "op.scan_activity.stuck_scans").card_summary is None


def test_unknown_status_scan_in_recent_window_warns(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {
            "resources": [
                _site_scan("finished", days_ago=1),
                _site_scan("unknown", days_ago=2),
            ],
            "page": {"totalPages": 1},
        },
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    unknown_rule = _rule(result, "op.scan_activity.recent_unknown_scans")
    assert unknown_rule.status == "warn"
    assert unknown_rule.summary["unknown_count"] == 1
    assert any(
        f.severity == "warn" and "unknown" in f.message.lower()
        for f in unknown_rule.findings
    )


def test_scan_activity_uses_snapshot_sites_not_paginate(fake_client, app_config):
    """When a snapshot is passed in, _fetch_parsed_sites must NOT call
    client.paginate('/api/3/sites') directly. Locks in the snapshot
    threading."""
    cfg = app_config
    fake_client.set_paginate("/api/3/sites", [
        {"id": 1, "name": "site-a"},
    ])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": []},
    )

    snap = _snap(fake_client)
    snap.sites()  # prime cache

    paginate_before = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )

    ScanActivityCheck().run(fake_client, cfg, snapshot=snap)

    paginate_after = sum(
        1 for c in fake_client.calls if c[0] == "paginate" and c[1] == "/api/3/sites"
    )
    assert paginate_after == paginate_before, (
        f"ScanActivityCheck issued {paginate_after - paginate_before} "
        f"additional /api/3/sites paginations after snapshot was primed"
    )


def test_scan_fetch_failure_isolated_into_error_rules(fake_client, app_config):
    """If the shared per-site scan fetch raises, the check must NOT propagate
    the exception. It returns a CheckResult whose rule cards are all `error`,
    so a single transient API failure doesn't black out the whole check."""
    from rapid7_healthcheck.client import Rapid7ClientError

    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get_raises(
        "/api/3/sites/1/scans",
        Rapid7ClientError("503 at /api/3/sites/1/scans", status_code=503),
    )

    # Must not raise.
    result = ScanActivityCheck().run(fake_client, app_config)

    assert result.status in ("fail", "error")
    assert len(result.rule_results) == 6
    assert all(rr.status == "error" for rr in result.rule_results)
    # Each error rule keeps its own identity (rule_id), not a shared placeholder.
    assert len({rr.rule_id for rr in result.rule_results}) == 6
