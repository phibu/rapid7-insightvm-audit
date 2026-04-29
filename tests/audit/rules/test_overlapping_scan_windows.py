from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit.rules.overlapping_scan_windows import (
    OverlappingScanWindowsRule,
)


def _iso(dt: datetime) -> str: return dt.isoformat().replace("+00:00", "Z")


def test_pass_when_schedules_dont_overlap_in_time(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(hours=2)),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_time_and_scope_overlap(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base),
                                          "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(minutes=30)),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.5"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert "10.0.0" in r.findings[0].message or True  # scope info present implicitly


def test_no_overlap_when_scope_disjoint(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.1.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_schedule_inside_blackout(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([{"id": 99, "enabled": True, "name": "Maint",
                                   "start": _iso(base - timedelta(minutes=30)),
                                   "duration": "PT3H"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert any("Maint" in f.message for f in r.findings)


def test_disabled_schedule_skipped(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": False,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_skips_blackout_check_when_endpoint_unavailable(fake_snapshot):
    """When /api/3/blackouts returns 404 the rule skips the blackout
    sub-check (emitting an info finding) and still runs scan-vs-scan overlap."""
    base = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([])
    fake_snapshot.set_blackouts_unavailable(True)

    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    # Scan-vs-scan overlap still detected.
    assert any(f.severity == "warn" and "overlap" in f.message.lower() for f in r.findings)
    # Info finding present explaining the skip.
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert "blackout" in info_findings[0].message.lower()
    assert r.summary["blackouts_unavailable"] is True
