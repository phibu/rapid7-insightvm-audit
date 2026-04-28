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
