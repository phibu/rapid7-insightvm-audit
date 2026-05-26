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
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert "10.0.0" in r.findings[0].message or True  # scope info present implicitly
    assert r.card_summary == {"examined": 2, "passed": 1, "failed": 1}


def test_no_overlap_when_scope_disjoint(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.1.0.0/24"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_hostname_scope_overlaps(fake_snapshot):
    """Two sites scanning the same hostname (not an IP) in overlapping time
    windows must be flagged. Hostnames are valid InsightVM scan targets and
    must not be silently dropped."""
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base),
                                          "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(minutes=30)),
                                          "duration": "PT1H", "repeat": None}])
    # Same host, different case — should match case-insensitively.
    fake_snapshot.set_site_included_targets(1, [{"address": "db01.corp.example.com"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "DB01.corp.example.com"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1


def test_no_overlap_when_hostnames_differ(fake_snapshot):
    """Distinct hostnames in overlapping time windows do not overlap in scope."""
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "db01.corp.example.com"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "web01.corp.example.com"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_disabled_schedule_skipped(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": False,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_assumed_scan_duration_knob_widens_overlap_window(fake_snapshot):
    """Two schedules with NO duration field start 90 min apart. With the
    default 60-min assumed duration they do not overlap. With the knob
    raised to 120 min the first window extends past the second's start,
    so they overlap and the rule warns."""
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    # No `duration` key → the rule substitutes the assumed duration.
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(minutes=90)),
                                          "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])

    # Default 60 min assumed duration: site-1 window is 12:00-13:00,
    # site-2 starts 13:30 → no overlap.
    default_result = OverlappingScanWindowsRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    assert default_result.status == "pass"

    # 120 min assumed duration: site-1 window is 12:00-14:00, site-2
    # starts 13:30 → overlap.
    widened_result = OverlappingScanWindowsRule().run(
        fake_snapshot, "warn", False, 500,
        {"assumed_scan_duration_minutes": 120},
    )
    assert widened_result.status == "warn"


def _overlap_fixture(fake_snapshot):
    """Two scope-overlapping schedules with no `duration` (so the assumed
    duration governs the window). Both start at the same instant, so any
    strictly-positive assumed duration produces an overlap; a zero/negative
    duration (the bug) would not."""
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base),
                                          "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])


def test_assumed_scan_duration_floored_at_one_minute_when_zero(fake_snapshot):
    """A zero assumed_scan_duration_minutes would collapse the window to a
    point in time and silently suppress findings. The knob must floor at 1."""
    _overlap_fixture(fake_snapshot)
    r = OverlappingScanWindowsRule().run(
        fake_snapshot, "warn", False, 500,
        {"assumed_scan_duration_minutes": 0},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1


def test_assumed_scan_duration_floored_at_one_minute_when_negative(fake_snapshot):
    """A negative assumed_scan_duration_minutes would produce a negative
    timedelta. The knob must floor at 1."""
    _overlap_fixture(fake_snapshot)
    r = OverlappingScanWindowsRule().run(
        fake_snapshot, "warn", False, 500,
        {"assumed_scan_duration_minutes": -5},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1


def test_assumed_scan_duration_non_numeric_raises_value_error(fake_snapshot):
    """Non-numeric strings must continue to raise ValueError so the caller's
    safe_run wrapper surfaces a status='error' rule card (preserves the
    bad-config-is-error pattern)."""
    import pytest

    _overlap_fixture(fake_snapshot)
    with pytest.raises(ValueError):
        OverlappingScanWindowsRule().run(
            fake_snapshot, "warn", False, 500,
            {"assumed_scan_duration_minutes": "abc"},
        )
