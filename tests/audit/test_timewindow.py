"""Tests for ``timewindow`` -- the single owner of the InsightVM time-shape
parsing both verticals used to copy (see CONTEXT.md "timewindow").

Three functions behind a tiny interface: ``parse_iso`` (always-aware UTC),
``parse_duration`` (``PT[nH][nM][nS]`` -> ``timedelta``), and
``windows_intersect`` (half-open interval overlap). These were extracted from
six copies of ``_parse_iso`` and two of the duration/intersect pair; the
extraction adopted the cloud-drift copy's always-aware-UTC behaviour as the one
contract, which fixes the latent ``TypeError`` the naive copies carried.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit.timewindow import (
    parse_duration,
    parse_iso,
    windows_intersect,
)


def test_parse_iso_offsetless_is_aware_utc():
    # An offset-less timestamp (the Console sometimes omits the offset) must
    # come back tz-aware as UTC -- the naive copies crashed downstream when
    # subtracted from an aware `now`.
    dt = parse_iso("2026-06-26T12:00:00")
    assert dt == datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
    assert dt.tzinfo is not None


def test_parse_iso_z_suffix_is_utc():
    assert parse_iso("2026-06-26T12:00:00Z") == datetime(
        2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc
    )


def test_parse_iso_preserves_explicit_offset():
    dt = parse_iso("2026-06-26T12:00:00+02:00")
    assert dt is not None
    assert dt.utcoffset().total_seconds() == 2 * 3600


def test_parse_iso_returns_none_for_empty_none_and_garbage():
    assert parse_iso(None) is None
    assert parse_iso("") is None
    assert parse_iso("not-a-date") is None


def test_parse_iso_returns_none_for_non_string():
    # engine_version_drift's copy added this guard; folded into the one contract.
    assert parse_iso(12345) is None
    assert parse_iso({"start": "2026-01-01"}) is None


def test_parse_duration_hours_minutes_seconds():
    assert parse_duration("PT3H45M30S") == timedelta(hours=3, minutes=45, seconds=30)


def test_parse_duration_partial_components():
    assert parse_duration("PT2H") == timedelta(hours=2)
    assert parse_duration("PT90M") == timedelta(minutes=90)


def test_parse_duration_empty_and_unparseable_is_zero():
    # The overlap rules fall back to an assumed duration when this is zero, so
    # an unparseable value must be timedelta(0), never a raise.
    assert parse_duration(None) == timedelta(0)
    assert parse_duration("") == timedelta(0)
    assert parse_duration("garbage") == timedelta(0)


def test_windows_intersect_overlapping():
    assert windows_intersect(0, 10, 5, 15) is True


def test_windows_intersect_disjoint():
    assert windows_intersect(0, 10, 20, 30) is False


def test_windows_intersect_touching_is_not_overlap():
    # Half-open: a window ending exactly when the next begins does not overlap.
    assert windows_intersect(0, 10, 10, 20) is False
