from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from rapid7_healthcheck.audit.cloud_drift.rules.scan_engine_cloud_registration import (
    ScanEngineCloudRegistrationRule,
)


def _now_iso(offset_hours: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=offset_hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _snapshot(console_engines: list[dict], cloud_engines: list[dict]) -> MagicMock:
    s = MagicMock()
    s.console_engines.return_value = console_engines
    s.cloud_engines.return_value = cloud_engines
    return s


def test_all_engines_present_and_recent_passes():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(1)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "pass"


def test_engine_missing_from_cloud_fails():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "fail"
    fail = [f for f in result.findings if f.severity == "fail"]
    assert len(fail) == 1
    assert "engine-b" in fail[0].message


def test_engine_present_but_stale_warns():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(48)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "stale" in result.findings[0].message.lower() or "last_seen" in result.findings[0].message


def test_ignored_engine_skipped():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "lab-only"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"ignore_engines": ["lab-only"]})
    assert result.status == "pass"


def test_cloud_engine_without_last_seen_treated_as_stale():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": None}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "warn"


def test_summary_counts():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[
            {"id": 1, "name": "engine-a"},
            {"id": 2, "name": "engine-b"},
            {"id": 3, "name": "engine-c"},
        ],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(48)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.summary["console_engines"] == 3
    assert result.summary["cloud_engines"] == 2
    assert result.summary["missing_from_cloud"] == 1
    assert result.summary["stale_in_cloud"] == 1


def test_rule_is_registered():
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    assert "cd.scan_engine_cloud_registration" in _CLOUD_RULE_REGISTRY


def test_fractional_max_age_falls_back_to_default():
    """A user setting last_seen_max_age_hours=0.5 must not silently truncate
    to 0 (which would make the threshold == now() and flag every engine as
    stale). The coercion helper falls back to the default with a warning."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        # 1h ago: stale under 0.5h (if truncation bug present), fresh under default 24h.
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(1)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 0.5})
    # Default 24h kicks in -> 1h-old engine is fresh -> pass.
    assert result.status == "pass"
    assert result.summary["max_age_hours"] == 24


def test_zero_or_negative_max_age_falls_back_to_default():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(1)}],
    )
    for bad in (0, -5, "abc", None, True):
        result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": bad})
        assert result.summary["max_age_hours"] == 24, f"bad input {bad!r} should fall back"


def test_duplicate_engine_names_pick_most_recent_last_seen():
    """A duplicate engine name in the cloud list should not silently let the
    older shadow registration mask the live one (last-write-wins in the
    naive dict comprehension would let response order decide). The newer
    last_seen wins."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[
            # Stale shadow first; live entry second. last_seen newer on the live entry.
            {"name": "engine-a", "last_seen": _now_iso(72)},
            {"name": "engine-a", "last_seen": _now_iso(1)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    # Newer entry (1h ago) wins -> rule should not flag stale.
    assert result.status == "pass"


def test_duplicate_engine_names_live_first_then_stale_still_picks_live():
    """Order-independent: live entry first, stale shadow second. The live
    one (newer last_seen) must still win."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(1)},
            {"name": "engine-a", "last_seen": _now_iso(72)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "pass"


def test_naive_last_seen_does_not_raise_type_error():
    # Defense in depth: if a future v4 response ever omits the timezone
    # offset, the naive datetime would otherwise raise TypeError when
    # compared to the aware threshold. _parse_iso treats naive as UTC.
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": "2026-05-07T00:00:00"}],
    )
    # Should not raise; should classify as either fresh or stale based on
    # the threshold, not crash.
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status in ("pass", "warn")
