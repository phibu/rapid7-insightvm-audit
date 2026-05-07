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
