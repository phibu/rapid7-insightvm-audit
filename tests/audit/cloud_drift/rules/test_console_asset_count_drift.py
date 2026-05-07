from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift.rules.console_asset_count_drift import (
    ConsoleAssetCountDriftRule,
)


def _snapshot(*, console_total: int, cloud_total: int) -> MagicMock:
    s = MagicMock()
    s.console_assets_total.return_value = console_total
    s.cloud_assets_total.return_value = cloud_total
    return s


def test_within_tolerance_passes():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1020)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["console_total"] == 1000
    assert result.summary["cloud_total"] == 1020


def test_outside_tolerance_warns():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "drift" in result.findings[0].message.lower()


def test_console_zero_cloud_nonzero_fails():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=0, cloud_total=500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "fail"
    assert result.findings[0].severity == "fail"
    assert "sync" in result.findings[0].message.lower() or "broken" in result.findings[0].message.lower()


def test_cloud_zero_console_nonzero_fails():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=500, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "fail"
    assert result.findings[0].severity == "fail"


def test_both_zero_passes():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=0, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "pass"


def test_default_tolerance_is_5_percent():
    rule = ConsoleAssetCountDriftRule()
    # 4% diff -> pass; 6% diff -> warn (with default tolerance of 5)
    snap_pass = _snapshot(console_total=1000, cloud_total=1040)
    snap_warn = _snapshot(console_total=1000, cloud_total=1060)
    assert rule.run(snap_pass, "warn", False, 500, {}).status == "pass"
    assert rule.run(snap_warn, "warn", False, 500, {}).status == "warn"


def test_summary_includes_drift_percent():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    # |1000 - 1500| / max(1000, 1500) * 100 = 33.33%
    assert pytest.approx(result.summary["drift_percent"], abs=0.01) == 33.33


def test_summary_drift_percent_none_when_both_zero():
    # drift_percent is meaningless when there are no assets on either side;
    # the summary surfaces None rather than misleadingly reporting 0.0.
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=0, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {})
    assert result.summary["drift_percent"] is None


def test_summary_drift_percent_none_on_broken_sync():
    # Same: the broken-sync path's "drift" is undefined, not 0.0.
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=500, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {})
    assert result.summary["drift_percent"] is None


def test_rule_is_registered():
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    assert "cd.console_asset_count_drift" in _CLOUD_RULE_REGISTRY
