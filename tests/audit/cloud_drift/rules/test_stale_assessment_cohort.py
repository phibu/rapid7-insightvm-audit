from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift.rules.stale_assessment_cohort import (
    StaleAssessmentCohortRule,
)


def _snapshot(*, total: int, stale: int) -> MagicMock:
    s = MagicMock()
    s.cloud_assets_total.return_value = total
    s.cloud_assets_stale.return_value = stale
    return s


def test_no_stale_passes():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=0)
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "pass"


def test_below_percent_threshold_passes():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=50)  # 5%
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "pass"


def test_above_percent_threshold_warns():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=200)  # 20%
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "warn"
    assert "20" in result.findings[0].message  # the percent shows up in the message


def test_above_count_threshold_warns():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=10000, stale=600)  # 6% — under default percent threshold
    result = rule.run(
        snap, "warn", False, 500,
        {"stale_after_days": 30, "max_stale_percent": 10, "max_stale_count": 500},
    )
    assert result.status == "warn"


def test_max_stale_count_null_ignored():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=10000, stale=200)  # 2%
    result = rule.run(
        snap, "warn", False, 500,
        {"stale_after_days": 30, "max_stale_percent": 10, "max_stale_count": None},
    )
    assert result.status == "pass"


def test_total_zero_passes_without_division_error():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=0, stale=0)
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "pass"
    assert result.summary["stale_percent"] == 0.0


def test_summary_includes_stale_percent():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=250)
    result = rule.run(snap, "warn", False, 500, {})
    assert pytest.approx(result.summary["stale_percent"]) == 25.0
    assert result.summary["stale_count"] == 250
    assert result.summary["total_count"] == 1000


def test_threshold_datetime_passed_to_snapshot():
    """stale_after_days must be converted to a UTC datetime threshold."""
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=100, stale=0)
    rule.run(snap, "warn", False, 500, {"stale_after_days": 30})
    args, kwargs = snap.cloud_assets_stale.call_args
    threshold = args[0] if args else kwargs["since"]
    # threshold should be ~30 days ago, not "today" — sanity check the math
    from datetime import datetime, timezone, timedelta
    expected = datetime.now(timezone.utc) - timedelta(days=30)
    assert abs((threshold - expected).total_seconds()) < 60


def test_rule_is_registered():
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    assert "cd.stale_assessment_cohort" in _CLOUD_RULE_REGISTRY
