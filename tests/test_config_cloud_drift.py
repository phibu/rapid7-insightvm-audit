from __future__ import annotations

import pytest

from rapid7_healthcheck.config import (
    CloudDriftConfig,
    ConfigError,
    _build_cloud_drift_config,
)


def test_default_when_section_missing():
    cfg = _build_cloud_drift_config(None)
    assert isinstance(cfg, CloudDriftConfig)
    assert cfg.rules == {}


def test_full_block_parses_three_rules():
    cfg = _build_cloud_drift_config({
        "rules": {
            "cd.console_asset_count_drift": {
                "enabled": True,
                "severity": "warn",
                "tolerance_percent": 5,
            },
            "cd.scan_engine_cloud_registration": {
                "enabled": True,
                "severity": "warn",
                "last_seen_max_age_hours": 24,
                "ignore_engines": ["lab-engine"],
            },
            "cd.stale_assessment_cohort": {
                "enabled": True,
                "severity": "warn",
                "stale_after_days": 30,
                "max_stale_percent": 10,
                "max_stale_count": None,
            },
        },
    })
    assert set(cfg.rules.keys()) == {
        "cd.console_asset_count_drift",
        "cd.scan_engine_cloud_registration",
        "cd.stale_assessment_cohort",
    }
    drift = cfg.rules["cd.console_asset_count_drift"]
    assert drift.enabled is True
    assert drift.severity == "warn"
    assert drift.knobs["tolerance_percent"] == 5


def test_unknown_rule_id_rejected():
    with pytest.raises(ConfigError, match="unknown rule id"):
        _build_cloud_drift_config({
            "rules": {"cd.bogus": {"enabled": True, "severity": "warn"}},
        })


def test_invalid_severity_rejected():
    with pytest.raises(ConfigError, match="severity"):
        _build_cloud_drift_config({
            "rules": {
                "cd.console_asset_count_drift": {
                    "enabled": True, "severity": "critical",
                },
            },
        })


def test_unknown_top_level_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        _build_cloud_drift_config({"rules": {}, "wat": True})
