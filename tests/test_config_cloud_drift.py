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


def _minimal_root_yaml() -> dict:
    """Minimal YAML root that satisfies the required AppConfig fields."""
    return {
        "rapid7": {
            "base_url": "https://console.example/",
            "verify_tls": True,
            "request_timeout_seconds": 30,
            "max_retries": 3,
        },
        "report": {
            "output_dir": "reports",
            "filename_pattern": "r-{timestamp}.html",
            "title": "t",
        },
        "thresholds": {
            "scan_engines": {"last_contact_warn_hours": 4, "last_contact_fail_hours": 24},
            "scan_activity": {"recent_window_days": 14, "stuck_scan_hours": 24, "site_no_scan_days": 30},
            "asset_coverage": {"stale_asset_days": 30, "flag_unscanned_assets": True, "never_scanned_days": 90},
            "data_quality": {"flag_missing_os": True, "flag_empty_sites": True},
        },
        "checks": {},
    }


def test_app_config_propagates_cloud_drift_through_build_app_config():
    # Regression: cloud_drift was computed but not threaded into AppConfig(...).
    # This test fails fast if the wiring breaks again.
    from rapid7_healthcheck.config import _build_app_config

    root = _minimal_root_yaml()
    root["cloud_drift"] = {
        "rules": {
            "cd.console_asset_count_drift": {
                "enabled": True,
                "severity": "warn",
                "tolerance_percent": 7,
            },
        },
    }
    cfg = _build_app_config(root)
    assert "cd.console_asset_count_drift" in cfg.cloud_drift.rules
    assert cfg.cloud_drift.rules["cd.console_asset_count_drift"].knobs["tolerance_percent"] == 7


def test_app_config_default_cloud_drift_when_block_absent():
    from rapid7_healthcheck.config import _build_app_config

    cfg = _build_app_config(_minimal_root_yaml())
    assert cfg.cloud_drift.rules == {}
    # Default-on behavior for the cloud_drift_audit check entry too.
    assert cfg.checks.get("cloud_drift_audit") is True
