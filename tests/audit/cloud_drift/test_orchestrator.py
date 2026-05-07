from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift import CloudDriftAuditCheck
from rapid7_healthcheck.config import (
    AppConfig,
    CloudDriftConfig,
    CloudIntegrationConfig,
    Rapid7Config,
    ReportConfig,
    RuleConfig,
    Thresholds,
    AssetCoverageThresholds,
    DataQualityThresholds,
    ScanActivityThresholds,
    ScanEngineThresholds,
)


def _minimal_thresholds() -> Thresholds:
    return Thresholds(
        scan_engines=ScanEngineThresholds(last_contact_warn_hours=4, last_contact_fail_hours=24),
        scan_activity=ScanActivityThresholds(recent_window_days=14, stuck_scan_hours=24, site_no_scan_days=30),
        asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=True, never_scanned_days=90),
        data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=True),
    )


def _config(*, cloud_enabled: bool, rules_enabled: bool = True) -> AppConfig:
    return AppConfig(
        rapid7=Rapid7Config(
            base_url="https://console.example/",
            verify_tls=True,
            request_timeout_seconds=30,
            max_retries=3,
        ),
        report=ReportConfig(output_dir="reports", filename_pattern="r-{timestamp}.html", title="t"),
        thresholds=_minimal_thresholds(),
        checks={"cloud_drift_audit": True},
        cloud_integration=CloudIntegrationConfig(
            enabled=cloud_enabled,
            base_url="https://us.api.insight.rapid7.com/vm/" if cloud_enabled else "",
            api_key_env="R7_CLOUD_API_KEY",
            timeout_seconds=30,
            max_retries=3,
            parallel_pages=1,
        ),
        cloud_drift=CloudDriftConfig(rules={
            "cd.console_asset_count_drift": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
            "cd.scan_engine_cloud_registration": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
            "cd.stale_assessment_cohort": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
        }),
    )


def test_skipped_when_cloud_integration_disabled():
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=False)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=None)
    assert result.status == "skipped"
    assert "cloud_integration" in result.summary["reason"]
    assert result.rule_results == []


def test_skipped_when_cloud_client_is_none_even_if_enabled():
    """Defense in depth: orchestrator never builds a snapshot without both clients."""
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=None)
    assert result.status == "skipped"


def test_runs_three_rules_when_enabled(monkeypatch):
    from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot

    # Stub each accessor to return safe values so all three rules pass.
    monkeypatch.setattr(CloudSnapshot, "console_assets_total", lambda self: 1000)
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_total", lambda self: 1000)
    monkeypatch.setattr(CloudSnapshot, "console_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_stale", lambda self, since: 0)

    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    assert result.status == "pass"
    assert result.rule_results is not None
    assert len(result.rule_results) == 3
    assert {r.rule_id for r in result.rule_results} == {
        "cd.console_asset_count_drift",
        "cd.scan_engine_cloud_registration",
        "cd.stale_assessment_cohort",
    }


def test_disabled_rules_appear_as_skipped(monkeypatch):
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True, rules_enabled=False)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    assert result.status == "pass"  # all skipped → pass
    assert all(r.status == "skipped" for r in result.rule_results)


def test_rule_exception_isolated(monkeypatch):
    from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot

    def _raise_boom(self):
        raise RuntimeError("boom")

    monkeypatch.setattr(CloudSnapshot, "console_assets_total", _raise_boom)
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_total", lambda self: 0)
    monkeypatch.setattr(CloudSnapshot, "console_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_stale", lambda self, since: 0)

    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    # The drift rule errors; the other two still run.
    drift = next(r for r in result.rule_results if r.rule_id == "cd.console_asset_count_drift")
    assert drift.status == "error"
    assert "boom" in drift.error
    others = [r for r in result.rule_results if r.rule_id != "cd.console_asset_count_drift"]
    assert all(r.status == "pass" for r in others)
    # Whole check rolls up to fail because one rule errored.
    assert result.status == "fail"
