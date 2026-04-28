from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from rapid7_healthcheck.__main__ import (
    EXIT_FAIL,
    EXIT_HEALTHY,
    EXIT_STARTUP,
    EXIT_WARN,
    build_thresholds_table,
    pick_exit_code,
    run,
)
from rapid7_healthcheck.checks import CheckResult


def _write_config(tmp_path: Path, base_url: str = "https://us.api.insight.rapid7.com") -> Path:
    body = textwrap.dedent(f"""
        rapid7:
          base_url: {base_url}
          verify_tls: true
          request_timeout_seconds: 30
          max_retries: 3
        report:
          output_dir: {tmp_path / "reports"}
          filename_pattern: "rapid7-health-{{timestamp}}.html"
          title: "T"
        thresholds:
          scan_engines:
            last_contact_warn_hours: 2
            last_contact_fail_hours: 24
          scan_activity:
            recent_window_days: 7
            stuck_scan_hours: 24
            site_no_scan_days: 14
          asset_coverage:
            stale_asset_days: 30
            flag_unscanned_assets: true
          data_quality:
            flag_missing_os: true
            flag_empty_sites: true
        checks:
          scan_engines: false
          scan_activity: false
          asset_coverage: false
          data_quality: false
    """).strip()
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_pick_exit_code_healthy():
    assert pick_exit_code([CheckResult(name="x", description="d", status="pass")]) == EXIT_HEALTHY


def test_pick_exit_code_warn():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="warn"),
        CheckResult(name="y", description="d", status="pass"),
    ]) == EXIT_WARN


def test_pick_exit_code_fail():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="fail"),
    ]) == EXIT_FAIL


def test_pick_exit_code_error_treated_as_fail():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="error", error="boom"),
    ]) == EXIT_FAIL


def test_run_missing_api_key_returns_startup_exit(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.delenv("R7_API_KEY", raising=False)
    code = run(["--config", str(cfg)])
    assert code == EXIT_STARTUP


def test_run_with_all_checks_disabled_writes_skipped_report(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("R7_API_KEY", "k")

    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        instance = MockClient.return_value
        instance.connect.return_value = None
        code = run(["--config", str(cfg)])

    assert code == EXIT_HEALTHY
    reports = list((tmp_path / "reports").glob("rapid7-health-*.html"))
    assert len(reports) == 1
    html = reports[0].read_text(encoding="utf-8")
    assert "SKIPPED" in html


def test_run_explicit_output_path(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("R7_API_KEY", "k")
    out = tmp_path / "fixed.html"
    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        MockClient.return_value.connect.return_value = None
        code = run(["--config", str(cfg), "--output", str(out)])
    assert code == EXIT_HEALTHY
    assert out.exists()


def test_run_bad_config_returns_startup_exit(tmp_path, monkeypatch):
    bad = tmp_path / "missing.yaml"
    monkeypatch.setenv("R7_API_KEY", "k")
    code = run(["--config", str(bad)])
    assert code == EXIT_STARTUP


def test_build_thresholds_table_includes_all_keys():
    from rapid7_healthcheck.config import (
        AppConfig, AssetCoverageThresholds, DataQualityThresholds,
        Rapid7Config, ReportConfig, ScanActivityThresholds,
        ScanEngineThresholds, Thresholds,
    )
    cfg = AppConfig(
        rapid7=Rapid7Config(base_url="https://x", verify_tls=True, request_timeout_seconds=30, max_retries=3),
        report=ReportConfig(output_dir=".", filename_pattern="x", title="t"),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(2, 24),
            scan_activity=ScanActivityThresholds(7, 24, 14),
            asset_coverage=AssetCoverageThresholds(30, True),
            data_quality=DataQualityThresholds(True, True),
        ),
        checks={"scan_engines": True, "scan_activity": True, "asset_coverage": True, "data_quality": True},
    )
    table = build_thresholds_table(cfg)
    keys = [k for k, _ in table]
    assert "scan_engines.last_contact_warn_hours" in keys
    assert "asset_coverage.stale_asset_days" in keys
    assert "data_quality.flag_empty_sites" in keys
