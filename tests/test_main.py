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
          configuration_audit: false
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


def _write_basic_auth_config(tmp_path: Path) -> Path:
    """Variant of _write_config with auth_mode: basic."""
    body = textwrap.dedent(f"""
        rapid7:
          base_url: https://acme.hosted.rapid7.com
          verify_tls: true
          request_timeout_seconds: 30
          max_retries: 3
          auth_mode: basic
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
          configuration_audit: false
    """).strip()
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_run_basic_mode_missing_user_returns_startup_exit(tmp_path, monkeypatch):
    cfg = _write_basic_auth_config(tmp_path)
    monkeypatch.delenv("R7_BASIC_USER", raising=False)
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    code = run(["--config", str(cfg)])
    assert code == EXIT_STARTUP


def test_run_basic_mode_missing_password_returns_startup_exit(tmp_path, monkeypatch):
    cfg = _write_basic_auth_config(tmp_path)
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.delenv("R7_BASIC_PASSWORD", raising=False)
    code = run(["--config", str(cfg)])
    assert code == EXIT_STARTUP


def test_run_basic_mode_passes_basic_auth_to_client(tmp_path, monkeypatch):
    cfg = _write_basic_auth_config(tmp_path)
    monkeypatch.setenv("R7_BASIC_USER", "svc")
    monkeypatch.setenv("R7_BASIC_PASSWORD", "pw")
    monkeypatch.delenv("R7_API_KEY", raising=False)

    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        MockClient.return_value.connect.return_value = None
        code = run(["--config", str(cfg)])

    assert code == EXIT_HEALTHY
    _, kwargs = MockClient.call_args
    assert kwargs["api_key"] is None
    assert kwargs["basic_auth"] == ("svc", "pw")


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


def test_run_check_exception_becomes_error_status(tmp_path, monkeypatch):
    # Arrange: enable scan_engines, but force its run() to raise.
    body = textwrap.dedent(f"""
        rapid7:
          base_url: https://us.api.insight.rapid7.com
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
          scan_engines: true
          scan_activity: false
          asset_coverage: false
          data_quality: false
          configuration_audit: false
    """).strip()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("R7_API_KEY", "k")

    def boom(self, client, config):
        raise RuntimeError("simulated check failure")

    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient, \
         patch(
             "rapid7_healthcheck.__main__.ScanEnginesCheck.run",
             new=boom,
         ):
        MockClient.return_value.connect.return_value = None
        out_path = tmp_path / "out.html"
        code = run(["--config", str(cfg), "--output", str(out_path)])

    # Status was "error" → exit code is EXIT_FAIL (per pick_exit_code).
    assert code == EXIT_FAIL
    html = out_path.read_text(encoding="utf-8")
    assert "ERROR" in html  # status badge
    assert "simulated check failure" in html


def test_api_key_never_leaks_to_stderr_or_report(tmp_path, monkeypatch, caplog):
    """Whatever the run does, the API key must not end up in logs or the rendered HTML.

    This is a guardrail: the value goes into `Rapid7Client._headers["X-Api-Key"]` and
    nowhere else by design. If a future change starts logging request bodies/URLs/headers
    or stuffs the key into the report context, this test will catch it.
    """
    secret = "supersecretapikey-zZyx123-DO-NOT-LEAK"

    body = textwrap.dedent(f"""
        rapid7:
          base_url: https://us.api.insight.rapid7.com
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
          configuration_audit: false
    """).strip()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("R7_API_KEY", secret)

    out = tmp_path / "report.html"
    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        MockClient.return_value.connect.return_value = None
        with caplog.at_level("DEBUG", logger="rapid7_healthcheck"):
            code = run(["--config", str(cfg), "--output", str(out), "--verbose"])

    assert code == EXIT_HEALTHY

    # API key must not appear in the rendered report.
    html = out.read_text(encoding="utf-8")
    assert secret not in html, "API key leaked into the HTML report"

    # API key must not appear in any log record (message, args, or formatted output).
    for record in caplog.records:
        assert secret not in record.getMessage(), (
            f"API key leaked into log record: {record.name} {record.levelname}"
        )


def test_run_with_audit_enabled_writes_audit_report(tmp_path, monkeypatch):
    """End-to-end: enable audit + one rule, simulate a passing run, see the audit section appear."""
    body = textwrap.dedent(f"""
        rapid7:
          base_url: https://us.api.insight.rapid7.com
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
          configuration_audit: true
        audit:
          enabled: true
          full_scan: false
          sample_size: 500
          rules:
            agent_unauth_collision:
              enabled: false
              severity: fail
            site_vuln_template_no_creds:
              enabled: true
              severity: fail
            credential_failure_in_recent_scans:
              enabled: false
              severity: warn
            overlapping_scan_windows:
              enabled: false
              severity: warn
            single_engine_overload:
              enabled: false
              severity: warn
            discovery_template_on_prod_site:
              enabled: false
              severity: warn
            policy_and_vuln_in_same_template:
              enabled: false
              severity: warn
            store_invulnerable_results:
              enabled: false
              severity: info
    """).strip()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("R7_API_KEY", "k")

    out_path = tmp_path / "out.html"
    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        instance = MockClient.return_value
        instance.connect.return_value = None
        instance.paginate.side_effect = lambda path, **kw: iter([])
        instance.get.side_effect = lambda path, **kw: {"resources": [], "page": {"totalResources": 0}}
        code = run(["--config", str(cfg), "--output", str(out_path)])

    assert code == EXIT_HEALTHY
    html = out_path.read_text(encoding="utf-8")
    assert "Configuration Audit" in html
    assert "Vulnerability Template Without Credentials" in html
