import textwrap
from pathlib import Path

import pytest

from rapid7_healthcheck.config import AppConfig, ConfigError, load_config


VALID_YAML = textwrap.dedent("""
    rapid7:
      base_url: https://us.api.insight.rapid7.com
      verify_tls: true
      request_timeout_seconds: 30
      max_retries: 3
    report:
      output_dir: ./reports
      filename_pattern: "rapid7-health-{timestamp}.html"
      title: "Rapid7 InsightVM Environment Health Check"
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
      scan_activity: true
      asset_coverage: true
      data_quality: true
""")


def write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_config_returns_typed_appconfig(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert isinstance(cfg, AppConfig)
    assert cfg.rapid7.base_url == "https://us.api.insight.rapid7.com"
    assert cfg.rapid7.verify_tls is True
    assert cfg.rapid7.request_timeout_seconds == 30
    assert cfg.rapid7.max_retries == 3
    assert cfg.report.output_dir == "./reports"
    assert cfg.thresholds.scan_engines.last_contact_warn_hours == 2
    assert cfg.thresholds.asset_coverage.flag_unscanned_assets is True
    assert cfg.checks["scan_engines"] is True


def test_unknown_key_raises(tmp_path):
    body = VALID_YAML + "\nunexpected_root: 1\n"
    with pytest.raises(ConfigError, match="unknown"):
        load_config(write(tmp_path, body))


def test_missing_required_section_raises(tmp_path):
    body = VALID_YAML.replace("rapid7:", "wrong_name:")
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, body))


def test_base_url_must_be_https(tmp_path):
    body = VALID_YAML.replace(
        "https://us.api.insight.rapid7.com",
        "http://us.api.insight.rapid7.com",
    )
    with pytest.raises(ConfigError, match="https"):
        load_config(write(tmp_path, body))


def test_unknown_nested_key_raises(tmp_path):
    body = VALID_YAML.replace(
        "verify_tls: true",
        "verify_tls: true\n  bogus: 1",
    )
    with pytest.raises(ConfigError, match="unknown"):
        load_config(write(tmp_path, body))


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.yaml")


def test_int_field_rejects_string(tmp_path):
    body = VALID_YAML.replace("request_timeout_seconds: 30", "request_timeout_seconds: \"thirty\"")
    with pytest.raises(ConfigError, match="request_timeout_seconds"):
        load_config(write(tmp_path, body))


def test_int_field_rejects_bool(tmp_path):
    body = VALID_YAML.replace("request_timeout_seconds: 30", "request_timeout_seconds: true")
    with pytest.raises(ConfigError, match="request_timeout_seconds"):
        load_config(write(tmp_path, body))


def test_bool_field_rejects_string(tmp_path):
    body = VALID_YAML.replace("verify_tls: true", "verify_tls: \"yes\"")
    with pytest.raises(ConfigError, match="verify_tls"):
        load_config(write(tmp_path, body))


def test_str_field_rejects_int(tmp_path):
    body = VALID_YAML.replace("title: \"Rapid7 InsightVM Environment Health Check\"", "title: 42")
    with pytest.raises(ConfigError, match="title"):
        load_config(write(tmp_path, body))


def test_negative_int_rejected(tmp_path):
    body = VALID_YAML.replace("last_contact_warn_hours: 2", "last_contact_warn_hours: -1")
    with pytest.raises(ConfigError, match="last_contact_warn_hours"):
        load_config(write(tmp_path, body))


def test_zero_int_rejected(tmp_path):
    body = VALID_YAML.replace("recent_window_days: 7", "recent_window_days: 0")
    with pytest.raises(ConfigError, match="recent_window_days"):
        load_config(write(tmp_path, body))


def test_base_url_whitespace_stripped(tmp_path):
    body = VALID_YAML.replace(
        "https://us.api.insight.rapid7.com",
        "  https://us.api.insight.rapid7.com  ",
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.rapid7.base_url == "https://us.api.insight.rapid7.com"


def test_checks_value_must_be_bool(tmp_path):
    # Existing behavior should continue to reject non-bool checks values
    body = VALID_YAML.replace("scan_engines: true\n  scan_activity: true", "scan_engines: 1\n  scan_activity: true")
    with pytest.raises(ConfigError, match="checks"):
        load_config(write(tmp_path, body))


AUDIT_BLOCK = textwrap.dedent("""
    audit:
      enabled: true
      full_scan: false
      sample_size: 500
      rules:
        agent_unauth_collision:
          enabled: true
          severity: fail
        site_vuln_template_no_creds:
          enabled: true
          severity: fail
        credential_failure_in_recent_scans:
          enabled: true
          severity: warn
        overlapping_scan_windows:
          enabled: true
          severity: warn
        single_engine_overload:
          enabled: true
          severity: warn
          asset_count_threshold: 5000
        discovery_template_on_prod_site:
          enabled: true
          severity: warn
        policy_and_vuln_in_same_template:
          enabled: true
          severity: warn
        store_invulnerable_results:
          enabled: true
          severity: info
""")


def _yaml_with_audit(checks_audit: bool = True) -> str:
    body = VALID_YAML
    body = body.replace(
        "  data_quality: true",
        "  data_quality: true\n  configuration_audit: " + ("true" if checks_audit else "false"),
    )
    return body + AUDIT_BLOCK


def test_audit_config_loads(tmp_path):
    cfg = load_config(write(tmp_path, _yaml_with_audit()))
    assert cfg.audit.enabled is True
    assert cfg.audit.full_scan is False
    assert cfg.audit.sample_size == 500
    assert cfg.audit.rules["agent_unauth_collision"].enabled is True
    assert cfg.audit.rules["agent_unauth_collision"].severity == "fail"
    assert cfg.audit.rules["single_engine_overload"].knobs["asset_count_threshold"] == 5000
    assert cfg.checks["configuration_audit"] is True


def test_audit_unknown_rule_id_raises(tmp_path):
    body = _yaml_with_audit().replace(
        "agent_unauth_collision:",
        "not_a_real_rule:",
        1,
    )
    with pytest.raises(ConfigError, match="not_a_real_rule"):
        load_config(write(tmp_path, body))


def test_audit_invalid_severity_raises(tmp_path):
    body = _yaml_with_audit().replace(
        "severity: fail",
        "severity: catastrophic",
        1,
    )
    with pytest.raises(ConfigError, match="severity"):
        load_config(write(tmp_path, body))


def test_audit_unknown_rule_knobs_silently_ignored(tmp_path):
    body = _yaml_with_audit().replace(
        "asset_count_threshold: 5000",
        "asset_count_threshold: 5000\n      future_knob: 42",
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.audit.rules["single_engine_overload"].knobs["asset_count_threshold"] == 5000
    assert cfg.audit.rules["single_engine_overload"].knobs.get("future_knob") == 42


def test_audit_missing_block_defaults_disabled(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.audit.enabled is False
    assert cfg.audit.rules == {}


def test_checks_configuration_audit_default_when_missing(tmp_path):
    cfg = load_config(write(tmp_path, _yaml_with_audit()))
    assert cfg.checks["configuration_audit"] is True


def test_auth_mode_defaults_to_api_key(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.rapid7.auth_mode == "api_key"


def test_auth_mode_accepts_basic(tmp_path):
    body = VALID_YAML.replace(
        "max_retries: 3",
        "max_retries: 3\n  auth_mode: basic",
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.rapid7.auth_mode == "basic"


def test_auth_mode_rejects_unknown_value(tmp_path):
    body = VALID_YAML.replace(
        "max_retries: 3",
        "max_retries: 3\n  auth_mode: oauth2",
    )
    with pytest.raises(ConfigError, match="auth_mode"):
        load_config(write(tmp_path, body))


def test_auth_mode_rejects_non_string(tmp_path):
    body = VALID_YAML.replace(
        "max_retries: 3",
        "max_retries: 3\n  auth_mode: 42",
    )
    with pytest.raises(ConfigError, match="auth_mode"):
        load_config(write(tmp_path, body))
