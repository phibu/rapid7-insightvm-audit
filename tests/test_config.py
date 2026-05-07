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
        never_scanned_days: 90
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


def test_asset_coverage_thresholds_have_new_toggles_with_defaults(tmp_path):
    """The asset-coverage toggles are optional with sensible defaults."""
    cfg = load_config(write(tmp_path, VALID_YAML))
    ac = cfg.thresholds.asset_coverage
    assert ac.flag_dead_asset_groups is True
    assert ac.flag_agent_only_assets is False


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


# --- delta_max_age_days tests -------------------------------------------

# Minimal valid config with `report:` block last so appending a line
# like "  delta_max_age_days: null\n" lands as a sibling key inside report:.
_MINIMAL_CONFIG_TEXT = textwrap.dedent("""\
    rapid7:
      base_url: https://us.api.insight.rapid7.com
      verify_tls: true
      request_timeout_seconds: 30
      max_retries: 3
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
        never_scanned_days: 90
      data_quality:
        flag_missing_os: true
        flag_empty_sites: true
    checks:
      scan_engines: true
      scan_activity: true
      asset_coverage: true
      data_quality: true
    report:
      output_dir: ./reports
      filename_pattern: "rapid7-health-{timestamp}.html"
      title: "Test"
""")


def test_report_delta_max_age_days_defaults_to_30(tmp_path):
    """Existing configs without delta_max_age_days still load, defaulting to 30."""
    p = tmp_path / "c.yaml"
    p.write_text(_MINIMAL_CONFIG_TEXT, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.report.delta_max_age_days == 30


def test_report_delta_max_age_days_can_be_disabled(tmp_path):
    """delta_max_age_days: null disables delta (loads as None)."""
    cfg_text = _MINIMAL_CONFIG_TEXT + "  delta_max_age_days: null\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.report.delta_max_age_days is None


def test_report_rejects_unknown_key(tmp_path):
    """Unknown keys under report: raise ConfigError."""
    cfg_text = _MINIMAL_CONFIG_TEXT + "  bogus: 1\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(p)


def test_report_rejects_negative_delta(tmp_path):
    """delta_max_age_days must be non-negative or null."""
    cfg_text = _MINIMAL_CONFIG_TEXT + "  delta_max_age_days: -1\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    with pytest.raises(ConfigError, match="non-negative"):
        load_config(p)


# --- user_audit block ---------------------------------------------------

USER_AUDIT_BLOCK = textwrap.dedent("""
    user_audit:
      enabled: true
      full_scan: false
      sample_size: 500
      rules:
        privileged_user_without_mfa:
          enabled: true
          severity: fail
          mfa_exempt_logins: ["healthcheck-svc"]
        local_account_when_sso_configured:
          enabled: true
          severity: warn
          max_local_accounts_when_sso: 2
        multiple_global_administrators:
          enabled: true
          severity: warn
        locked_user_account:
          enabled: true
          severity: warn
        disabled_user_with_role_bindings:
          enabled: true
          severity: info
        user_with_role_but_no_access:
          enabled: true
          severity: info
        superuser_flag_outside_global_admin:
          enabled: true
          severity: fail
""")


def test_user_audit_block_defaults_disabled_when_missing(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.user_audit.enabled is False
    assert cfg.user_audit.rules == {}


def test_user_audit_block_loads(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML + USER_AUDIT_BLOCK))
    assert cfg.user_audit.enabled is True
    assert cfg.user_audit.full_scan is False
    assert cfg.user_audit.sample_size == 500
    mfa = cfg.user_audit.rules["privileged_user_without_mfa"]
    assert mfa.enabled is True
    assert mfa.severity == "fail"
    assert mfa.knobs["mfa_exempt_logins"] == ["healthcheck-svc"]
    sso = cfg.user_audit.rules["local_account_when_sso_configured"]
    assert sso.knobs["max_local_accounts_when_sso"] == 2


def test_user_audit_unknown_rule_id_raises(tmp_path):
    body = (VALID_YAML + USER_AUDIT_BLOCK).replace(
        "privileged_user_without_mfa:",
        "not_a_real_rule:",
        1,
    )
    with pytest.raises(ConfigError, match="not_a_real_rule"):
        load_config(write(tmp_path, body))


def test_user_audit_invalid_severity_raises(tmp_path):
    body = (VALID_YAML + USER_AUDIT_BLOCK).replace(
        "severity: fail",
        "severity: catastrophic",
        1,
    )
    with pytest.raises(ConfigError, match="severity"):
        load_config(write(tmp_path, body))


def test_user_permission_audit_check_toggle_default_true(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.checks["user_permission_audit"] is True


def _yaml_with_rapid7_extras(*, parallel_pages: int | None = None, page_size: int | None = None) -> str:
    """Inject parallel_pages / page_size into the rapid7: block of VALID_YAML."""
    extras = []
    if parallel_pages is not None:
        extras.append(f"  parallel_pages: {parallel_pages}")
    if page_size is not None:
        extras.append(f"  page_size: {page_size}")
    if not extras:
        return VALID_YAML
    insertion = "\n".join(extras) + "\n"
    return VALID_YAML.replace(
        "  max_retries: 3\n",
        f"  max_retries: 3\n{insertion}",
    )


def test_rapid7_parallel_pages_default_is_one(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.rapid7.parallel_pages == 1


def test_rapid7_parallel_pages_accepts_six(tmp_path):
    body = _yaml_with_rapid7_extras(parallel_pages=6)
    cfg = load_config(write(tmp_path, body))
    assert cfg.rapid7.parallel_pages == 6


def test_rapid7_parallel_pages_rejects_zero(tmp_path):
    body = _yaml_with_rapid7_extras(parallel_pages=0)
    with pytest.raises(ConfigError, match="parallel_pages"):
        load_config(write(tmp_path, body))


def test_rapid7_parallel_pages_rejects_seventeen(tmp_path):
    body = _yaml_with_rapid7_extras(parallel_pages=17)
    with pytest.raises(ConfigError, match="parallel_pages"):
        load_config(write(tmp_path, body))


def test_rapid7_parallel_pages_nine_warns(tmp_path, caplog):
    """Values >8 are accepted but emit a warning log line."""
    body = _yaml_with_rapid7_extras(parallel_pages=9)
    with caplog.at_level("WARNING"):
        cfg = load_config(write(tmp_path, body))
    assert cfg.rapid7.parallel_pages == 9
    assert any("8-parallel" in r.message for r in caplog.records)


def test_rapid7_page_size_default_is_250(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.rapid7.page_size == 250


def test_rapid7_page_size_rejects_zero(tmp_path):
    body = _yaml_with_rapid7_extras(page_size=0)
    with pytest.raises(ConfigError, match="page_size"):
        load_config(write(tmp_path, body))


def test_rapid7_page_size_rejects_501(tmp_path):
    body = _yaml_with_rapid7_extras(page_size=501)
    with pytest.raises(ConfigError, match="page_size"):
        load_config(write(tmp_path, body))


def _yaml_with_dead_groups_cap(cap_value) -> str:
    """Insert dead_groups_fallback_cap into asset_coverage block of VALID_YAML."""
    insertion = f"    dead_groups_fallback_cap: {cap_value}\n"
    return VALID_YAML.replace(
        "    never_scanned_days: 90\n",
        "    never_scanned_days: 90\n" + insertion,
    )


def test_dead_groups_fallback_cap_zero_disables_fallback(tmp_path):
    """cap=0 is documented as 'disable fallback'; YAML->config must accept it."""
    body = _yaml_with_dead_groups_cap(0)
    cfg = load_config(write(tmp_path, body))
    assert cfg.thresholds.asset_coverage.dead_groups_fallback_cap == 0


def test_dead_groups_fallback_cap_negative_rejected(tmp_path):
    body = _yaml_with_dead_groups_cap(-1)
    with pytest.raises(ConfigError, match="dead_groups_fallback_cap"):
        load_config(write(tmp_path, body))


def test_dead_groups_fallback_cap_positive_accepted(tmp_path):
    body = _yaml_with_dead_groups_cap(200)
    cfg = load_config(write(tmp_path, body))
    assert cfg.thresholds.asset_coverage.dead_groups_fallback_cap == 200


def _yaml_with_duplicate_detection_max_assets(value) -> str:
    """Insert duplicate_detection_max_assets into data_quality block of VALID_YAML.

    `value` is rendered verbatim so callers can pass non-int YAML scalars
    (e.g. the literal string '"fifty thousand"') for negative-path tests.
    """
    insertion = f"    duplicate_detection_max_assets: {value}\n"
    return VALID_YAML.replace(
        "    flag_empty_sites: true\n",
        "    flag_empty_sites: true\n" + insertion,
    )


def test_data_quality_default_duplicate_detection_max_assets(tmp_path):
    """Default value should be 50000 when key is absent from YAML."""
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.thresholds.data_quality.duplicate_detection_max_assets == 50000


def test_data_quality_duplicate_detection_max_assets_zero_accepted(tmp_path):
    """Zero is the 'always skip' sentinel and must be accepted."""
    body = _yaml_with_duplicate_detection_max_assets(0)
    cfg = load_config(write(tmp_path, body))
    assert cfg.thresholds.data_quality.duplicate_detection_max_assets == 0


def test_data_quality_duplicate_detection_max_assets_negative_rejected(tmp_path):
    """Negative values must be rejected with a clear error."""
    body = _yaml_with_duplicate_detection_max_assets(-1)
    with pytest.raises(ConfigError, match="must be a non-negative integer"):
        load_config(write(tmp_path, body))


def test_data_quality_duplicate_detection_max_assets_non_int_rejected(tmp_path):
    """A string value must be rejected."""
    body = _yaml_with_duplicate_detection_max_assets('"fifty thousand"')
    with pytest.raises(ConfigError, match="expected int, got"):
        load_config(write(tmp_path, body))


def test_data_quality_duplicate_detection_max_assets_positive_accepted(tmp_path):
    """A non-default positive value round-trips through the validator (re-attach path)."""
    body = _yaml_with_duplicate_detection_max_assets(100000)
    cfg = load_config(write(tmp_path, body))
    assert cfg.thresholds.data_quality.duplicate_detection_max_assets == 100000


def test_report_log_format_defaults_to_plain(tmp_path):
    """When report.log_format is absent, default is 'plain'."""
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.report.log_format == "plain"


@pytest.mark.parametrize("value", ["plain", "cmtrace", "json"])
def test_report_log_format_accepts_valid_values(tmp_path, value):
    body = VALID_YAML.replace(
        'title: "Rapid7 InsightVM Environment Health Check"',
        f'title: "Rapid7 InsightVM Environment Health Check"\n  log_format: {value}',
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.report.log_format == value


def test_report_log_format_rejects_unknown_value(tmp_path):
    body = VALID_YAML.replace(
        'title: "Rapid7 InsightVM Environment Health Check"',
        'title: "Rapid7 InsightVM Environment Health Check"\n  log_format: yaml',
    )
    with pytest.raises(ConfigError, match="report.log_format"):
        load_config(write(tmp_path, body))


def test_audit_agents_timeout_seconds_defaults_to_180():
    """audit.agents_timeout_seconds defaults to 180 when omitted."""
    from rapid7_healthcheck.config import _build_audit_config
    cfg = _build_audit_config({
        "enabled": True,
        "full_scan": False,
        "sample_size": 500,
        "rules": {},
    })
    assert cfg.agents_timeout_seconds == 180


def test_audit_agents_timeout_seconds_custom_value():
    """audit.agents_timeout_seconds accepts a positive int."""
    from rapid7_healthcheck.config import _build_audit_config
    cfg = _build_audit_config({
        "enabled": True,
        "full_scan": False,
        "sample_size": 500,
        "agents_timeout_seconds": 300,
        "rules": {},
    })
    assert cfg.agents_timeout_seconds == 300


def test_audit_agents_timeout_seconds_rejects_zero():
    from rapid7_healthcheck.config import _build_audit_config
    with pytest.raises(ConfigError, match="agents_timeout_seconds"):
        _build_audit_config({
            "enabled": True, "full_scan": False, "sample_size": 500,
            "agents_timeout_seconds": 0, "rules": {},
        })


def test_audit_agents_timeout_seconds_rejects_negative():
    from rapid7_healthcheck.config import _build_audit_config
    with pytest.raises(ConfigError, match="agents_timeout_seconds"):
        _build_audit_config({
            "enabled": True, "full_scan": False, "sample_size": 500,
            "agents_timeout_seconds": -5, "rules": {},
        })


def test_audit_agents_timeout_seconds_rejects_non_int():
    from rapid7_healthcheck.config import _build_audit_config
    with pytest.raises(ConfigError, match="agents_timeout_seconds"):
        _build_audit_config({
            "enabled": True, "full_scan": False, "sample_size": 500,
            "agents_timeout_seconds": "180", "rules": {},
        })


def test_audit_agents_timeout_seconds_rejects_bool():
    """bool is a subclass of int; reject it explicitly like sample_size does."""
    from rapid7_healthcheck.config import _build_audit_config
    with pytest.raises(ConfigError, match="agents_timeout_seconds"):
        _build_audit_config({
            "enabled": True, "full_scan": False, "sample_size": 500,
            "agents_timeout_seconds": True, "rules": {},
        })
