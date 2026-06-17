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


# --- template_audit block -----------------------------------------------

def test_template_audit_block_defaults_when_missing(tmp_path):
    """Missing template_audit: block falls back to defaults (enabled=True, empty rules)."""
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.template_audit.enabled is True
    assert cfg.template_audit.full_scan is False
    assert cfg.template_audit.sample_size == 500
    assert cfg.template_audit.rules == {}


def test_template_audit_check_toggle_default_true(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.checks["template_audit"] is True


def test_template_audit_check_can_be_disabled(tmp_path):
    body = VALID_YAML.replace(
        "  data_quality: true\n",
        "  data_quality: true\n  template_audit: false\n",
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.checks["template_audit"] is False


def test_template_audit_unknown_key_raises(tmp_path):
    body = VALID_YAML + textwrap.dedent("""
        template_audit:
          enabled: true
          full_scan: false
          sample_size: 500
          rules: {}
          bogus: 1
    """)
    with pytest.raises(ConfigError, match="template_audit"):
        load_config(write(tmp_path, body))


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


def test_load_audit_rejects_removed_rule_id():
    """Users upgrading from 0.3.6 with the old block must see a clear error.

    Strict-mode validator behavior: any rule id not registered in the audit
    rule registry raises ConfigError at load time. Locks in the hard-break
    upgrade contract from
    0.4.0 — operators removing the deprecated rule from config.yaml will see
    this exact error string in their first 0.4.0 run.
    """
    from rapid7_healthcheck.config import _build_audit_config
    with pytest.raises(ConfigError, match=r"audit\.rules: unknown rule id 'insight_agent_version_currency'"):
        _build_audit_config({
            "enabled": True,
            "full_scan": False,
            "sample_size": 500,
            "agents_timeout_seconds": 180,
            "rules": {
                "insight_agent_version_currency": {"enabled": True, "severity": "warn"},
            },
        })


def test_ensure_default_on_adds_missing_keys():
    """The helper must add missing audit category keys with `True`."""
    from rapid7_healthcheck.config import _ensure_default_on
    checks = {"scan_engines": True}
    result = _ensure_default_on(checks, "configuration_audit", "user_permission_audit")
    assert result["configuration_audit"] is True
    assert result["user_permission_audit"] is True
    assert result["scan_engines"] is True  # existing keys preserved


def test_ensure_default_on_preserves_user_disable():
    """The helper must NEVER overwrite a user-set `False`."""
    from rapid7_healthcheck.config import _ensure_default_on
    checks = {"configuration_audit": False, "scan_engines": True}
    result = _ensure_default_on(checks, "configuration_audit", "user_permission_audit")
    assert result["configuration_audit"] is False  # critical: do not overwrite
    assert result["user_permission_audit"] is True


def test_ensure_default_on_preserves_user_enable():
    """The helper must NOT touch a user-set `True` either."""
    from rapid7_healthcheck.config import _ensure_default_on
    checks = {"configuration_audit": True}
    result = _ensure_default_on(checks, "configuration_audit")
    assert result == {"configuration_audit": True}


def test_ensure_default_on_returns_same_dict_when_no_changes():
    """When every name is already present, return the input dict by identity
    (no copy). The docstring promises this as an optimization; pin it."""
    from rapid7_healthcheck.config import _ensure_default_on
    checks = {"configuration_audit": True, "user_permission_audit": False}
    result = _ensure_default_on(checks, "configuration_audit", "user_permission_audit")
    assert result is checks


# --- _validate_rules_block: the single helper all four audit builders share ---
#
# Previously each of _build_audit_config / _build_user_audit_config /
# _build_cloud_drift_config / _build_template_audit_config carried a private,
# ~95%-identical copy of the rule-validation loop. These exercise the one
# extracted helper directly so the per-builder tests can stay thin.

def test_validate_rules_block_builds_rule_configs():
    from rapid7_healthcheck.config import _validate_rules_block, RuleConfig
    out = _validate_rules_block(
        {"r1": {"enabled": True, "severity": "warn", "foo": 1, "bar": "x"}},
        valid_rule_ids={"r1", "r2"},
        path="audit.rules",
    )
    assert out == {"r1": RuleConfig(enabled=True, severity="warn", knobs={"foo": 1, "bar": "x"})}


def test_validate_rules_block_strips_enabled_and_severity_from_knobs():
    from rapid7_healthcheck.config import _validate_rules_block
    out = _validate_rules_block(
        {"r1": {"enabled": False, "severity": "fail", "threshold": 7}},
        valid_rule_ids={"r1"},
        path="audit.rules",
    )
    assert out["r1"].knobs == {"threshold": 7}
    assert out["r1"].enabled is False
    assert out["r1"].severity == "fail"


def test_validate_rules_block_rejects_unknown_rule_id_with_path_prefix():
    """The path argument prefixes the error so each builder keeps its own
    `audit.rules: ...` / `user_audit.rules: ...` wording verbatim."""
    from rapid7_healthcheck.config import _validate_rules_block
    with pytest.raises(ConfigError, match=r"user_audit\.rules: unknown rule id 'nope'"):
        _validate_rules_block(
            {"nope": {"enabled": True, "severity": "warn"}},
            valid_rule_ids={"r1"},
            path="user_audit.rules",
        )


def test_validate_rules_block_rejects_non_dict_body():
    from rapid7_healthcheck.config import _validate_rules_block
    with pytest.raises(ConfigError, match=r"audit\.rules\.r1: expected mapping"):
        _validate_rules_block(
            {"r1": "not-a-dict"},
            valid_rule_ids={"r1"},
            path="audit.rules",
        )


def test_validate_rules_block_rejects_non_bool_enabled():
    from rapid7_healthcheck.config import _validate_rules_block
    with pytest.raises(ConfigError, match=r"audit\.rules\.r1\.enabled: expected bool"):
        _validate_rules_block(
            {"r1": {"enabled": "yes", "severity": "warn"}},
            valid_rule_ids={"r1"},
            path="audit.rules",
        )


def test_validate_rules_block_rejects_bad_severity():
    from rapid7_healthcheck.config import _validate_rules_block
    with pytest.raises(ConfigError, match=r"audit\.rules\.r1\.severity: must be one of"):
        _validate_rules_block(
            {"r1": {"enabled": True, "severity": "critical"}},
            valid_rule_ids={"r1"},
            path="audit.rules",
        )


def test_validate_rules_block_empty_returns_empty():
    from rapid7_healthcheck.config import _validate_rules_block
    assert _validate_rules_block({}, valid_rule_ids={"r1"}, path="audit.rules") == {}


# --- _registry_rule_ids: valid ids sourced from the live rule registries ---
#
# The four valid-id sets are no longer hand-kept in config.py; they come from
# the @register* decorators via the rule registries. This is the regression
# guard: every registry's keys must be exactly what the validator accepts.

def test_registry_rule_ids_matches_all_four_registries():
    from rapid7_healthcheck.config import _registry_rule_ids
    from rapid7_healthcheck.audit import _RULE_REGISTRY
    from rapid7_healthcheck.audit.user_permission import _USER_RULE_REGISTRY
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    from rapid7_healthcheck.audit.template import _TEMPLATE_RULE_REGISTRY

    audit_ids, user_ids, cloud_ids, template_ids = _registry_rule_ids()
    assert audit_ids == frozenset(_RULE_REGISTRY)
    assert user_ids == frozenset(_USER_RULE_REGISTRY)
    assert cloud_ids == frozenset(_CLOUD_RULE_REGISTRY)
    assert template_ids == frozenset(_TEMPLATE_RULE_REGISTRY)


def test_registry_rule_ids_populates_when_config_imported_first():
    """Import-order safety: even if config is the only thing imported, the
    helper's lazy import of the audit packages must populate the registries
    (rather than returning empty sets, which would reject every real rule id).

    Runs in a clean subprocess so it actually exercises a config-first import
    graph instead of relying on other tests having imported the audit tree.
    """
    import subprocess
    import sys
    code = (
        "import rapid7_healthcheck.config as c;"
        "a,u,cl,t=c._registry_rule_ids();"
        "assert 'agent_unauth_collision' in a, a;"
        "assert 'privileged_user_without_mfa' in u, u;"
        "assert 'cd.console_asset_count_drift' in cl, cl;"
        "assert any(x.startswith('template.') for x in t), t;"
        "print('ok')"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ok"


# ---------------------------------------------------------------------------
# Characterization safety net: int-boundary validation
#
# These tests pin the CURRENT observable validation behavior for every
# zero/negative/bool boundary before the _from_dict collapse refactor
# (Task 1 of refactor/config-from-dict-collapse).  They must remain green
# against the unmodified code; later tasks must keep them green too.
# ---------------------------------------------------------------------------

class TestConfigCharacterization:
    """Parametrized consolidation of int-boundary cases across all builders."""

    # -- rapid7.max_retries -------------------------------------------------
    # _check_scalar(..., int) rejects value <= 0.
    # Error: "rapid7.max_retries: must be a positive integer, got N"

    @pytest.mark.parametrize("value,ok", [(1, True), (3, True), (0, False), (-1, False)])
    def test_char_rapid7_max_retries_boundary(self, tmp_path, value, ok):
        body = VALID_YAML.replace("max_retries: 3", f"max_retries: {value}")
        if ok:
            cfg = load_config(write(tmp_path, body))
            assert cfg.rapid7.max_retries == value
        else:
            with pytest.raises(ConfigError, match="max_retries"):
                load_config(write(tmp_path, body))

    # -- audit.sample_size --------------------------------------------------
    # _build_audit_config rejects value <= 0 and bool values.
    # Error: "audit.sample_size: expected positive int"
    # Called directly (same pattern as test_audit_agents_timeout_seconds_*).

    @pytest.mark.parametrize("value,ok", [(1, True), (500, True), (0, False), (-1, False)])
    def test_char_audit_sample_size_boundary(self, value, ok):
        from rapid7_healthcheck.config import _build_audit_config
        raw = {
            "enabled": True,
            "full_scan": False,
            "sample_size": value,
            "agents_timeout_seconds": 180,
            "rules": {},
        }
        if ok:
            cfg = _build_audit_config(raw)
            assert cfg.sample_size == value
        else:
            with pytest.raises(ConfigError, match="sample_size"):
                _build_audit_config(raw)

    def test_char_audit_sample_size_bool_rejected(self):
        """bool is a subclass of int; must be rejected like 0/-1."""
        from rapid7_healthcheck.config import _build_audit_config
        with pytest.raises(ConfigError, match="sample_size"):
            _build_audit_config({
                "enabled": True,
                "full_scan": False,
                "sample_size": True,
                "agents_timeout_seconds": 180,
                "rules": {},
            })

    # -- user_audit.sample_size ---------------------------------------------
    # _build_user_audit_config rejects value <= 0 and bool values.
    # Error: "user_audit.sample_size: expected positive int"
    # Called directly (same pattern as test_char_audit_sample_size_boundary;
    # user_audit block has NO agents_timeout_seconds).

    @pytest.mark.parametrize("value,ok", [(1, True), (500, True), (0, False), (-1, False)])
    def test_char_user_audit_sample_size_boundary(self, value, ok):
        from rapid7_healthcheck.config import _build_user_audit_config
        raw = {
            "enabled": True,
            "full_scan": False,
            "sample_size": value,
            "rules": {},
        }
        if ok:
            cfg = _build_user_audit_config(raw)
            assert cfg.sample_size == value
        else:
            with pytest.raises(ConfigError, match="sample_size"):
                _build_user_audit_config(raw)

    def test_char_user_audit_sample_size_bool_rejected(self):
        """bool is a subclass of int; must be rejected like 0/-1."""
        from rapid7_healthcheck.config import _build_user_audit_config
        with pytest.raises(ConfigError, match="sample_size"):
            _build_user_audit_config({
                "enabled": True,
                "full_scan": False,
                "sample_size": True,
                "rules": {},
            })

    # -- thresholds.asset_coverage.dead_groups_fallback_cap -----------------
    # 0 is accepted (= disable fallback); negative is rejected.
    # Error: "thresholds.asset_coverage.dead_groups_fallback_cap: must be a non-negative integer"

    @pytest.mark.parametrize("value,ok", [(0, True), (5, True), (-1, False)])
    def test_char_dead_groups_fallback_cap_boundary(self, tmp_path, value, ok):
        body = _yaml_with_dead_groups_cap(value)
        if ok:
            cfg = load_config(write(tmp_path, body))
            assert cfg.thresholds.asset_coverage.dead_groups_fallback_cap == value
        else:
            with pytest.raises(ConfigError, match="dead_groups_fallback_cap"):
                load_config(write(tmp_path, body))

    # -- thresholds.data_quality.duplicate_detection_max_assets -------------
    # 0 is accepted (= always skip); negative is rejected.
    # Error: "thresholds.data_quality.duplicate_detection_max_assets: must be a non-negative integer"

    @pytest.mark.parametrize("value,ok", [(0, True), (5, True), (-1, False)])
    def test_char_duplicate_detection_max_assets_boundary(self, tmp_path, value, ok):
        body = _yaml_with_duplicate_detection_max_assets(value)
        if ok:
            cfg = load_config(write(tmp_path, body))
            assert cfg.thresholds.data_quality.duplicate_detection_max_assets == value
        else:
            with pytest.raises(ConfigError, match="non-negative"):
                load_config(write(tmp_path, body))

    # -- report.delta_max_age_days ------------------------------------------
    # 0 and None (null) are both accepted; negative is rejected.
    # Error: "report.delta_max_age_days: expected non-negative int or null"

    @pytest.mark.parametrize("yaml_value,expected,ok", [
        ("0", 0, True),
        ("30", 30, True),
        ("null", None, True),
        ("-1", None, False),
    ])
    def test_char_delta_max_age_days_boundary(self, tmp_path, yaml_value, expected, ok):
        cfg_text = _MINIMAL_CONFIG_TEXT + f"  delta_max_age_days: {yaml_value}\n"
        if ok:
            cfg = load_config(write(tmp_path, cfg_text))
            assert cfg.report.delta_max_age_days == expected
        else:
            with pytest.raises(ConfigError, match="non-negative"):
                load_config(write(tmp_path, cfg_text))

    # -- rapid7.parallel_pages ----------------------------------------------
    # Range [1, 16]; 0 rejected by _check_scalar (<=0); 17 rejected by range check.
    # Already covered by individual tests; this parametrized form is the
    # canonical cross-run regression anchor.

    @pytest.mark.parametrize("value,ok", [(1, True), (16, True), (0, False), (17, False)])
    def test_char_rapid7_parallel_pages_boundary(self, tmp_path, value, ok):
        body = _yaml_with_rapid7_extras(parallel_pages=value)
        if ok:
            cfg = load_config(write(tmp_path, body))
            assert cfg.rapid7.parallel_pages == value
        else:
            with pytest.raises(ConfigError, match="parallel_pages"):
                load_config(write(tmp_path, body))

    # -- cloud_integration enabled=true with empty base_url -----------------
    # Error: "cloud_integration.base_url: required when enabled is true"

    def test_char_cloud_integration_enabled_requires_base_url(self, tmp_path):
        cloud_block = textwrap.dedent("""
            cloud_integration:
              enabled: true
              base_url: ""
        """)
        with pytest.raises(ConfigError, match="base_url"):
            load_config(write(tmp_path, VALID_YAML + cloud_block))

    # -- bool rejected where int expected -----------------------------------
    # In YAML, `true` parses as Python True (bool), a subclass of int.
    # _build_audit_config has an explicit isinstance(v, bool) guard.
    # Error: "audit.sample_size: expected positive int"
    # (Same as test_char_audit_sample_size_bool_rejected; kept here for
    # completeness as the canonical "bool-for-int" characterization anchor.)

    def test_char_bool_rejected_for_int_field_via_yaml(self, tmp_path):
        """YAML `true` for audit.sample_size must be rejected (bool is not int)."""
        audit_block = textwrap.dedent("""
            audit:
              enabled: true
              full_scan: false
              sample_size: true
              rules: {}
        """)
        body = VALID_YAML.replace(
            "  data_quality: true",
            "  data_quality: true\n  configuration_audit: true",
        ) + audit_block
        with pytest.raises(ConfigError, match="sample_size"):
            load_config(write(tmp_path, body))


# ---------------------------------------------------------------------------
# Task 2: unit tests for _check_scalar positive_int=False and _from_dict
# post_validate + type-only behaviour
# ---------------------------------------------------------------------------

from dataclasses import dataclass, replace  # noqa: E402
from rapid7_healthcheck.config import _check_scalar, _from_dict  # noqa: E402


@dataclass(frozen=True)
class _Sample:
    n: int
    name: str = "x"


class TestCheckScalarPositiveIntFalse:
    def test_allows_zero_and_negative(self):
        # type-only: 0 and negative ints must NOT raise
        _check_scalar("x", 0, int, "p", positive_int=False)
        _check_scalar("x", -5, int, "p", positive_int=False)

    def test_still_rejects_bool(self):
        with pytest.raises(ConfigError, match="expected int, got bool"):
            _check_scalar("x", True, int, "p", positive_int=False)

    def test_still_rejects_non_int(self):
        with pytest.raises(ConfigError, match="expected int, got str"):
            _check_scalar("x", "5", int, "p", positive_int=False)

    def test_default_positive_int_true_still_rejects_zero(self):
        # default positive_int=True preserves current behavior
        with pytest.raises(ConfigError, match="must be a positive integer"):
            _check_scalar("x", 0, int, "p")


class TestFromDictTypeOnlyAndPostValidate:
    def test_is_type_only_allows_zero(self):
        # _from_dict must NOT enforce positive-int; that is post_validate's job
        obj = _from_dict(_Sample, {"n": 0}, "s")
        assert obj.n == 0

    def test_still_rejects_wrong_type(self):
        with pytest.raises(ConfigError, match="expected int, got str"):
            _from_dict(_Sample, {"n": "5"}, "s")

    def test_runs_post_validate(self):
        def pv(obj):
            if obj.n < 0:
                raise ConfigError("s.n: must be non-negative")
            return obj

        assert _from_dict(_Sample, {"n": 3}, "s", post_validate=pv).n == 3
        with pytest.raises(ConfigError, match="must be non-negative"):
            _from_dict(_Sample, {"n": -1}, "s", post_validate=pv)

    def test_post_validate_can_replace(self):
        def pv(obj):
            return replace(obj, name=obj.name.strip())

        assert _from_dict(_Sample, {"n": 1, "name": "  y  "}, "s", post_validate=pv).name == "y"
