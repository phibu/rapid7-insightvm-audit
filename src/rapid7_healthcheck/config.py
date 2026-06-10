from __future__ import annotations

import logging
import typing
from dataclasses import MISSING, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or has unknown keys."""


_VALID_AUTH_MODES = ("api_key", "basic")


@dataclass(frozen=True)
class Rapid7Config:
    base_url: str
    verify_tls: bool
    request_timeout_seconds: int
    max_retries: int
    auth_mode: str = "api_key"
    parallel_pages: int = 1
    page_size: int = 250


@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str
    delta_max_age_days: int | None = 30
    log_format: str = "plain"


@dataclass(frozen=True)
class ScanEngineThresholds:
    last_contact_warn_hours: int
    last_contact_fail_hours: int


@dataclass(frozen=True)
class ScanActivityThresholds:
    recent_window_days: int
    stuck_scan_hours: int
    site_no_scan_days: int


@dataclass(frozen=True)
class AssetCoverageThresholds:
    stale_asset_days: int
    flag_unscanned_assets: bool
    never_scanned_days: int
    flag_dead_asset_groups: bool = True
    flag_agent_only_assets: bool = False
    dead_groups_fallback_cap: int = 200
    flag_ghost_assets: bool = True


@dataclass(frozen=True)
class DataQualityThresholds:
    flag_missing_os: bool
    flag_empty_sites: bool
    flag_stale_assets: bool = True
    stale_asset_days: int = 180
    flag_duplicate_hostnames: bool = True
    flag_duplicate_ips: bool = True
    duplicate_detection_max_assets: int = 50000


@dataclass(frozen=True)
class Thresholds:
    scan_engines: ScanEngineThresholds
    scan_activity: ScanActivityThresholds
    asset_coverage: AssetCoverageThresholds
    data_quality: DataQualityThresholds


_VALID_RULE_IDS = {
    "agent_unauth_collision",
    "site_vuln_template_no_creds",
    "overlapping_scan_windows",
    "single_engine_overload",
    "discovery_template_on_prod_site",
    "policy_and_vuln_in_same_template",
    "local_engine_production_scope",
    "dynamic_groups_and_nested_tags",
    "scan_report_schedule_overlap",
    "engine_version_drift",
    "insight_agent_deployed",
}
_VALID_SEVERITIES = {"info", "warn", "fail"}

_VALID_USER_AUDIT_RULE_IDS = {
    "privileged_user_without_mfa",
    "local_account_when_sso_configured",
    "multiple_global_administrators",
    "locked_user_account",
    "disabled_user_with_role_bindings",
    "user_with_role_but_no_access",
    "superuser_flag_outside_global_admin",
}

_VALID_CLOUD_DRIFT_RULE_IDS = {
    "cd.console_asset_count_drift",
    "cd.scan_engine_cloud_registration",
    "cd.stale_assessment_cohort",
}

# Keep in sync with @register_template_rule calls under
# `src/rapid7_healthcheck/audit/template/rules/`. F1 lands empty; F2-F4 add
# the 14 rules and each new rule_id must be appended here.
_VALID_TEMPLATE_AUDIT_RULE_IDS: set[str] = set()


@dataclass(frozen=True)
class RuleConfig:
    enabled: bool
    severity: str
    knobs: dict


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool
    full_scan: bool
    sample_size: int
    agents_timeout_seconds: int
    rules: dict  # str -> RuleConfig


@dataclass(frozen=True)
class UserAuditConfig:
    """Sibling to AuditConfig, scoped to the User & Permission audit category."""
    enabled: bool
    full_scan: bool
    sample_size: int
    rules: dict  # str -> RuleConfig


def _default_audit() -> AuditConfig:
    return AuditConfig(enabled=False, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules={})


def _default_user_audit() -> UserAuditConfig:
    return UserAuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})


@dataclass(frozen=True)
class CloudIntegrationConfig:
    """Connection settings for the InsightVM Cloud Integrations API (v4).

    Disabled-by-default; when enabled, the env var named in `api_key_env`
    must hold a valid Insight Platform API key (separate from the console
    key used for v3). The `cloud_drift` audit category self-skips when
    `enabled` is False or the env var is missing.
    """
    enabled: bool
    base_url: str
    api_key_env: str
    timeout_seconds: int
    max_retries: int
    parallel_pages: int


def _default_cloud_integration() -> CloudIntegrationConfig:
    return CloudIntegrationConfig(
        enabled=False,
        base_url="",
        api_key_env="R7_CLOUD_API_KEY",
        timeout_seconds=30,
        max_retries=3,
        parallel_pages=1,
    )


@dataclass(frozen=True)
class CloudDriftConfig:
    """Rule-bearing config for the Cloud Drift audit category.

    Independent of `cloud_integration:` so users can author rule
    overrides before wiring the connection. The `CloudDriftAuditCheck`
    self-skips when `cloud_integration` is disabled regardless of what
    this block contains.
    """
    rules: dict  # str -> RuleConfig


def _default_cloud_drift() -> CloudDriftConfig:
    return CloudDriftConfig(rules={})


@dataclass(frozen=True)
class TemplateAuditConfig:
    """Sibling to AuditConfig / UserAuditConfig, scoped to the Template
    Configuration Audit category."""
    enabled: bool = True
    full_scan: bool = False
    sample_size: int = 500
    rules: dict = field(default_factory=dict)  # str -> RuleConfig


def _default_template_audit() -> TemplateAuditConfig:
    return TemplateAuditConfig(enabled=True, full_scan=False, sample_size=500, rules={})


@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict
    audit: AuditConfig = field(default_factory=_default_audit)
    user_audit: UserAuditConfig = field(default_factory=_default_user_audit)
    cloud_integration: CloudIntegrationConfig = field(default_factory=_default_cloud_integration)
    cloud_drift: CloudDriftConfig = field(default_factory=_default_cloud_drift)
    template_audit: TemplateAuditConfig = field(default_factory=_default_template_audit)


def _check_scalar(field_name: str, value: Any, expected: type, path: str) -> None:
    # bool is a subclass of int, so handle it carefully.
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"{path}.{field_name}: expected int, got {type(value).__name__}"
            )
        if value <= 0:
            raise ConfigError(
                f"{path}.{field_name}: must be a positive integer, got {value}"
            )
    elif expected is bool:
        if not isinstance(value, bool):
            raise ConfigError(
                f"{path}.{field_name}: expected bool, got {type(value).__name__}"
            )
    elif expected is str:
        if not isinstance(value, str):
            raise ConfigError(
                f"{path}.{field_name}: expected str, got {type(value).__name__}"
            )
    else:
        # No other scalar types currently used.
        raise ConfigError(
            f"{path}.{field_name}: unsupported declared type {expected!r}"
        )


def _validate_dict_schema(
    data: Any,
    *,
    expected: set[str],
    required: set[str],
    name: str,
) -> dict:
    """Validate `data` is a mapping with only `expected` keys and all `required` keys.

    Returns `data` cast to dict on success. Raises `ConfigError` matching
    the wording used by `_build_audit_config` and `_build_user_audit_config`
    so existing error messages remain stable:

      - "{name}: expected mapping"
      - "{name}: unknown key(s): [...]"
      - "{name}: missing required key(s): [...]"

    Not used for `_build_report_config`, which has different error wording
    (`"report: expected mapping, got <type>"`) and a custom required/optional
    split.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"{name}: expected mapping")
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"{name}: unknown key(s): {sorted(unknown)}")
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"{name}: missing required key(s): {sorted(missing)}")
    return data


def _from_dict(cls: type, data: Any, path: str) -> Any:
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected mapping, got {type(data).__name__}")
    expected = {f.name for f in fields(cls)}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {sorted(unknown)}")
    required = {
        f.name
        for f in fields(cls)
        if f.default is MISSING and f.default_factory is MISSING  # type: ignore[misc]
    }
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"{path}: missing required key(s): {sorted(missing)}")

    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name in data:
            _check_scalar(f.name, data[f.name], hints[f.name], path)
            kwargs[f.name] = data[f.name]
    return cls(**kwargs)


_THRESHOLD_NESTED = {
    "scan_engines": ScanEngineThresholds,
    "scan_activity": ScanActivityThresholds,
    "asset_coverage": AssetCoverageThresholds,
    "data_quality": DataQualityThresholds,
}


def _build_rapid7_config(data: Any) -> Rapid7Config:
    """Validator for the `rapid7:` block.

    Mirrors `_from_dict` semantics (unknown keys reject, scalar types
    enforced) but treats `auth_mode` as optional with a default and
    additionally constrains it to the `_VALID_AUTH_MODES` allowlist.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"rapid7: expected mapping, got {type(data).__name__}")

    required = {"base_url", "verify_tls", "request_timeout_seconds", "max_retries"}
    optional = {"auth_mode", "parallel_pages", "page_size"}
    expected = required | optional

    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"rapid7: unknown key(s): {sorted(unknown)}")
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"rapid7: missing required key(s): {sorted(missing)}")

    _check_scalar("base_url", data["base_url"], str, "rapid7")
    _check_scalar("verify_tls", data["verify_tls"], bool, "rapid7")
    _check_scalar("request_timeout_seconds", data["request_timeout_seconds"], int, "rapid7")
    _check_scalar("max_retries", data["max_retries"], int, "rapid7")

    auth_mode = data.get("auth_mode", "api_key")
    if not isinstance(auth_mode, str):
        raise ConfigError(
            f"rapid7.auth_mode: expected str, got {type(auth_mode).__name__}"
        )
    if auth_mode not in _VALID_AUTH_MODES:
        raise ConfigError(
            f"rapid7.auth_mode: must be one of {list(_VALID_AUTH_MODES)}, got {auth_mode!r}"
        )

    parallel_pages = data.get("parallel_pages", 1)
    _check_scalar("parallel_pages", parallel_pages, int, "rapid7")
    if not (1 <= parallel_pages <= 16):
        raise ConfigError(
            f"rapid7.parallel_pages must be in range [1, 16]; got {parallel_pages}"
        )
    if parallel_pages > 8:
        logger.warning(
            "rapid7.parallel_pages=%d exceeds the documented InsightVM "
            "8-parallel-request limit; proceed at your own risk",
            parallel_pages,
        )

    page_size = data.get("page_size", 250)
    _check_scalar("page_size", page_size, int, "rapid7")
    if not (1 <= page_size <= 500):
        raise ConfigError(
            f"rapid7.page_size must be in range [1, 500]; got {page_size}"
        )

    return Rapid7Config(
        base_url=data["base_url"],
        verify_tls=data["verify_tls"],
        request_timeout_seconds=data["request_timeout_seconds"],
        max_retries=data["max_retries"],
        auth_mode=auth_mode,
        parallel_pages=parallel_pages,
        page_size=page_size,
    )


def _build_thresholds(data: Any) -> Thresholds:
    if not isinstance(data, dict):
        raise ConfigError("thresholds: expected mapping")
    expected = set(_THRESHOLD_NESTED.keys())
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"thresholds: unknown key(s): {sorted(unknown)}")
    missing = expected - set(data.keys())
    if missing:
        raise ConfigError(f"thresholds: missing required key(s): {sorted(missing)}")

    # asset_coverage.dead_groups_fallback_cap accepts 0 (= disable fallback),
    # which the generic _check_scalar (>0) rejects. Pull the field out, build
    # the rest via the normal path, then re-attach the validated value.
    ac_raw = data["asset_coverage"]
    if not isinstance(ac_raw, dict):
        raise ConfigError(
            f"thresholds.asset_coverage: expected mapping, got {type(ac_raw).__name__}"
        )
    ac_data = dict(ac_raw)
    cap: int | None = None
    if "dead_groups_fallback_cap" in ac_data:
        cap = ac_data.pop("dead_groups_fallback_cap")
        if isinstance(cap, bool) or not isinstance(cap, int):
            raise ConfigError(
                f"thresholds.asset_coverage.dead_groups_fallback_cap: "
                f"expected int, got {type(cap).__name__}"
            )
        if cap < 0:
            raise ConfigError(
                f"thresholds.asset_coverage.dead_groups_fallback_cap: "
                f"must be a non-negative integer, got {cap}"
            )

    asset_coverage = _from_dict(
        AssetCoverageThresholds, ac_data, "thresholds.asset_coverage"
    )
    if cap is not None:
        asset_coverage = replace(asset_coverage, dead_groups_fallback_cap=cap)

    # data_quality.duplicate_detection_max_assets accepts 0 (= always skip),
    # which the generic _check_scalar (>0) rejects. Pull it out, build the
    # rest via the normal path, then re-attach the validated value. Mirrors
    # the asset_coverage.dead_groups_fallback_cap handling above.
    dq_raw = data["data_quality"]
    if not isinstance(dq_raw, dict):
        raise ConfigError(
            f"thresholds.data_quality: expected mapping, got {type(dq_raw).__name__}"
        )
    dq_data = dict(dq_raw)
    dup_cap: int | None = None
    if "duplicate_detection_max_assets" in dq_data:
        dup_cap = dq_data.pop("duplicate_detection_max_assets")
        if isinstance(dup_cap, bool) or not isinstance(dup_cap, int):
            raise ConfigError(
                f"thresholds.data_quality.duplicate_detection_max_assets: "
                f"expected int, got {type(dup_cap).__name__}"
            )
        if dup_cap < 0:
            raise ConfigError(
                f"thresholds.data_quality.duplicate_detection_max_assets: "
                f"must be a non-negative integer, got {dup_cap}"
            )

    data_quality = _from_dict(
        DataQualityThresholds, dq_data, "thresholds.data_quality"
    )
    if dup_cap is not None:
        data_quality = replace(data_quality, duplicate_detection_max_assets=dup_cap)

    return Thresholds(
        scan_engines=_from_dict(ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines"),
        scan_activity=_from_dict(ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity"),
        asset_coverage=asset_coverage,
        data_quality=data_quality,
    )


def _build_audit_config(data: dict | None) -> AuditConfig:
    if data is None:
        return AuditConfig(enabled=False, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules={})
    _validate_dict_schema(
        data,
        expected={"enabled", "full_scan", "sample_size", "agents_timeout_seconds", "rules"},
        required=set(),  # legacy: only `unknown` was checked here, missing
                         # keys fall through to the field checks below
        name="audit",
    )
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("audit.enabled: expected bool")
    if not isinstance(data.get("full_scan"), bool):
        raise ConfigError("audit.full_scan: expected bool")
    if (
        not isinstance(data.get("sample_size"), int)
        or isinstance(data.get("sample_size"), bool)
        or data["sample_size"] <= 0
    ):
        raise ConfigError("audit.sample_size: expected positive int")

    agents_timeout_seconds = data.get("agents_timeout_seconds", 180)
    if (
        not isinstance(agents_timeout_seconds, int)
        or isinstance(agents_timeout_seconds, bool)
        or agents_timeout_seconds <= 0
    ):
        raise ConfigError("audit.agents_timeout_seconds: expected positive int")

    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("audit.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_RULE_IDS:
            raise ConfigError(f"audit.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"audit.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"audit.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"audit.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)

    return AuditConfig(
        enabled=data["enabled"],
        full_scan=data["full_scan"],
        sample_size=data["sample_size"],
        agents_timeout_seconds=agents_timeout_seconds,
        rules=rules,
    )


def _build_user_audit_config(data: dict | None) -> UserAuditConfig:
    """Validator for the `user_audit:` block. Mirrors `_build_audit_config`
    but uses `_VALID_USER_AUDIT_RULE_IDS` and the `UserAuditConfig` shape."""
    if data is None:
        return UserAuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})
    _validate_dict_schema(
        data,
        expected={"enabled", "full_scan", "sample_size", "rules"},
        required=set(),
        name="user_audit",
    )
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("user_audit.enabled: expected bool")
    if not isinstance(data.get("full_scan"), bool):
        raise ConfigError("user_audit.full_scan: expected bool")
    if (
        not isinstance(data.get("sample_size"), int)
        or isinstance(data.get("sample_size"), bool)
        or data["sample_size"] <= 0
    ):
        raise ConfigError("user_audit.sample_size: expected positive int")

    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("user_audit.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_USER_AUDIT_RULE_IDS:
            raise ConfigError(f"user_audit.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"user_audit.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"user_audit.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"user_audit.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)

    return UserAuditConfig(
        enabled=data["enabled"],
        full_scan=data["full_scan"],
        sample_size=data["sample_size"],
        rules=rules,
    )


def _build_cloud_integration_config(data: dict | None) -> CloudIntegrationConfig:
    """Validator for the optional `cloud_integration:` block.

    Mirrors `_build_audit_config` semantics: missing block = defaults
    (disabled), unknown keys reject, type checks per field. When
    `enabled: true`, `base_url` becomes required and must be HTTPS.
    """
    if data is None:
        return _default_cloud_integration()
    _validate_dict_schema(
        data,
        expected={
            "enabled", "base_url", "api_key_env",
            "timeout_seconds", "max_retries", "parallel_pages",
        },
        required=set(),
        name="cloud_integration",
    )
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("cloud_integration.enabled: expected bool")
    enabled = data["enabled"]

    base_url = data.get("base_url", "")
    if not isinstance(base_url, str):
        raise ConfigError("cloud_integration.base_url: expected str")
    if enabled and not base_url:
        raise ConfigError(
            "cloud_integration.base_url: required when enabled is true"
        )
    if enabled and not base_url.startswith("https://"):
        raise ConfigError("cloud_integration.base_url must start with https://")

    api_key_env = data.get("api_key_env", "R7_CLOUD_API_KEY")
    if not isinstance(api_key_env, str) or not api_key_env:
        raise ConfigError("cloud_integration.api_key_env: expected non-empty str")

    timeout_seconds = data.get("timeout_seconds", 30)
    _check_scalar("timeout_seconds", timeout_seconds, int, "cloud_integration")

    max_retries = data.get("max_retries", 3)
    _check_scalar("max_retries", max_retries, int, "cloud_integration")

    parallel_pages = data.get("parallel_pages", 1)
    _check_scalar("parallel_pages", parallel_pages, int, "cloud_integration")
    if not (1 <= parallel_pages <= 16):
        raise ConfigError(
            f"cloud_integration.parallel_pages must be in range [1, 16]; got {parallel_pages}"
        )

    return CloudIntegrationConfig(
        enabled=enabled,
        base_url=base_url,
        api_key_env=api_key_env,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        parallel_pages=parallel_pages,
    )


def _build_cloud_drift_config(data: dict | None) -> CloudDriftConfig:
    """Validator for the optional `cloud_drift:` block.

    Mirrors `_build_user_audit_config` rule-validation logic against
    `_VALID_CLOUD_DRIFT_RULE_IDS`. Has no top-level `enabled`/`full_scan`/
    `sample_size` keys — sampling does not apply to cloud-drift rules
    (they read aggregate counts) and the category-level enable lives in
    `checks.cloud_drift_audit` like every other check.
    """
    if data is None:
        return _default_cloud_drift()
    _validate_dict_schema(
        data,
        expected={"rules"},
        required=set(),
        name="cloud_drift",
    )
    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("cloud_drift.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_CLOUD_DRIFT_RULE_IDS:
            raise ConfigError(f"cloud_drift.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"cloud_drift.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"cloud_drift.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"cloud_drift.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)
    return CloudDriftConfig(rules=rules)


def _build_template_audit_config(data: dict | None) -> TemplateAuditConfig:
    """Validator for the `template_audit:` block. Mirrors
    `_build_user_audit_config` but uses `_VALID_TEMPLATE_AUDIT_RULE_IDS`
    and the `TemplateAuditConfig` shape."""
    if data is None:
        return _default_template_audit()
    _validate_dict_schema(
        data,
        expected={"enabled", "full_scan", "sample_size", "rules"},
        required=set(),
        name="template_audit",
    )
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("template_audit.enabled: expected bool")
    if not isinstance(data.get("full_scan"), bool):
        raise ConfigError("template_audit.full_scan: expected bool")
    if (
        not isinstance(data.get("sample_size"), int)
        or isinstance(data.get("sample_size"), bool)
        or data["sample_size"] <= 0
    ):
        raise ConfigError("template_audit.sample_size: expected positive int")

    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("template_audit.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_TEMPLATE_AUDIT_RULE_IDS:
            raise ConfigError(f"template_audit.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"template_audit.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"template_audit.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"template_audit.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)

    return TemplateAuditConfig(
        enabled=data["enabled"],
        full_scan=data["full_scan"],
        sample_size=data["sample_size"],
        rules=rules,
    )


def _build_report_config(data: Any) -> ReportConfig:
    """Validate the `report:` block, allowing `delta_max_age_days` to be absent.

    Accepts:
      - missing key  -> default 30
      - integer >= 0 -> use as-is
      - null/None    -> delta disabled
    Rejects unknown keys (consistent with `_from_dict`).

    Not routed through `_validate_dict_schema` because this validator has a
    distinct error-message wording (`expected mapping, got <type>`) and a
    custom optional/required split that doesn't generalize cleanly.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"report: expected mapping, got {type(data).__name__}")
    expected = {"output_dir", "filename_pattern", "title", "delta_max_age_days", "log_format"}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"report: unknown key(s): {sorted(unknown)}")
    required = {"output_dir", "filename_pattern", "title"}
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"report: missing required key(s): {sorted(missing)}")
    for k in ("output_dir", "filename_pattern", "title"):
        if not isinstance(data[k], str):
            raise ConfigError(f"report.{k}: expected str")
    delta = data.get("delta_max_age_days", 30)
    if delta is not None and (not isinstance(delta, int) or isinstance(delta, bool) or delta < 0):
        raise ConfigError("report.delta_max_age_days: expected non-negative int or null")
    log_format = data.get("log_format", "plain")
    if log_format not in ("plain", "cmtrace", "json"):
        raise ConfigError(
            f"report.log_format: invalid value {log_format!r}; "
            f"must be one of: plain, cmtrace, json"
        )
    return ReportConfig(
        output_dir=data["output_dir"],
        filename_pattern=data["filename_pattern"],
        title=data["title"],
        delta_max_age_days=delta,
        log_format=log_format,
    )


def _ensure_default_on(checks: dict, *names: str) -> dict:
    """Return `checks` with any missing name defaulted to ``True``.

    Preserves explicit user values: if a key is already present (even with
    ``False``), it is not overwritten. Mutates and returns a copy of the
    input dict only when at least one name was missing — when every name
    is present, returns the input dict unchanged so the caller doesn't pay
    for a copy.
    """
    missing = [n for n in names if n not in checks]
    if not missing:
        return checks
    result = dict(checks)
    for name in missing:
        result[name] = True
    return result


def _build_app_config(data: dict) -> AppConfig:
    expected_root = {"rapid7", "report", "thresholds", "checks", "audit", "user_audit", "cloud_integration", "cloud_drift", "template_audit"}
    unknown = set(data.keys()) - expected_root
    if unknown:
        raise ConfigError(f"unknown root key(s): {sorted(unknown)}")
    # The five audit/integration blocks are optional.
    required_root = expected_root - {"audit", "user_audit", "cloud_integration", "cloud_drift", "template_audit"}
    missing = required_root - set(data.keys())
    if missing:
        raise ConfigError(f"missing required root key(s): {sorted(missing)}")

    rapid7_data = dict(data["rapid7"]) if isinstance(data["rapid7"], dict) else data["rapid7"]
    if isinstance(rapid7_data, dict) and isinstance(rapid7_data.get("base_url"), str):
        rapid7_data["base_url"] = rapid7_data["base_url"].strip()
    rapid7 = _build_rapid7_config(rapid7_data)
    if not rapid7.base_url.startswith("https://"):
        raise ConfigError("rapid7.base_url must start with https://")

    report = _build_report_config(data["report"])
    thresholds = _build_thresholds(data["thresholds"])

    checks = data["checks"]
    if not isinstance(checks, dict) or not all(isinstance(v, bool) for v in checks.values()):
        raise ConfigError("checks: expected mapping of name -> bool")
    checks = _ensure_default_on(
        checks,
        "configuration_audit",
        "user_permission_audit",
        "cloud_drift_audit",
        "template_audit",
    )

    audit = _build_audit_config(data.get("audit"))
    user_audit = _build_user_audit_config(data.get("user_audit"))
    cloud_integration = _build_cloud_integration_config(data.get("cloud_integration"))
    cloud_drift = _build_cloud_drift_config(data.get("cloud_drift"))
    template_audit = _build_template_audit_config(data.get("template_audit"))
    return AppConfig(
        rapid7=rapid7,
        report=report,
        thresholds=thresholds,
        checks=checks,
        audit=audit,
        user_audit=user_audit,
        cloud_integration=cloud_integration,
        cloud_drift=cloud_drift,
        template_audit=template_audit,
    )


def load_config(path: Path | str) -> AppConfig:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"failed to parse YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    return _build_app_config(raw)
