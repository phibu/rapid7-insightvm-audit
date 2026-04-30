from __future__ import annotations

import typing
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


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


@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str
    delta_max_age_days: int | None = 30


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


@dataclass(frozen=True)
class DataQualityThresholds:
    flag_missing_os: bool
    flag_empty_sites: bool


@dataclass(frozen=True)
class Thresholds:
    scan_engines: ScanEngineThresholds
    scan_activity: ScanActivityThresholds
    asset_coverage: AssetCoverageThresholds
    data_quality: DataQualityThresholds


_VALID_RULE_IDS = {
    "agent_unauth_collision",
    "site_vuln_template_no_creds",
    "credential_failure_in_recent_scans",
    "overlapping_scan_windows",
    "single_engine_overload",
    "discovery_template_on_prod_site",
    "policy_and_vuln_in_same_template",
    "store_invulnerable_results",
    "local_engine_production_scope",
    "dynamic_groups_and_nested_tags",
    "scan_report_schedule_overlap",
    "engine_version_drift",
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
    rules: dict  # str -> RuleConfig


@dataclass(frozen=True)
class UserAuditConfig:
    """Sibling to AuditConfig, scoped to the User & Permission audit category."""
    enabled: bool
    full_scan: bool
    sample_size: int
    rules: dict  # str -> RuleConfig


def _default_audit() -> AuditConfig:
    return AuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})


def _default_user_audit() -> UserAuditConfig:
    return UserAuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})


@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict
    audit: AuditConfig = field(default_factory=_default_audit)
    user_audit: UserAuditConfig = field(default_factory=_default_user_audit)


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
    missing = expected - set(data.keys())
    if missing:
        raise ConfigError(f"{path}: missing required key(s): {sorted(missing)}")

    hints = typing.get_type_hints(cls)
    for f in fields(cls):
        _check_scalar(f.name, data[f.name], hints[f.name], path)

    return cls(**{f.name: data[f.name] for f in fields(cls)})


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
    optional = {"auth_mode"}
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

    return Rapid7Config(
        base_url=data["base_url"],
        verify_tls=data["verify_tls"],
        request_timeout_seconds=data["request_timeout_seconds"],
        max_retries=data["max_retries"],
        auth_mode=auth_mode,
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
    return Thresholds(
        scan_engines=_from_dict(ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines"),
        scan_activity=_from_dict(ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity"),
        asset_coverage=_from_dict(AssetCoverageThresholds, data["asset_coverage"], "thresholds.asset_coverage"),
        data_quality=_from_dict(DataQualityThresholds, data["data_quality"], "thresholds.data_quality"),
    )


def _build_audit_config(data: dict | None) -> AuditConfig:
    if data is None:
        return AuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})
    _validate_dict_schema(
        data,
        expected={"enabled", "full_scan", "sample_size", "rules"},
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
    expected = {"output_dir", "filename_pattern", "title", "delta_max_age_days"}
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
    return ReportConfig(
        output_dir=data["output_dir"],
        filename_pattern=data["filename_pattern"],
        title=data["title"],
        delta_max_age_days=delta,
    )


def _build_app_config(data: dict) -> AppConfig:
    expected_root = {"rapid7", "report", "thresholds", "checks", "audit", "user_audit"}
    unknown = set(data.keys()) - expected_root
    if unknown:
        raise ConfigError(f"unknown root key(s): {sorted(unknown)}")
    required_root = expected_root - {"audit", "user_audit"}  # both audits are optional
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
    if "configuration_audit" not in checks:
        checks = dict(checks)
        checks["configuration_audit"] = True
    if "user_permission_audit" not in checks:
        checks = dict(checks)
        checks["user_permission_audit"] = True

    audit = _build_audit_config(data.get("audit"))
    user_audit = _build_user_audit_config(data.get("user_audit"))
    return AppConfig(
        rapid7=rapid7,
        report=report,
        thresholds=thresholds,
        checks=checks,
        audit=audit,
        user_audit=user_audit,
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
