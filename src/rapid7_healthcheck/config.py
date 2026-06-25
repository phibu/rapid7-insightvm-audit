from __future__ import annotations

import logging
import typing
from dataclasses import MISSING, dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Callable

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
    # The display name of the site Rapid7 auto-assigns Insight-Agent assets to.
    # The id varies per console but the name is deterministic, so the
    # agent-only-coverage-gap rule resolves the site by name (see ADR-0004).
    agent_site_name: str = "Rapid7 Insight Agents"


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


_VALID_SEVERITIES = {"info", "warn", "fail"}


def _audit_rule_ids() -> frozenset[str]:
    """Valid rule ids for the Configuration Audit category.

    The import is lazy and deliberately so: ``config.py`` is a leaf module,
    and every ``audit/**/__init__.py`` imports ``config.AppConfig`` -- importing
    the audit packages at this module's top level would be a circular import.
    By the time this runs (inside ``load_config`` → the builders), the cycle is
    resolved and the side-effect rule imports in each package's ``__init__``
    have populated its registry. Importing here also *guarantees* population
    rather than depending on the caller having imported the audit tree first,
    so the "unknown rule id" rejection stays correct regardless of import order
    (covered by ``test_registry_rule_ids_populates_when_config_imported_first``).

    Peer accessors (``_user_rule_ids``, ``_cloud_rule_ids``,
    ``_template_rule_ids``) carry the same lazy-import rationale, one per
    category. Each ``ConfigBlockSpec.registry`` points at its own accessor, so
    a builder asks for exactly its category's ids -- no build-all-four-and-
    discard-three tuple. A new rule registered via ``@register`` /
    ``@register_user_rule`` / ``@register_cloud_rule`` /
    ``@register_template_rule`` is accepted by config automatically.
    """
    from rapid7_healthcheck.audit import _RULE_REGISTRY

    return frozenset(_RULE_REGISTRY)


def _user_rule_ids() -> frozenset[str]:
    """Valid rule ids for the User & Permission audit. See `_audit_rule_ids`."""
    from rapid7_healthcheck.audit.user_permission import _USER_RULE_REGISTRY

    return frozenset(_USER_RULE_REGISTRY)


def _cloud_rule_ids() -> frozenset[str]:
    """Valid rule ids for the Cloud Drift audit. See `_audit_rule_ids`."""
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY

    return frozenset(_CLOUD_RULE_REGISTRY)


def _template_rule_ids() -> frozenset[str]:
    """Valid rule ids for the Template Configuration Audit. See `_audit_rule_ids`."""
    from rapid7_healthcheck.audit.template import _TEMPLATE_RULE_REGISTRY

    return frozenset(_TEMPLATE_RULE_REGISTRY)


def _validate_rules_block(
    raw_rules: Any,
    *,
    valid_rule_ids: set[str] | frozenset[str],
    path: str,
) -> dict[str, "RuleConfig"]:
    """Validate a ``rules:`` mapping and build its ``RuleConfig`` entries.

    The single rule-validation loop shared by every audit builder
    (``_build_audit_config``, ``_build_user_audit_config``,
    ``_build_cloud_drift_config``, ``_build_template_audit_config``). Each rule
    body must be a mapping with a bool ``enabled``, a ``severity`` in
    ``_VALID_SEVERITIES``, and any remaining keys treated as opaque knobs.

    ``path`` is the dotted config location (e.g. ``"audit.rules"``) used to
    prefix every error so each builder keeps its existing, test-pinned wording:

      - "{path}: unknown rule id '{rule_id}'"
      - "{path}.{rule_id}: expected mapping"
      - "{path}.{rule_id}.enabled: expected bool"
      - "{path}.{rule_id}.severity: must be one of [...]"

    Callers are responsible for the surrounding ``data.get("rules") or {}`` and
    the "expected mapping" check on the rules container itself; this helper
    assumes ``raw_rules`` is already a dict (it is, at every call site).
    """
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in valid_rule_ids:
            raise ConfigError(f"{path}: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"{path}.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"{path}.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"{path}.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)
    return rules


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
    agents_timeout_seconds: int = 180
    rules: dict = field(default_factory=dict)  # str -> RuleConfig


@dataclass(frozen=True)
class UserAuditConfig:
    """Sibling to AuditConfig, scoped to the User & Permission audit category."""
    enabled: bool
    full_scan: bool
    sample_size: int
    rules: dict = field(default_factory=dict)  # str -> RuleConfig


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
    base_url: str = ""
    api_key_env: str = "R7_CLOUD_API_KEY"
    timeout_seconds: int = 30
    max_retries: int = 3
    parallel_pages: int = 1


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
    rules: dict = field(default_factory=dict)  # str -> RuleConfig


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


def _check_scalar(
    field_name: str, value: Any, expected: type, path: str, *, positive_int: bool = True
) -> None:
    # bool is a subclass of int, so handle it carefully.
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"{path}.{field_name}: expected int, got {type(value).__name__}"
            )
        if positive_int and value <= 0:
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


def _from_dict(cls: type, data: Any, path: str, *, post_validate: Callable[[Any], Any] | None = None) -> Any:
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
            _check_scalar(f.name, data[f.name], hints[f.name], path, positive_int=False)
            kwargs[f.name] = data[f.name]
    obj = cls(**kwargs)
    return post_validate(obj) if post_validate is not None else obj


_THRESHOLD_NESTED = {
    "scan_engines": ScanEngineThresholds,
    "scan_activity": ScanActivityThresholds,
    "asset_coverage": AssetCoverageThresholds,
    "data_quality": DataQualityThresholds,
}


def _build_rapid7_config(data: Any) -> Rapid7Config:
    """Validator for the `rapid7:` block.

    Unknown keys reject, scalar types enforced by `_from_dict`. Enum
    membership (auth_mode), positive-int fields (request_timeout_seconds,
    max_retries), range checks (parallel_pages [1,16], page_size [1,500]),
    and the >8 parallel_pages warning are enforced in the post_validate hook.

    Note: the base_url HTTPS check lives in `_build_app_config`, not here.
    """
    def pv(c: Rapid7Config) -> Rapid7Config:
        if c.auth_mode not in _VALID_AUTH_MODES:
            raise ConfigError(
                f"rapid7.auth_mode: must be one of {list(_VALID_AUTH_MODES)}, got {c.auth_mode!r}"
            )
        _positive_int_fields(c, "rapid7", ("request_timeout_seconds", "max_retries"))
        if not (1 <= c.parallel_pages <= 16):
            raise ConfigError(
                f"rapid7.parallel_pages must be in range [1, 16]; got {c.parallel_pages}"
            )
        if c.parallel_pages > 8:
            logger.warning(
                "rapid7.parallel_pages=%d exceeds the documented InsightVM "
                "8-parallel-request limit; proceed at your own risk",
                c.parallel_pages,
            )
        if not (1 <= c.page_size <= 500):
            raise ConfigError(
                f"rapid7.page_size must be in range [1, 500]; got {c.page_size}"
            )
        return c

    return _from_dict(Rapid7Config, data, "rapid7", post_validate=pv)


def _positive_int_fields(obj: Any, path: str, field_names: tuple[str, ...]) -> Any:
    """Raise ConfigError if any named int field on obj is <= 0."""
    for name in field_names:
        val = getattr(obj, name)
        if isinstance(val, int) and not isinstance(val, bool) and val <= 0:
            raise ConfigError(f"{path}.{name}: must be a positive integer, got {val}")
    return obj


def _non_negative_int_fields(obj: Any, path: str, field_names: tuple[str, ...]) -> Any:
    """Raise ConfigError if any named int field on obj is < 0."""
    for name in field_names:
        val = getattr(obj, name)
        if isinstance(val, int) and not isinstance(val, bool) and val < 0:
            raise ConfigError(f"{path}.{name}: must be a non-negative integer, got {val}")
    return obj


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

    # Field classification (confirmed against the dataclasses, config.py:41-73).
    # POS_* = positive-only int fields, NN_* = non-negative int fields.
    # bool fields are validated by _from_dict's _check_scalar(bool) and are NOT
    # listed here.
    POS_SCAN_ENGINES = ("last_contact_warn_hours", "last_contact_fail_hours")
    POS_SCAN_ACTIVITY = ("recent_window_days", "stuck_scan_hours", "site_no_scan_days")
    POS_ASSET_COVERAGE = ("stale_asset_days", "never_scanned_days")
    NN_ASSET_COVERAGE = ("dead_groups_fallback_cap",)
    POS_DATA_QUALITY = ("stale_asset_days",)
    NN_DATA_QUALITY = ("duplicate_detection_max_assets",)

    return Thresholds(
        scan_engines=_from_dict(
            ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines",
            post_validate=lambda o: _positive_int_fields(o, "thresholds.scan_engines", POS_SCAN_ENGINES),
        ),
        scan_activity=_from_dict(
            ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity",
            post_validate=lambda o: _positive_int_fields(o, "thresholds.scan_activity", POS_SCAN_ACTIVITY),
        ),
        asset_coverage=_from_dict(
            AssetCoverageThresholds, data["asset_coverage"], "thresholds.asset_coverage",
            post_validate=lambda o: _non_negative_int_fields(
                _positive_int_fields(o, "thresholds.asset_coverage", POS_ASSET_COVERAGE),
                "thresholds.asset_coverage", NN_ASSET_COVERAGE),
        ),
        data_quality=_from_dict(
            DataQualityThresholds, data["data_quality"], "thresholds.data_quality",
            post_validate=lambda o: _non_negative_int_fields(
                _positive_int_fields(o, "thresholds.data_quality", POS_DATA_QUALITY),
                "thresholds.data_quality", NN_DATA_QUALITY),
        ),
    )


@dataclass(frozen=True)
class BodySpec:
    """The scalar-body slice of a rule-bearing config block -- everything
    beyond its `rules:` mapping.

    `cls` is the config dataclass to parse the body into; `pv` is the
    post-validate hook (the `sample_size` / `+agents_timeout` positive-int
    checks); `required` is the set of keys the block must carry explicitly.

    `required` defaults to `frozenset()` because `AuditConfig` /
    `UserAuditConfig` declare their body fields with no dataclass default, so
    `_from_dict`'s MISSING-derivation already requires them. Only
    `TemplateAuditConfig` populates it (`{enabled, full_scan, sample_size}`) --
    that dataclass *gives* those three defaults, so without the explicit set an
    empty `template_audit: {}` block would silently validate instead of
    erroring. See CONTEXT.md "BodySpec".
    """
    cls: type
    pv: Callable[[Any], Any]
    required: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ConfigBlockSpec:
    """Descriptor carrying the only things that differ between the four
    rule-bearing audit config blocks when `_build_rule_audit_config` parses
    them. The config-parse mirror of `AuditCategory`. See CONTEXT.md
    "ConfigBlockSpec".

    - `path`: dotted location of the rules mapping (e.g. `"audit.rules"`),
      prefixing every `*.rules` error message.
    - `body_path`: dotted location of the block itself (e.g. `"audit"`),
      prefixing body-level mapping/key error messages.
    - `registry`: zero-arg callable returning *this* category's valid rule ids
      (lazy import inside, to dodge the config↔audit circular import).
    - `body`: the block's scalar-body spec, or `None` for a rules-only block
      (`cloud_drift`, which has no `enabled`/`full_scan`/`sample_size`).
    """
    path: str
    body_path: str
    registry: Callable[[], frozenset[str]]
    body: BodySpec | None


def _build_rule_audit_config(data: dict | None, spec: ConfigBlockSpec, *, default: Any) -> Any:
    """The single builder for every rule-bearing audit config block.

    Owns everything identical across the four blocks: the `None → default`
    short-circuit, the mapping checks, the required-key gate, the `_from_dict`
    body parse, and the `_validate_rules_block` + `replace` rule-merge. The
    per-block differences arrive via `spec`. See CONTEXT.md
    "_build_rule_audit_config".

    Error wording matches the pre-collapse builders by construction -- `path`
    and `body_path` carry it -- so the existing config tests pass unchanged.
    The first-failure ordering is preserved per block:

      - rules-only (`spec.body is None`, i.e. cloud_drift): `_validate_dict_schema`
        on the container ("{body_path}: ..."), then the `rules` isinstance check
        ("{path}: expected mapping"), then `_validate_rules_block`.
      - bodied: container isinstance ("{body_path}: expected mapping"), the
        explicit required-key gate, the `rules` isinstance check, then
        `_from_dict` (its own unknown/missing/scalar checks) before
        `_validate_rules_block`.
    """
    if data is None:
        return default

    if spec.body is None:
        _validate_dict_schema(data, expected={"rules"}, required=set(), name=spec.body_path)
        raw_rules = data.get("rules") or {}
        if not isinstance(raw_rules, dict):
            raise ConfigError(f"{spec.path}: expected mapping")
        rules = _validate_rules_block(raw_rules, valid_rule_ids=spec.registry(), path=spec.path)
        return replace(default, rules=rules)

    if not isinstance(data, dict):
        raise ConfigError(f"{spec.body_path}: expected mapping")
    raw = dict(data)
    raw_rules = raw.pop("rules", None) or {}
    missing = spec.body.required - set(raw)
    if missing:
        raise ConfigError(f"{spec.body_path}: missing required key(s): {sorted(missing)}")
    if not isinstance(raw_rules, dict):
        raise ConfigError(f"{spec.path}: expected mapping")
    obj = _from_dict(spec.body.cls, raw, spec.body_path, post_validate=spec.body.pv)
    rules = _validate_rules_block(raw_rules, valid_rule_ids=spec.registry(), path=spec.path)
    return replace(obj, rules=rules)


_AUDIT_BLOCK_SPEC = ConfigBlockSpec(
    path="audit.rules",
    body_path="audit",
    registry=_audit_rule_ids,
    body=BodySpec(
        cls=AuditConfig,
        pv=lambda obj: _positive_int_fields(obj, "audit", ("sample_size", "agents_timeout_seconds")),
    ),
)

_USER_AUDIT_BLOCK_SPEC = ConfigBlockSpec(
    path="user_audit.rules",
    body_path="user_audit",
    registry=_user_rule_ids,
    body=BodySpec(
        cls=UserAuditConfig,
        pv=lambda obj: _positive_int_fields(obj, "user_audit", ("sample_size",)),
    ),
)

_CLOUD_DRIFT_BLOCK_SPEC = ConfigBlockSpec(
    path="cloud_drift.rules",
    body_path="cloud_drift",
    registry=_cloud_rule_ids,
    body=None,
)

_TEMPLATE_AUDIT_BLOCK_SPEC = ConfigBlockSpec(
    path="template_audit.rules",
    body_path="template_audit",
    registry=_template_rule_ids,
    body=BodySpec(
        cls=TemplateAuditConfig,
        pv=lambda obj: _positive_int_fields(obj, "template_audit", ("sample_size",)),
        required=frozenset({"enabled", "full_scan", "sample_size"}),
    ),
)


def _build_audit_config(data: dict | None) -> AuditConfig:
    return _build_rule_audit_config(data, _AUDIT_BLOCK_SPEC, default=_default_audit())


def _build_user_audit_config(data: dict | None) -> UserAuditConfig:
    return _build_rule_audit_config(data, _USER_AUDIT_BLOCK_SPEC, default=_default_user_audit())


def _build_cloud_integration_config(data: dict | None) -> CloudIntegrationConfig:
    """Validator for the optional `cloud_integration:` block.

    Missing block → disabled defaults. Unknown keys reject, scalar types
    enforced by `_from_dict`. Cross-field rules (enabled→base_url required,
    HTTPS prefix), api_key_env non-empty, positive-int fields, and
    parallel_pages range are enforced in the post_validate hook.
    """
    if data is None:
        return _default_cloud_integration()

    def pv(c: CloudIntegrationConfig) -> CloudIntegrationConfig:
        if c.enabled and not c.base_url:
            raise ConfigError("cloud_integration.base_url: required when enabled is true")
        if c.enabled and not c.base_url.startswith("https://"):
            raise ConfigError("cloud_integration.base_url must start with https://")
        if not c.api_key_env:
            raise ConfigError("cloud_integration.api_key_env: expected non-empty str")
        _positive_int_fields(c, "cloud_integration", ("timeout_seconds", "max_retries"))
        if not (1 <= c.parallel_pages <= 16):
            raise ConfigError(
                f"cloud_integration.parallel_pages must be in range [1, 16]; got {c.parallel_pages}"
            )
        return c

    return _from_dict(CloudIntegrationConfig, data, "cloud_integration", post_validate=pv)


def _build_cloud_drift_config(data: dict | None) -> CloudDriftConfig:
    """Validator for the optional `cloud_drift:` block -- a rules-only block
    (no `enabled`/`full_scan`/`sample_size`; sampling does not apply to
    cloud-drift rules and the category enable lives in `checks.cloud_drift_audit`).
    Thin shim over `_build_rule_audit_config` with a `body=None` spec; see
    CONTEXT.md "The four config builders"."""
    return _build_rule_audit_config(data, _CLOUD_DRIFT_BLOCK_SPEC, default=_default_cloud_drift())


def _build_template_audit_config(data: dict | None) -> TemplateAuditConfig:
    """Validator for the `template_audit:` block. Thin shim over
    `_build_rule_audit_config`; its spec carries the explicit
    `{enabled, full_scan, sample_size}` required-key gate (load-bearing because
    `TemplateAuditConfig` gives those fields defaults). See CONTEXT.md
    "The four config builders" / "BodySpec"."""
    return _build_rule_audit_config(data, _TEMPLATE_AUDIT_BLOCK_SPEC, default=_default_template_audit())


def _build_report_config(data: Any) -> ReportConfig:
    """Validate the `report:` block, allowing `delta_max_age_days` to be absent.

    Accepts:
      - missing key  -> default 30
      - integer >= 0 -> use as-is
      - null/None    -> delta disabled
    Rejects unknown keys (consistent with `_from_dict`).

    `delta_max_age_days` is `int | None`. `get_type_hints` resolves this to
    `Optional[int]`, which `_check_scalar`'s `if expected is int` does NOT
    match -- it would hit the "unsupported declared type" branch and raise.
    So we pop `delta_max_age_days` before calling `_from_dict`, validate it
    by hand (non-negative int or None; reject bool and negative), then
    re-attach it via `replace` after `_from_dict` returns.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"report: expected mapping, got {type(data).__name__}")
    raw = dict(data)
    # Pop the union field before _from_dict -- validated and re-attached below.
    delta = raw.pop("delta_max_age_days", 30)
    if delta is not None and (not isinstance(delta, int) or isinstance(delta, bool) or delta < 0):
        raise ConfigError("report.delta_max_age_days: expected non-negative int or null")

    def pv(c: ReportConfig) -> ReportConfig:
        if c.log_format not in ("plain", "cmtrace", "json"):
            raise ConfigError(
                f"report.log_format: invalid value {c.log_format!r}; "
                f"must be one of: plain, cmtrace, json"
            )
        return c

    obj = _from_dict(ReportConfig, raw, "report", post_validate=pv)
    return replace(obj, delta_max_age_days=delta)


def _ensure_default_on(checks: dict, *names: str) -> dict:
    """Return `checks` with any missing name defaulted to ``True``.

    Preserves explicit user values: if a key is already present (even with
    ``False``), it is not overwritten. Mutates and returns a copy of the
    input dict only when at least one name was missing -- when every name
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
