from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or has unknown keys."""


@dataclass(frozen=True)
class Rapid7Config:
    base_url: str
    verify_tls: bool
    request_timeout_seconds: int
    max_retries: int


@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str


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


@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict[str, bool]


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
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        value = data[f.name]
        sub_path = f"{path}.{f.name}" if path else f.name
        if is_dataclass(f.type) if isinstance(f.type, type) else False:
            kwargs[f.name] = _from_dict(f.type, value, sub_path)
        else:
            kwargs[f.name] = value
    return cls(**kwargs)


_NESTED = {
    "rapid7": Rapid7Config,
    "report": ReportConfig,
    "thresholds": Thresholds,
}
_THRESHOLD_NESTED = {
    "scan_engines": ScanEngineThresholds,
    "scan_activity": ScanActivityThresholds,
    "asset_coverage": AssetCoverageThresholds,
    "data_quality": DataQualityThresholds,
}


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


def _build_app_config(data: dict) -> AppConfig:
    expected_root = {"rapid7", "report", "thresholds", "checks"}
    unknown = set(data.keys()) - expected_root
    if unknown:
        raise ConfigError(f"unknown root key(s): {sorted(unknown)}")
    missing = expected_root - set(data.keys())
    if missing:
        raise ConfigError(f"missing required root key(s): {sorted(missing)}")

    rapid7 = _from_dict(Rapid7Config, data["rapid7"], "rapid7")
    if not rapid7.base_url.startswith("https://"):
        raise ConfigError("rapid7.base_url must start with https://")

    report = _from_dict(ReportConfig, data["report"], "report")
    thresholds = _build_thresholds(data["thresholds"])

    checks = data["checks"]
    if not isinstance(checks, dict) or not all(isinstance(v, bool) for v in checks.values()):
        raise ConfigError("checks: expected mapping of name -> bool")

    return AppConfig(rapid7=rapid7, report=report, thresholds=thresholds, checks=checks)


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
