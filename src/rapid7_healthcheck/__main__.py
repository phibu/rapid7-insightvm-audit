from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

from rapid7_healthcheck import __version__
from rapid7_healthcheck.audit import ConfigurationAuditCheck
from rapid7_healthcheck.audit.rule_rollup import worst_status
from rapid7_healthcheck.audit.cloud_drift import CloudDriftAuditCheck
from rapid7_healthcheck.audit.template import TemplateAuditCheck
from rapid7_healthcheck.audit.user_permission import UserPermissionAuditCheck
from rapid7_healthcheck.checks import Check, CheckResult
from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.checks.data_quality import DataQualityCheck
from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck
from rapid7_healthcheck.checks.scan_engines import ScanEnginesCheck
from rapid7_healthcheck._log import (
    FlushingFileHandler,
    ProgressAwareStreamHandler,
    make_file_formatter,
)
from rapid7_healthcheck.client import Rapid7AuthError, Rapid7Client, Rapid7ClientError
from rapid7_healthcheck.cloud_client import CloudClient
from rapid7_healthcheck.config import (
    AppConfig,
    CloudIntegrationConfig,
    ConfigError,
    Rapid7Config,
    load_config,
)
from rapid7_healthcheck.report import InventoryTotals, ReportContext, write_report


EXIT_HEALTHY = 0
EXIT_WARN = 1
EXIT_FAIL = 2
EXIT_STARTUP = 3
EXIT_INTERNAL = 4

logger = logging.getLogger("rapid7_healthcheck")


_REGISTRY: dict[str, type[Check]] = {
    "scan_engines": ScanEnginesCheck,
    "scan_activity": ScanActivityCheck,
    "asset_coverage": AssetCoverageCheck,
    "data_quality": DataQualityCheck,
    "configuration_audit": ConfigurationAuditCheck,
    "user_permission_audit": UserPermissionAuditCheck,
    "cloud_drift_audit": CloudDriftAuditCheck,
    "template_audit": TemplateAuditCheck,
}


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Split out from ``_parse_args`` so the frozen flag set is introspectable
    (the 1.0 contract-lock test asserts the exact option strings). The set of
    flags here is part of the 1.0 public contract — see
    ``tests/test_contract_lock.py``.
    """
    p = argparse.ArgumentParser(prog="rapid7-healthcheck")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    p.add_argument("--output", default=None, help="Override report output path")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    p.add_argument("--log-file", default=None, help="Also write logs to this file")
    p.add_argument("--no-log-file", action="store_true", help="Suppress the default-on run log file")
    p.add_argument(
        "--check-connection",
        action="store_true",
        help=(
            "Validate config, credentials, and console connectivity, then exit "
            "(no checks run, no report written). Exit 0 = reachable; 3 = "
            "config/auth/network failure."
        ),
    )
    p.add_argument(
        "--log-format",
        choices=["plain", "cmtrace", "json"],
        default=None,
        help="File log format. Overrides report.log_format. Stderr stays plain.",
    )
    progress_group = p.add_mutually_exclusive_group()
    progress_group.add_argument(
        "--progress",
        action="store_true",
        help="Force progress output on (overrides TTY auto-detect).",
    )
    progress_group.add_argument(
        "--no-progress",
        action="store_true",
        help="Suppress progress output (overrides TTY auto-detect).",
    )
    return p


def _parse_args(argv: list[str]) -> argparse.Namespace:
    return _build_parser().parse_args(argv)


def _resolve_progress_enabled(*, progress: bool, no_progress: bool) -> bool | None:
    """Map CLI flags to the ProgressReporter `enabled` value.

    --no-progress wins (False), then --progress (True), else None (auto-detect).
    """
    if no_progress:
        return False
    if progress:
        return True
    return None


def _setup_logging(verbose: bool, log_file: str | None, log_format: str = "plain") -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [ProgressAwareStreamHandler(sys.stderr)]
    file_open_error: str | None = None
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = FlushingFileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(make_file_formatter(log_format))
            handlers.append(file_handler)
        except OSError as e:
            file_open_error = f"log file unavailable ({log_file}); continuing without file logging: {e}"
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    if file_open_error:
        logging.getLogger(__name__).warning(file_open_error)


def _build_cloud_client_or_none(
    cloud_integration: CloudIntegrationConfig,
) -> tuple[CloudClient | None, str | None]:
    """Construct a CloudClient if cloud_integration is enabled and the
    env var holds a key; otherwise return ``(None, error_or_None)``.

    The ``error`` string (when non-None) is logged and surfaced to the
    user as a startup error: enabling cloud integration without the key
    is a config mistake, so we exit 3 in __main__ rather than silently
    skipping the audit category.
    """
    if not cloud_integration.enabled:
        return None, None
    key = os.environ.get(cloud_integration.api_key_env)
    if not key:
        return None, (
            f"cloud_integration.enabled=true but env var "
            f"{cloud_integration.api_key_env} is not set"
        )
    client = CloudClient(
        base_url=cloud_integration.base_url,
        api_key=key,
        timeout_seconds=cloud_integration.timeout_seconds,
        max_retries=cloud_integration.max_retries,
        parallel_pages=cloud_integration.parallel_pages,
    )
    return client, None


def _resolve_auth_or_none(
    rapid7: Rapid7Config,
) -> tuple[tuple[str | None, tuple[str, str] | None] | None, str | None]:
    """Resolve the ``(api_key, basic_auth)`` the Rapid7Client takes from the
    configured ``auth_mode`` plus the environment, or ``(None, error)``.

    Peer of ``_build_cloud_client_or_none``: reads ``os.environ`` inside and
    returns ``(value, error_or_None)``. The ``error`` string (when non-None) is
    logged and surfaced as a startup error — a configured ``auth_mode`` whose
    env vars are unset is an operator mistake, so __main__ exits 3 rather than
    proceeding without credentials.

    On success the value is a ``(api_key, basic_auth)`` pair where exactly one
    side is populated: ``(key, None)`` for ``api_key`` mode, ``(None, (user,
    password))`` for ``basic``. ``auth_mode`` is already validated against
    ``_VALID_AUTH_MODES`` by config loading, so no else-branch is needed.
    """
    if rapid7.auth_mode == "api_key":
        api_key = os.environ.get("R7_API_KEY")
        if not api_key:
            return None, "R7_API_KEY environment variable is not set"
        return (api_key, None), None

    # basic
    user = os.environ.get("R7_BASIC_USER")
    password = os.environ.get("R7_BASIC_PASSWORD")
    if not user:
        return None, "R7_BASIC_USER environment variable is not set"
    if not password:
        return None, "R7_BASIC_PASSWORD environment variable is not set"
    return (None, (user, password)), None


def _resolve_log_file(args: argparse.Namespace, cfg: AppConfig, log_format: str) -> Path | None:
    """Resolve which path (if any) the run-log FileHandler should write to.

    Precedence:
      1. --no-log-file  -> None (suppress)
      2. --log-file <p> -> <p> (explicit override; honored verbatim)
      3. --output <p>   -> <p> with .log suffix (alongside report)
      4. otherwise      -> cfg.report.output_dir + filename pattern with
                           format-aware suffix (.jsonl for json, else .log)

    Format-aware suffix applies ONLY to step 4. Explicit user paths in
    steps 2 and 3 are never rewritten.
    """
    if getattr(args, "no_log_file", False):
        return None
    if getattr(args, "log_file", None):
        return Path(args.log_file)
    if getattr(args, "output", None):
        return Path(args.output).with_suffix(".log")
    # Derive from config — mirror what write_report does for the default path.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    base = cfg.report.filename_pattern.replace("{timestamp}", timestamp)
    suffix = ".jsonl" if log_format == "json" else ".log"
    log_name = Path(base).with_suffix(suffix).name
    return Path(cfg.report.output_dir) / log_name


def build_thresholds_table(cfg: AppConfig) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for section_name in ("scan_engines", "scan_activity", "asset_coverage", "data_quality"):
        section = getattr(cfg.thresholds, section_name)
        for f in fields(section):
            value = getattr(section, f.name)
            rows.append((f"{section_name}.{f.name}", str(value)))
    return rows


# The process exit code for each worst-status outcome. The status precedence
# lives once, in `worst_status`; this is only the status->int mapping. The
# startup/internal exit codes (3/4) are not run-status outcomes and never come
# from here. `worst_status` collapses the run to one of fail/warn/pass, so those
# three are the only keys reached.
_EXIT_BY_STATUS: dict[str, int] = {
    "fail": EXIT_FAIL,
    "warn": EXIT_WARN,
    "pass": EXIT_HEALTHY,
}


def pick_exit_code(results: list[CheckResult]) -> int:
    return _EXIT_BY_STATUS[worst_status(results)]


def _build_inventory_totals(snapshot: Any) -> "InventoryTotals | None":
    """Build the InventoryTotals dataclass from the shared EnvSnapshot.

    A single snapshot-accessor failure should not kill the whole report —
    if any accessor raises, log and return None, and the template skips
    the inventory strip.
    """
    try:
        groups = snapshot.asset_groups()
        static = sum(1 for g in groups if g.get("type") == "static")
        dynamic = sum(1 for g in groups if g.get("type") == "dynamic")
        return InventoryTotals(
            total_assets=snapshot.total_asset_count(),
            total_sites=len(snapshot.sites()),
            total_scan_engines=len(snapshot.scan_engines()),
            total_asset_groups_static=static,
            total_asset_groups_dynamic=dynamic,
            total_scans=snapshot.scans_total(),
        )
    except Exception:
        logger.exception("inventory totals build failed; report will skip the strip")
        return None


def _run_checks(
    client: Any,
    cfg: AppConfig,
    snapshot: Any,
    progress: "ProgressReporter | None" = None,
    *,
    cloud_client: Any = None,
) -> list[CheckResult]:
    # The caller owns the snapshot (since 0.6.6) so it can be shared with the
    # inventory-totals builder. Op-checks accept it via the `snapshot=` kwarg;
    # audit checks still build their own snapshot internally today (deferred
    # cleanup — see backlog).
    results: list[CheckResult] = []
    total = len(_REGISTRY)
    for idx, (name, check_cls) in enumerate(_REGISTRY.items(), start=1):
        enabled = cfg.checks.get(name, False)
        instance = check_cls()
        if not enabled:
            results.append(CheckResult(
                name=instance.name,
                description=instance.description,
                status="skipped",
            ))
            if progress is not None:
                progress.finish_check(idx, total, instance.name, status_text="skipped")
            continue
        if progress is not None:
            progress.start_check(idx, total, instance.name)
        logger.info("running check: %s", instance.name)
        start = time.monotonic()
        try:
            try:
                # Every check accepts the same optional-kwarg superset and uses
                # only what it needs (op-checks read snapshot, cloud-drift reads
                # cloud_client, audits read progress). Dispatch is uniform — no
                # branching on check identity. See CONTEXT.md "Check dispatch".
                results.append(instance.run(
                    client, cfg,
                    snapshot=snapshot,
                    cloud_client=cloud_client,
                    progress=progress,
                ))
            except Exception as e:  # per-check isolation
                logger.exception("check %s failed", instance.name)
                results.append(CheckResult(
                    name=instance.name,
                    description=instance.description,
                    status="error",
                    error=str(e),
                    duration_ms=int((time.monotonic() - start) * 1000),
                ))
        finally:
            if progress is not None:
                from rapid7_healthcheck.progress import format_duration
                progress.finish_check(
                    idx, total, instance.name,
                    status_text=format_duration(int((time.monotonic() - start) * 1000)),
                )
    return results


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    # First pass: stderr-only so config errors are visible. log_format is plain
    # because we don't have the config yet; this pass never opens a file.
    _setup_logging(args.verbose, log_file=None, log_format="plain")
    load_dotenv(override=False)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("config error: %s", e)
        return EXIT_STARTUP

    # Effective format: CLI override > config default.
    effective_log_format = args.log_format or cfg.report.log_format

    # Second pass: now we know where the log should go and in which format.
    resolved_log = _resolve_log_file(args, cfg, effective_log_format)
    _setup_logging(
        args.verbose,
        log_file=str(resolved_log) if resolved_log else None,
        log_format=effective_log_format,
    )

    auth, auth_error = _resolve_auth_or_none(cfg.rapid7)
    if auth_error is not None:
        logger.error(auth_error)
        return EXIT_STARTUP
    api_key, basic_auth = auth

    if not cfg.rapid7.verify_tls:
        logger.warning("TLS verification disabled (verify_tls: false)")

    try:
        client = Rapid7Client(
            base_url=cfg.rapid7.base_url,
            api_key=api_key,
            basic_auth=basic_auth,
            verify_tls=cfg.rapid7.verify_tls,
            timeout_seconds=cfg.rapid7.request_timeout_seconds,
            max_retries=cfg.rapid7.max_retries,
            parallel_pages=cfg.rapid7.parallel_pages,
            default_page_size=cfg.rapid7.page_size,
        )
        client.connect()
    except Rapid7AuthError as e:
        logger.error("authentication failed: %s", e)
        return EXIT_STARTUP
    except Rapid7ClientError as e:
        logger.error("could not reach Rapid7 (%s); check base_url and network", e)
        return EXIT_STARTUP

    if args.check_connection:
        # Pre-flight: config loaded, auth resolved, and the console answered
        # client.connect(). Report success and exit before running any checks
        # or writing a report. Failures already returned EXIT_STARTUP above.
        logger.info(
            "connection OK: reached %s and authenticated successfully",
            cfg.rapid7.base_url,
        )
        return EXIT_HEALTHY

    cloud_client, cloud_error = _build_cloud_client_or_none(cfg.cloud_integration)
    if cloud_error is not None:
        logger.error("config error: %s", cloud_error)
        return EXIT_STARTUP

    from rapid7_healthcheck.progress import ProgressReporter
    progress = ProgressReporter(
        enabled=_resolve_progress_enabled(
            progress=args.progress,
            no_progress=args.no_progress,
        )
    )

    from rapid7_healthcheck.audit.snapshot import build_env_snapshot
    snapshot = build_env_snapshot(
        client,
        sampling=cfg.audit,
        agents_timeout_seconds=cfg.audit.agents_timeout_seconds,
    )

    results = _run_checks(client, cfg, snapshot, progress=progress, cloud_client=cloud_client)

    inventory_totals = _build_inventory_totals(snapshot)

    progress.newline_if_needed()
    ctx = ReportContext(
        title=cfg.report.title,
        generated_at=datetime.now(timezone.utc),
        base_url_host=urlparse(cfg.rapid7.base_url).hostname or cfg.rapid7.base_url,
        tool_version=__version__,
        config_path=args.config,
        results=results,
        thresholds_table=build_thresholds_table(cfg),
        inventory_totals=inventory_totals,
    )

    if args.output:
        out = write_report(ctx, explicit_path=Path(args.output),
                           delta_max_age_days=cfg.report.delta_max_age_days)
    else:
        out = write_report(
            ctx,
            output_dir=Path(cfg.report.output_dir),
            filename_pattern=cfg.report.filename_pattern,
            delta_max_age_days=cfg.report.delta_max_age_days,
        )

    progress.newline_if_needed()
    print(out.resolve())
    return pick_exit_code(results)


def main() -> None:
    try:
        sys.exit(run())
    except Exception:
        logger.exception("internal error")
        sys.exit(EXIT_INTERNAL)


if __name__ == "__main__":
    main()
