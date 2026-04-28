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
from rapid7_healthcheck.checks import Check, CheckResult
from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.checks.data_quality import DataQualityCheck
from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck
from rapid7_healthcheck.checks.scan_engines import ScanEnginesCheck
from rapid7_healthcheck.client import Rapid7AuthError, Rapid7Client, Rapid7ClientError
from rapid7_healthcheck.config import AppConfig, ConfigError, load_config
from rapid7_healthcheck.report import ReportContext, write_report


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
}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rapid7-healthcheck")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    p.add_argument("--output", default=None, help="Override report output path")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    p.add_argument("--log-file", default=None, help="Also write logs to this file")
    return p.parse_args(argv)


def _setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def build_thresholds_table(cfg: AppConfig) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for section_name in ("scan_engines", "scan_activity", "asset_coverage", "data_quality"):
        section = getattr(cfg.thresholds, section_name)
        for f in fields(section):
            value = getattr(section, f.name)
            rows.append((f"{section_name}.{f.name}", str(value)))
    return rows


def pick_exit_code(results: list[CheckResult]) -> int:
    if any(r.status in ("fail", "error") for r in results):
        return EXIT_FAIL
    if any(r.status == "warn" for r in results):
        return EXIT_WARN
    return EXIT_HEALTHY


def _run_checks(client: Any, cfg: AppConfig) -> list[CheckResult]:
    results: list[CheckResult] = []
    for name, check_cls in _REGISTRY.items():
        enabled = cfg.checks.get(name, False)
        if not enabled:
            instance = check_cls()
            results.append(CheckResult(
                name=instance.name,
                description=instance.description,
                status="skipped",
            ))
            continue
        instance = check_cls()
        logger.info("running check: %s", instance.name)
        start = time.monotonic()
        try:
            results.append(instance.run(client, cfg))
        except Exception as e:  # per-check isolation
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception("check %s failed", instance.name)
            results.append(CheckResult(
                name=instance.name,
                description=instance.description,
                status="error",
                error=str(e),
                duration_ms=duration_ms,
            ))
    return results


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _setup_logging(args.verbose, args.log_file)
    load_dotenv(override=False)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("config error: %s", e)
        return EXIT_STARTUP

    api_key = os.environ.get("R7_API_KEY")
    if not api_key:
        logger.error("R7_API_KEY environment variable is not set")
        return EXIT_STARTUP

    if not cfg.rapid7.verify_tls:
        logger.warning("TLS verification disabled (verify_tls: false)")

    try:
        client = Rapid7Client(
            base_url=cfg.rapid7.base_url,
            api_key=api_key,
            verify_tls=cfg.rapid7.verify_tls,
            timeout_seconds=cfg.rapid7.request_timeout_seconds,
            max_retries=cfg.rapid7.max_retries,
        )
        client.connect()
    except Rapid7AuthError as e:
        logger.error("authentication failed: %s", e)
        return EXIT_STARTUP
    except Rapid7ClientError as e:
        logger.error("could not reach Rapid7 (%s); check base_url and network", e)
        return EXIT_STARTUP

    results = _run_checks(client, cfg)

    ctx = ReportContext(
        title=cfg.report.title,
        generated_at=datetime.now(timezone.utc),
        base_url_host=urlparse(cfg.rapid7.base_url).hostname or cfg.rapid7.base_url,
        tool_version=__version__,
        config_path=args.config,
        results=results,
        thresholds_table=build_thresholds_table(cfg),
    )

    if args.output:
        out = write_report(ctx, explicit_path=Path(args.output))
    else:
        out = write_report(
            ctx,
            output_dir=Path(cfg.report.output_dir),
            filename_pattern=cfg.report.filename_pattern,
        )

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
