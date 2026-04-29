from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.asset_coverage

        stale_filter = {
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-earlier-than",
                    "value": t.stale_asset_days,
                }
            ],
            "match": "all",
        }
        stale = list(client.paginate_post("/api/3/assets/search", json_body=stale_filter))

        unscanned: list[dict] = []
        unscanned_unavailable = False
        if t.flag_unscanned_assets:
            unscanned_filter = {
                "filters": [
                    {"field": "last-scan-date", "operator": "is-empty"}
                ],
                "match": "all",
            }
            try:
                unscanned = list(client.paginate_post("/api/3/assets/search", json_body=unscanned_filter))
            except Rapid7ClientError as e:
                # Some consoles reject is-empty on date fields with HTTP 400;
                # the rest of the check is still useful, so degrade rather than abort.
                if "400" in str(e) and "is-empty" in str(e):
                    unscanned_unavailable = True
                else:
                    raise

        findings: list[Finding] = []
        if stale:
            findings.append(Finding(
                severity="warn",
                message=f"{len(stale)} stale asset(s) (no scan in last {t.stale_asset_days} days)",
                details={"total": len(stale), "examples": _example_hostnames(stale)},
            ))
        if unscanned:
            findings.append(Finding(
                severity="fail",
                message=f"{len(unscanned)} asset(s) have never been scanned",
                details={"total": len(unscanned), "examples": _example_hostnames(unscanned)},
            ))
        if unscanned_unavailable:
            findings.append(Finding(
                severity="info",
                message=(
                    "Console rejected the 'is-empty' filter on last-scan-date; "
                    "never-scanned asset count not available. Set "
                    "asset_coverage.flag_unscanned_assets: false in config.yaml "
                    "to suppress this notice."
                ),
                details={"reason": "is-empty operator unsupported on this console"},
            ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "stale_count": len(stale),
                "unscanned_count": len(unscanned),
                "unscanned_unavailable": unscanned_unavailable,
                "total_assets": len(stale) + len(unscanned),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
