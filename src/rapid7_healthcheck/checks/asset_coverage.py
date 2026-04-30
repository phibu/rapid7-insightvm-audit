from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
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
        if t.flag_unscanned_assets:
            unscanned_filter = {
                "filters": [
                    {
                        "field": "last-scan-date",
                        "operator": "is-earlier-than",
                        "value": t.never_scanned_days,
                    }
                ],
                "match": "all",
            }
            unscanned = list(client.paginate_post("/api/3/assets/search", json_body=unscanned_filter))

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
                message=f"{len(unscanned)} asset(s) have not been scanned in the last {t.never_scanned_days} days",
                details={"total": len(unscanned), "examples": _example_hostnames(unscanned)},
            ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "stale_count": len(stale),
                "unscanned_count": len(unscanned),
                "total_assets": len(stale) + len(unscanned),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
