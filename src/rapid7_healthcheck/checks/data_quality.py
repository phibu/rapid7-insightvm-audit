from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class DataQualityCheck:
    name = "Data Quality"
    description = "Assets without OS fingerprint and sites with zero assets."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.data_quality
        findings: list[Finding] = []

        missing_os: list[dict] = []
        if t.flag_missing_os:
            missing_filter = {
                "filters": [{"field": "os-name", "operator": "is-empty"}],
                "match": "all",
            }
            missing_os = list(client.paginate_post("/api/3/assets/search", json_body=missing_filter))
            if missing_os:
                findings.append(Finding(
                    severity="warn",
                    message=f"{len(missing_os)} asset(s) have no OS fingerprint",
                    details={"total": len(missing_os), "examples": _example_hostnames(missing_os)},
                ))

        empty_sites: list[dict] = []
        if t.flag_empty_sites:
            for site in client.paginate("/api/3/sites"):
                site_id = site.get("id")
                body = client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
                total = int(body.get("page", {}).get("totalResources", 0))
                if total == 0:
                    empty_sites.append(site)
            if empty_sites:
                findings.append(Finding(
                    severity="warn",
                    message=f"{len(empty_sites)} site(s) have zero assets",
                    details={
                        "total": len(empty_sites),
                        "examples": [s.get("name", f"id={s.get('id')}") for s in empty_sites[:_EXAMPLES_LIMIT]],
                    },
                ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "missing_os_count": len(missing_os),
                "empty_sites_count": len(empty_sites),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
