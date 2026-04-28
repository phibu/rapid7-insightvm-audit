from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class ScanEnginesCheck:
    name = "Scan Engines"
    description = "Health and pairing status of all configured scan engines."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        thresholds = config.thresholds.scan_engines
        body = client.get("/api/3/scan_engines")
        engines = body.get("resources", [])
        now = datetime.now(timezone.utc)

        findings: list[Finding] = []
        warn_count = 0
        fail_count = 0

        for engine in engines:
            name = engine.get("name", f"id={engine.get('id')}")
            status = engine.get("status", "unknown")
            last_refreshed = _parse_iso(engine.get("lastRefreshedDate"))
            sites = engine.get("sites") or []

            if status == "inactive" or status == "unknown":
                findings.append(Finding(
                    severity="fail",
                    message=f"Engine '{name}' status is '{status}'",
                    details={"id": engine.get("id"), "status": status},
                ))
                fail_count += 1
                continue

            if last_refreshed is None:
                findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' has no lastRefreshedDate",
                    details={"id": engine.get("id")},
                ))
                warn_count += 1
                continue

            age_hours = (now - last_refreshed).total_seconds() / 3600.0
            if age_hours >= thresholds.last_contact_fail_hours:
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_fail_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
                fail_count += 1
            elif age_hours >= thresholds.last_contact_warn_hours:
                findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_warn_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
                warn_count += 1

            if not sites:
                findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' is not paired with any sites",
                    details={"id": engine.get("id")},
                ))
                warn_count += 1

        total = len(engines)
        healthy = total - warn_count - fail_count
        # An engine can produce both an age finding and a pairing finding; healthy is bounded at >= 0.
        if healthy < 0:
            healthy = 0

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "engines_total": total,
                "engines_healthy": healthy,
                "engines_warn": warn_count,
                "engines_fail": fail_count,
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
