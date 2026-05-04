from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
)
from rapid7_healthcheck.config import AppConfig

_SRC_SCAN_ENGINES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Scan-Engine"
_SRC_ENGINE_STATUS = "https://docs.rapid7.com/insightvm/managing-scan-engines"


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

        bad_status_findings: list[Finding] = []
        missing_refresh_findings: list[Finding] = []
        last_contact_findings: list[Finding] = []
        unpaired_findings: list[Finding] = []
        per_engine_worst: list[str | None] = []

        for engine in engines:
            engine_worst: str | None = None
            name = engine.get("name", f"id={engine.get('id')}")
            status = engine.get("status", "unknown")
            last_refreshed = _parse_iso(engine.get("lastRefreshedDate"))
            sites = engine.get("sites") or []

            if status == "inactive" or status == "unknown":
                bad_status_findings.append(Finding(
                    severity="fail",
                    message=f"Engine '{name}' status is '{status}'",
                    details={"id": engine.get("id"), "status": status},
                ))
                per_engine_worst.append("fail")
                continue

            if last_refreshed is None:
                missing_refresh_findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' has no lastRefreshedDate",
                    details={"id": engine.get("id")},
                ))
                engine_worst = "warn"
            else:
                age_hours = (now - last_refreshed).total_seconds() / 3600.0
                if age_hours >= thresholds.last_contact_fail_hours:
                    last_contact_findings.append(Finding(
                        severity="fail",
                        message=(
                            f"Engine '{name}' last contact {age_hours:.1f}h ago "
                            f"(threshold {thresholds.last_contact_fail_hours}h)"
                        ),
                        details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                    ))
                    engine_worst = "fail"
                elif age_hours >= thresholds.last_contact_warn_hours:
                    last_contact_findings.append(Finding(
                        severity="warn",
                        message=(
                            f"Engine '{name}' last contact {age_hours:.1f}h ago "
                            f"(threshold {thresholds.last_contact_warn_hours}h)"
                        ),
                        details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                    ))
                    engine_worst = "warn"

            if not sites:
                unpaired_findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' is not paired with any sites",
                    details={"id": engine.get("id")},
                ))
                if engine_worst != "fail":
                    engine_worst = "warn"

            per_engine_worst.append(engine_worst)

        total = len(engines)
        warn_engines = sum(1 for s in per_engine_worst if s == "warn")
        fail_engines = sum(1 for s in per_engine_worst if s == "fail")
        healthy_engines = sum(1 for s in per_engine_worst if s is None)

        rule_results: list[RuleResult] = [
            make_rule_result(
                rule_id="op.scan_engines.bad_status",
                rule_name="Engines in inactive or unknown state",
                description=(
                    "Scan engines reporting status 'inactive' or 'unknown' — "
                    "console can no longer reach them."
                ),
                findings=bad_status_findings,
                sources=[_SRC_SCAN_ENGINES, _SRC_ENGINE_STATUS],
                summary={"count": len(bad_status_findings)},
                default_severity="fail",
            ),
            make_rule_result(
                rule_id="op.scan_engines.last_contact",
                rule_name="Engines past last-contact threshold",
                description=(
                    "Engines whose lastRefreshedDate exceeds the warn or fail threshold. "
                    "Indicates degraded console-engine connectivity."
                ),
                findings=last_contact_findings,
                sources=[_SRC_SCAN_ENGINES, _SRC_ENGINE_STATUS],
                summary={"count": len(last_contact_findings)},
                default_severity="warn",
            ),
            make_rule_result(
                rule_id="op.scan_engines.missing_last_refresh",
                rule_name="Engines missing lastRefreshedDate",
                description=(
                    "Engines that report no lastRefreshedDate at all — usually a "
                    "freshly paired engine that has not yet completed a refresh."
                ),
                findings=missing_refresh_findings,
                sources=[_SRC_SCAN_ENGINES],
                summary={"count": len(missing_refresh_findings)},
                default_severity="warn",
            ),
            make_rule_result(
                rule_id="op.scan_engines.unpaired",
                rule_name="Engines not paired with any sites",
                description=(
                    "Engines configured on the console but not assigned to any site — "
                    "they sit idle and consume no work."
                ),
                findings=unpaired_findings,
                sources=[_SRC_SCAN_ENGINES],
                summary={"count": len(unpaired_findings)},
                default_severity="warn",
            ),
        ]

        # Build a per-check summary that retains the existing engine-count metrics
        # *and* the rule rollup the template's tile strip expects.
        summary = rule_summary(rule_results)
        summary.update({
            "engines_total": total,
            "engines_healthy": healthy_engines,
            "engines_warn": warn_engines,
            "engines_fail": fail_engines,
        })

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=summary,
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )
