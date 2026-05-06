from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, NamedTuple

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    safe_run_rule,
)
from rapid7_healthcheck.config import AppConfig

_SRC_SCAN_ENGINES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Scan-Engine"
_SRC_ENGINE_STATUS = "https://docs.rapid7.com/insightvm/managing-scan-engines"


# Per v3 ScanEngine.status enum: [active, incompatible-version, not-responding,
# pending-authorization, unknown]. "active" is the only good state.
class _BadStatus(NamedTuple):
    severity: str
    reason: str


_BAD_STATUS: dict[str, _BadStatus] = {
    "incompatible-version": _BadStatus(
        "fail",
        "engine code is incompatible with this console; cannot scan",
    ),
    "not-responding": _BadStatus(
        "fail",
        "console cannot reach engine; scans blocked",
    ),
    "pending-authorization": _BadStatus(
        "warn",
        "engine reachable but not yet authorized",
    ),
    "unknown": _BadStatus(
        "warn",
        "engine status is indeterminate",
    ),
}


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _engine_name(engine: dict) -> str:
    return engine.get("name", f"id={engine.get('id')}")


class EngineBadStatusRule:
    RULE_ID = "op.scan_engines.bad_status"
    RULE_NAME = "Engines in non-active state"
    DESCRIPTION = (
        "Scan engines whose status is 'incompatible-version', 'not-responding', "
        "'pending-authorization', or 'unknown' — console cannot reliably use them "
        "for scans. Severity per finding: incompatible-version and not-responding "
        "are fail; pending-authorization and unknown are warn."
    )
    SOURCES = (_SRC_SCAN_ENGINES, _SRC_ENGINE_STATUS)
    DEFAULT_SEVERITY = "fail"

    def run(self, engines: list[dict]) -> RuleResult:
        findings: list[Finding] = []
        for engine in engines:
            status = engine.get("status", "unknown")
            if status not in _BAD_STATUS:
                continue
            bad = _BAD_STATUS[status]
            name = _engine_name(engine)
            findings.append(Finding(
                severity=bad.severity,
                message=f"Engine '{name}' status is '{status}' — {bad.reason}",
                details={"id": engine.get("id"), "status": status},
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            default_severity=self.DEFAULT_SEVERITY,
        )


class EngineLastContactRule:
    RULE_ID = "op.scan_engines.last_contact"
    RULE_NAME = "Engines past last-contact threshold"
    DESCRIPTION = (
        "Engines whose lastRefreshedDate exceeds the warn or fail threshold. "
        "Indicates degraded console-engine connectivity."
    )
    SOURCES = (_SRC_SCAN_ENGINES, _SRC_ENGINE_STATUS)
    DEFAULT_SEVERITY = "warn"

    def run(self, engines: list[dict], thresholds) -> RuleResult:
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)
        for engine in engines:
            status = engine.get("status", "unknown")
            if status in _BAD_STATUS:
                continue
            last_refreshed = _parse_iso(engine.get("lastRefreshedDate"))
            if last_refreshed is None:
                continue
            age_hours = (now - last_refreshed).total_seconds() / 3600.0
            name = _engine_name(engine)
            if age_hours >= thresholds.last_contact_fail_hours:
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_fail_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
            elif age_hours >= thresholds.last_contact_warn_hours:
                findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_warn_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            default_severity=self.DEFAULT_SEVERITY,
        )


class EngineMissingLastRefreshRule:
    RULE_ID = "op.scan_engines.missing_last_refresh"
    RULE_NAME = "Engines missing lastRefreshedDate"
    DESCRIPTION = (
        "Engines that report no lastRefreshedDate at all — usually a freshly "
        "paired engine that has not yet completed a refresh."
    )
    SOURCES = (_SRC_SCAN_ENGINES,)
    DEFAULT_SEVERITY = "warn"

    def run(self, engines: list[dict]) -> RuleResult:
        findings: list[Finding] = []
        for engine in engines:
            status = engine.get("status", "unknown")
            if status in _BAD_STATUS:
                continue
            if _parse_iso(engine.get("lastRefreshedDate")) is not None:
                continue
            name = _engine_name(engine)
            findings.append(Finding(
                severity="warn",
                message=f"Engine '{name}' has no lastRefreshedDate",
                details={"id": engine.get("id")},
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            default_severity=self.DEFAULT_SEVERITY,
        )


class EngineUnpairedRule:
    RULE_ID = "op.scan_engines.unpaired"
    RULE_NAME = "Engines not paired with any sites"
    DESCRIPTION = (
        "Engines configured on the console but not assigned to any site — "
        "they sit idle and consume no work."
    )
    SOURCES = (_SRC_SCAN_ENGINES,)
    DEFAULT_SEVERITY = "warn"

    def run(self, engines: list[dict]) -> RuleResult:
        findings: list[Finding] = []
        for engine in engines:
            status = engine.get("status", "unknown")
            if status in _BAD_STATUS:
                continue
            sites = engine.get("sites") or []
            if sites:
                continue
            name = _engine_name(engine)
            address = engine.get("address")
            port = engine.get("port")
            host = f"{address}:{port}" if address and port else address
            findings.append(Finding(
                severity="warn",
                message=f"Engine '{name}' is not paired with any sites",
                details={
                    "id": engine.get("id"),
                    "name": name,
                    "address": address,
                    "port": port,
                    "host": host,
                    "status": status,
                    "product_version": engine.get("productVersion"),
                    "content_version": engine.get("contentVersion"),
                    "serial_number": engine.get("serialNumber"),
                    "last_refreshed": engine.get("lastRefreshedDate"),
                },
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            default_severity=self.DEFAULT_SEVERITY,
        )


def _compute_engine_count_summary(engines: list[dict], rule_results: list[RuleResult]) -> dict:
    """Derive per-engine worst-severity counts from rule-emitted findings.

    Walks every rule's findings, extracts the engine_id from finding.details
    (via the "id" key — all four engine rule classes write engine_id under
    "id"), and tracks the worst severity seen per engine. Engines that
    appear in no finding are healthy.
    """
    SEV_RANK = {"info": 0, "warn": 1, "fail": 2}
    worst_per_engine: dict[object, str] = {}
    for r in rule_results:
        for f in r.findings:
            details = f.details or {}
            engine_id = details.get("id")
            if engine_id is None:
                continue
            current = worst_per_engine.get(engine_id)
            if current is None or SEV_RANK[f.severity] > SEV_RANK[current]:
                worst_per_engine[engine_id] = f.severity
    total = len(engines)
    fail_count = sum(1 for s in worst_per_engine.values() if s == "fail")
    warn_count = sum(1 for s in worst_per_engine.values() if s == "warn")
    healthy = total - fail_count - warn_count
    return {
        "engines_total": total,
        "engines_healthy": healthy,
        "engines_warn": warn_count,
        "engines_fail": fail_count,
    }


class ScanEnginesCheck:
    name = "Scan Engines"
    description = "Health and pairing status of all configured scan engines."

    def run(self, client: Any, config: AppConfig, **_kwargs: object) -> CheckResult:
        start = time.monotonic()
        thresholds = config.thresholds.scan_engines
        body = client.get("/api/3/scan_engines")
        engines = body.get("resources", [])

        bad_status = EngineBadStatusRule()
        last_contact = EngineLastContactRule()
        missing_refresh = EngineMissingLastRefreshRule()
        unpaired = EngineUnpairedRule()
        rule_results: list[RuleResult] = [
            safe_run_rule(bad_status, lambda: bad_status.run(engines)),
            safe_run_rule(last_contact, lambda: last_contact.run(engines, thresholds)),
            safe_run_rule(missing_refresh, lambda: missing_refresh.run(engines)),
            safe_run_rule(unpaired, lambda: unpaired.run(engines)),
        ]

        summary = rule_summary(rule_results)
        summary.update(_compute_engine_count_summary(engines, rule_results))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=summary,
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )
