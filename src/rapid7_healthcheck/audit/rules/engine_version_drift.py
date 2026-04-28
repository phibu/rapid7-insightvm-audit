from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_REFRESH_STALE_DAYS = 7

# Likely keys for console version inside /api/3/administration/properties.
# The schema is documented as the loose `EnvironmentProperties` object, so we
# probe several candidates. Console operators on different builds have seen
# any of these keys populated.
_CONSOLE_PRODUCT_VERSION_KEYS = (
    "productVersion", "product_version", "consoleVersion", "version",
)
_CONSOLE_CONTENT_VERSION_KEYS = (
    "contentVersion", "content_version", "vulnDefVersion",
)


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _first_present(d: dict, keys) -> str | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


@register
class EngineVersionDriftRule:
    rule_id = "engine_version_drift"
    rule_name = "Scan Engine Version Drift or Stale Content Refresh"
    description = (
        "Scan engines whose productVersion or contentVersion differs from "
        "the console, OR whose lastRefreshedDate is older than the freshness "
        "threshold. Engine drift silently degrades scan quality because newer "
        "vulnerability checks may be missing from older content."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        stale_days = int(
            rule_config.get("refresh_stale_days", _DEFAULT_REFRESH_STALE_DAYS)
        )
        check_product_version = bool(rule_config.get("check_product_version", True))
        check_content_version = bool(rule_config.get("check_content_version", True))

        props = snapshot.administration_properties()
        console_product = _first_present(props, _CONSOLE_PRODUCT_VERSION_KEYS)
        console_content = _first_present(props, _CONSOLE_CONTENT_VERSION_KEYS)

        engines = snapshot.scan_engines()
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=stale_days)

        findings: list[Finding] = []
        engines_flagged = 0
        for engine in engines:
            engine_id = engine.get("id")
            engine_name = engine.get("name") or f"id={engine_id}"
            issues: list[str] = []
            engine_details: dict = {
                "engine_id": engine_id,
                "engine_name": engine.get("name"),
                "engine_address": engine.get("address"),
            }

            if check_product_version and console_product:
                e_product = engine.get("productVersion") or ""
                if e_product and e_product != console_product:
                    issues.append(
                        f"productVersion {e_product!r} != console {console_product!r}"
                    )
                    engine_details["engine_product_version"] = e_product
                    engine_details["console_product_version"] = console_product

            if check_content_version and console_content:
                e_content = engine.get("contentVersion") or ""
                if e_content and e_content != console_content:
                    issues.append(
                        f"contentVersion {e_content!r} != console {console_content!r}"
                    )
                    engine_details["engine_content_version"] = e_content
                    engine_details["console_content_version"] = console_content

            refreshed_at = _parse_iso(engine.get("lastRefreshedDate"))
            if refreshed_at is not None and refreshed_at < stale_cutoff:
                age_days = (now - refreshed_at).days
                issues.append(
                    f"lastRefreshedDate is {age_days} day(s) old "
                    f"(threshold {stale_days})"
                )
                engine_details["last_refreshed_date"] = engine.get("lastRefreshedDate")
                engine_details["age_days"] = age_days

            if not issues:
                continue
            engines_flagged += 1
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Scan engine '{engine_name}': " + "; ".join(issues)
                ),
                details=engine_details,
            ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "engines_examined": len(engines),
                "engines_flagged": engines_flagged,
                "console_product_version": console_product,
                "console_content_version": console_content,
                "refresh_stale_days": stale_days,
            },
            sources=list(self.sources),
        )
