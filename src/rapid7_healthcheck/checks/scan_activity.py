from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
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

_FAILED_STATUSES = {"failed", "aborted", "stopped", "error"}
_MAX_FAILED_FINDINGS = 20

_SRC_SITES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Site"
_SRC_SCANS = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Scan"


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class ScanActivityCheck:
    name = "Scan Activity"
    description = "Recent scan success/failure, sites with no recent scans, and stuck scans."

    def run(self, client: Any, config: AppConfig, **_kwargs: object) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.scan_activity
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(days=t.recent_window_days)
        fail_cutoff = now - timedelta(days=t.site_no_scan_days)
        stuck_cutoff = now - timedelta(hours=t.stuck_scan_hours)

        # Per-concept finding buckets.
        never_scanned_findings: list[Finding] = []
        no_success_findings: list[Finding] = []
        stuck_findings: list[Finding] = []
        failed_recent_findings: list[Finding] = []
        late_site_findings: list[Finding] = []

        sites_total = 0
        sites_with_recent = 0
        failed_count = 0
        stuck_count = 0
        failed_findings_emitted = 0

        for site in client.paginate("/api/3/sites"):
            sites_total += 1
            site_id = site.get("id")
            site_name = site.get("name", f"id={site_id}")
            body = client.get(
                f"/api/3/sites/{site_id}/scans",
                params={"sort": "startTime,DESC", "size": 20},
            )
            scans = body.get("resources", [])

            if not scans:
                never_scanned_findings.append(Finding(
                    severity="fail",
                    message=f"Site '{site_name}' has never been scanned",
                    details={"site_id": site_id},
                ))
                continue

            most_recent_finished = None
            for s in scans:
                start_time = _parse_iso(s.get("startTime"))
                status = (s.get("status") or "").lower()
                if start_time is None:
                    continue
                if status == "running" and start_time < stuck_cutoff:
                    age_h = (now - start_time).total_seconds() / 3600.0
                    stuck_findings.append(Finding(
                        severity="fail",
                        message=(
                            f"Site '{site_name}' has a scan running for {age_h:.1f}h "
                            f"(threshold {t.stuck_scan_hours}h)"
                        ),
                        details={"site_id": site_id, "scan_id": s.get("id"), "age_hours": round(age_h, 1)},
                    ))
                    stuck_count += 1
                if status in _FAILED_STATUSES and start_time >= recent_cutoff:
                    failed_count += 1
                    if failed_findings_emitted < _MAX_FAILED_FINDINGS:
                        failed_recent_findings.append(Finding(
                            severity="warn",
                            message=f"Site '{site_name}' had a {status} scan {start_time.isoformat()}",
                            details={"site_id": site_id, "scan_id": s.get("id"), "status": status},
                        ))
                        failed_findings_emitted += 1
                if status == "finished":
                    if most_recent_finished is None or start_time > most_recent_finished:
                        most_recent_finished = start_time

            if most_recent_finished is None:
                no_success_findings.append(Finding(
                    severity="fail",
                    message=f"Site '{site_name}' has no successful scans on record",
                    details={"site_id": site_id},
                ))
                continue

            if most_recent_finished < fail_cutoff:
                age_d = (now - most_recent_finished).days
                late_site_findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Site '{site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.site_no_scan_days}d)"
                    ),
                    details={"site_id": site_id, "age_days": age_d},
                ))
            elif most_recent_finished < recent_cutoff:
                age_d = (now - most_recent_finished).days
                late_site_findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Site '{site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.recent_window_days}d)"
                    ),
                    details={"site_id": site_id, "age_days": age_d},
                ))
            else:
                sites_with_recent += 1

        if failed_count > failed_findings_emitted:
            failed_recent_findings.append(Finding(
                severity="warn",
                message=(
                    f"{failed_count - failed_findings_emitted} additional failed scans "
                    f"omitted from findings (capped at {_MAX_FAILED_FINDINGS})"
                ),
            ))

        rule_results: list[RuleResult] = [
            make_rule_result(
                rule_id="op.scan_activity.sites_never_scanned",
                rule_name="Sites never scanned",
                description="Sites that have no scans on record at all.",
                findings=never_scanned_findings,
                sources=[_SRC_SITES, _SRC_SCANS],
                summary={"count": len(never_scanned_findings)},
                default_severity="fail",
            ),
            make_rule_result(
                rule_id="op.scan_activity.sites_no_successful_scan",
                rule_name="Sites with no successful scans",
                description=(
                    "Sites that have scan history but none of the recent scans "
                    "finished successfully."
                ),
                findings=no_success_findings,
                sources=[_SRC_SCANS],
                summary={"count": len(no_success_findings)},
                default_severity="fail",
            ),
            make_rule_result(
                rule_id="op.scan_activity.stuck_scans",
                rule_name="Stuck scans",
                description=(
                    "Scans in 'running' state past the stuck-scan threshold — "
                    "likely hung or orphaned."
                ),
                findings=stuck_findings,
                sources=[_SRC_SCANS],
                summary={"stuck_count": stuck_count},
                default_severity="fail",
            ),
            make_rule_result(
                rule_id="op.scan_activity.recent_failed_scans",
                rule_name="Recent failed scans",
                description=(
                    "Scans within the recent window that finished in a non-success state "
                    "(failed / aborted / stopped / error)."
                ),
                findings=failed_recent_findings,
                sources=[_SRC_SCANS],
                summary={"failed_count": failed_count},
                default_severity="warn",
            ),
            make_rule_result(
                rule_id="op.scan_activity.sites_overdue_scans",
                rule_name="Sites with overdue scans",
                description=(
                    "Sites whose last successful scan is past the recent-window threshold. "
                    "Crosses into fail when past the site-no-scan threshold."
                ),
                findings=late_site_findings,
                sources=[_SRC_SCANS],
                summary={
                    "count": len(late_site_findings),
                    "sites_with_recent_scans": sites_with_recent,
                    "sites_total": sites_total,
                },
                default_severity="warn",
            ),
        ]

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=rule_summary(rule_results),
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )
