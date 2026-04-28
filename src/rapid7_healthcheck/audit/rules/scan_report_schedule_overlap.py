from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from itertools import combinations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


# Mirror the existing overlap rule's parsers so behaviour stays consistent.
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")

_DEFAULT_REPORT_DURATION = timedelta(minutes=30)
_DEFAULT_SCAN_DURATION = timedelta(hours=1)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_duration(value: str | None) -> timedelta:
    if not value:
        return timedelta(0)
    m = _DURATION_RE.match(value)
    if not m:
        return timedelta(0)
    h, mn, s = (int(x) if x else 0 for x in m.groups())
    return timedelta(hours=h, minutes=mn, seconds=s)


def _windows_intersect(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end


def _report_windows(report: dict) -> list[tuple[datetime, datetime]]:
    """Materialize concrete (start, end) windows from a Report's frequency.

    Prefers `frequency.nextRuntimes` when populated (already-resolved firings).
    Falls back to a single window built from `frequency.start`. Reports do not
    declare a duration in the API schema, so we apply a configurable default.
    """
    freq = report.get("frequency") if isinstance(report, dict) else None
    if not isinstance(freq, dict):
        return []

    duration = _DEFAULT_REPORT_DURATION
    next_runtimes = freq.get("nextRuntimes") or []
    starts: list[datetime] = []
    if isinstance(next_runtimes, list) and next_runtimes:
        for nr in next_runtimes:
            t = _parse_iso(nr if isinstance(nr, str) else None)
            if t is not None:
                starts.append(t)
    else:
        t = _parse_iso(freq.get("start"))
        if t is not None:
            starts.append(t)
    return [(s, s + duration) for s in starts]


def _report_site_scope(report: dict) -> set[int]:
    scope = report.get("scope") if isinstance(report, dict) else None
    if not isinstance(scope, dict):
        return set()
    sites = scope.get("sites") or []
    return {int(s) for s in sites if isinstance(s, int)}


@register
class ScanReportScheduleOverlapRule:
    rule_id = "scan_report_schedule_overlap"
    rule_name = "Scan and Report Schedules Overlap on Shared Scope"
    description = (
        "Scheduled reports whose run window overlaps a scheduled scan on the "
        "same site (or another scheduled report on the same site). Concurrent "
        "scans and reports compete for console + PostgreSQL resources; Rapid7 "
        "recommends staggering them."
    )
    default_severity = "warn"
    expensive = True
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Build scan windows keyed by site (reuses the same parsing as the
        # existing overlapping_scan_windows rule, but only carries site-id
        # scope — report scope is also expressed in site IDs in /api/3).
        sites = snapshot.sites()
        sampled = False
        sample_info = None
        if not full_scan and len(sites) > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {len(snapshot.sites())} sites"

        scan_windows: list[tuple[int, str, dict, datetime, datetime]] = []
        for site in sites:
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            for sch in snapshot.site_schedules(sid):
                if not sch.get("enabled", False):
                    continue
                start = _parse_iso(sch.get("start"))
                if start is None:
                    continue
                duration = _parse_duration(sch.get("duration"))
                end = start + duration if duration > timedelta(0) else start + _DEFAULT_SCAN_DURATION
                scan_windows.append((sid, name, sch, start, end))

        # Build report windows (one report can contribute many windows via nextRuntimes).
        report_windows: list[tuple[int, str, set[int], datetime, datetime]] = []
        for report in snapshot.reports():
            r_id = report.get("id")
            r_name = report.get("name", f"id={r_id}")
            scope = _report_site_scope(report)
            for s, e in _report_windows(report):
                report_windows.append((r_id, r_name, scope, s, e))

        findings: list[Finding] = []

        # report-vs-scan: same site in scope, time windows overlap.
        for r_id, r_name, r_scope, r_s, r_e in report_windows:
            if not r_scope:
                continue
            for sid, s_name, sch, s_s, s_e in scan_windows:
                if sid not in r_scope:
                    continue
                if not _windows_intersect(r_s, r_e, s_s, s_e):
                    continue
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Report '{r_name}' overlaps scan on site '{s_name}' at "
                        f"{max(r_s, s_s).isoformat()}. Stagger the schedules."
                    ),
                    details={
                        "report_id": r_id,
                        "site_id": sid,
                        "schedule_id": sch.get("id"),
                        "overlap_start": max(r_s, s_s).isoformat(),
                        "overlap_end": min(r_e, s_e).isoformat(),
                    },
                ))

        # report-vs-report: same site in both scopes, windows overlap.
        for (a_id, a_name, a_scope, a_s, a_e), (b_id, b_name, b_scope, b_s, b_e) in combinations(report_windows, 2):
            shared = a_scope & b_scope
            if not shared:
                continue
            if not _windows_intersect(a_s, a_e, b_s, b_e):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Reports '{a_name}' and '{b_name}' overlap on shared sites "
                    f"{sorted(shared)} at {max(a_s, b_s).isoformat()}."
                ),
                details={
                    "report_a": a_id,
                    "report_b": b_id,
                    "shared_sites": sorted(shared),
                    "overlap_start": max(a_s, b_s).isoformat(),
                    "overlap_end": min(a_e, b_e).isoformat(),
                },
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
                "scan_windows_examined": len(scan_windows),
                "report_windows_examined": len(report_windows),
                "findings_count": len(findings),
            },
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
