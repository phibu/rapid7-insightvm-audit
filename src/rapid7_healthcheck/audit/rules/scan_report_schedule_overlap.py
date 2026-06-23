from __future__ import annotations

import re
from datetime import datetime, timedelta
from itertools import combinations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding


# Mirror the existing overlap rule's parsers so behaviour stays consistent.
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")

_DEFAULT_REPORT_DURATION_MINUTES = 30
_DEFAULT_SCAN_DURATION_MINUTES = 60


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


def _coerce_id_set(values) -> set[int]:
    out: set[int] = set()
    for v in values or []:
        try:
            out.add(int(v))
        except (TypeError, ValueError):
            continue
    return out


def _report_windows(report: dict, duration: timedelta) -> list[tuple[datetime, datetime]]:
    """Materialize concrete (start, end) windows from a Report's frequency.

    Prefers `frequency.nextRuntimes` when populated (already-resolved firings).
    Falls back to a single window built from `frequency.start`. Reports do not
    declare a duration in the API schema, so we apply a configurable default.
    """
    freq = report.get("frequency") if isinstance(report, dict) else None
    if not isinstance(freq, dict):
        return []

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


def _resolve_report_scope(report: dict, snapshot) -> tuple[set[int], bool]:
    """Best-effort site IDs in a report's scope.

    Returns (site_ids, fully_resolved). `site_ids` is the union of explicit
    site IDs plus site IDs derivable from referenced asset groups. When a
    report's scope references tags or individual assets (which we can't cheaply
    map to sites), `fully_resolved` is False so the caller can count it.
    """
    scope = report.get("scope") if isinstance(report, dict) else None
    if not isinstance(scope, dict):
        return set(), True

    sites = _coerce_id_set(scope.get("sites"))
    fully_resolved = True

    for gid in _coerce_id_set(scope.get("assetGroups")):
        derived = snapshot.asset_group_sites(gid)
        if derived:
            sites |= derived
        else:
            fully_resolved = False

    if scope.get("tags") or scope.get("assets"):
        fully_resolved = False

    return sites, fully_resolved


@register
class ScanReportScheduleOverlapRule(AuditRule):
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
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/insightvm/working-with-reports/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Floor each knob at 1 minute: a zero would collapse the assumed
        # window to a point in time (silently suppressing overlap findings);
        # a negative would produce a negative timedelta. Non-numeric strings
        # still raise ValueError, which safe_run surfaces as a status="error"
        # rule card.
        report_duration = timedelta(
            minutes=max(1, int(rule_config.get(
                "assumed_report_duration_minutes", _DEFAULT_REPORT_DURATION_MINUTES
            )))
        )
        scan_duration_default = timedelta(
            minutes=max(1, int(rule_config.get(
                "assumed_scan_duration_minutes", _DEFAULT_SCAN_DURATION_MINUTES
            )))
        )

        all_sites = snapshot.sites()
        all_reports = snapshot.reports()

        sites = all_sites
        reports = all_reports
        sampled = False
        sample_info_parts: list[str] = []
        if not full_scan:
            if len(all_sites) > sample_size:
                sites = all_sites[:sample_size]
                sampled = True
                sample_info_parts.append(
                    f"checked {len(sites)} of {len(all_sites)} sites"
                )
            if len(all_reports) > sample_size:
                reports = all_reports[:sample_size]
                sampled = True
                sample_info_parts.append(
                    f"checked {len(reports)} of {len(all_reports)} reports"
                )
        sample_info = "; ".join(sample_info_parts) if sample_info_parts else None

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
                end = start + duration if duration > timedelta(0) else start + scan_duration_default
                scan_windows.append((sid, name, sch, start, end))

        # Build report windows (one report can contribute many windows via nextRuntimes).
        report_windows: list[tuple[int, str, set[int], datetime, datetime]] = []
        reports_unresolvable = 0
        for report in reports:
            r_id = report.get("id")
            r_name = report.get("name", f"id={r_id}")
            scope, fully_resolved = _resolve_report_scope(report, snapshot)
            if not fully_resolved:
                reports_unresolvable += 1
            for s, e in _report_windows(report, report_duration):
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

        return self.result(
            findings,
            severity=severity,
            summary={
                "scan_windows_examined": len(scan_windows),
                "report_windows_examined": len(report_windows),
                "reports_with_unresolvable_scope": reports_unresolvable,
                "findings_count": len(findings),
            },
            sampled=sampled,
            sample_info=sample_info,
        )
