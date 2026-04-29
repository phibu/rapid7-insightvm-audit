from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from itertools import combinations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding

# ISO 8601 duration parser, minimal: PT[nH][nM][nS]
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


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


def _parse_scope(targets: list) -> list:
    out = []
    for t in targets:
        addr = t.get("address") if isinstance(t, dict) else t
        if not addr:
            continue
        try:
            out.append(ipaddress.ip_network(addr, strict=False))
        except ValueError:
            continue
    return out


def _scopes_intersect(a, b) -> bool:
    for na in a:
        for nb in b:
            if na.overlaps(nb):
                return True
    return False


@register
class OverlappingScanWindowsRule:
    rule_id = "overlapping_scan_windows"
    rule_name = "Overlapping Scan Windows or Blackout Conflicts"
    description = (
        "Scheduled scans whose time windows overlap and target the same IP scope, "
        "or scans scheduled inside an enabled blackout."
    )
    default_severity = "warn"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/scan-blackouts",
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        sites = snapshot.sites()
        sampled = False
        sample_info = None
        if not full_scan and len(sites) > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {len(snapshot.sites())} sites"

        windows = []
        for site in sites:
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            scope = _parse_scope(snapshot.site_included_targets(sid))
            for sch in snapshot.site_schedules(sid):
                if not sch.get("enabled", False):
                    continue
                start = _parse_iso(sch.get("start"))
                if start is None:
                    continue
                duration = _parse_duration(sch.get("duration"))
                end = start + duration if duration > timedelta(0) else start + timedelta(hours=1)
                windows.append((sid, name, sch, start, end, scope))

        findings: list[Finding] = []

        for (sid_a, name_a, sch_a, s_a, e_a, scope_a), (sid_b, name_b, sch_b, s_b, e_b, scope_b) in combinations(windows, 2):
            if sid_a == sid_b:
                continue
            if not _windows_intersect(s_a, e_a, s_b, e_b):
                continue
            if not _scopes_intersect(scope_a, scope_b):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Sites '{name_a}' and '{name_b}' have schedules that overlap "
                    f"on {s_a.date().isoformat()} {s_a.strftime('%H:%M')} and target overlapping IP scope"
                ),
                details={
                    "site_a": sid_a, "site_b": sid_b,
                    "schedule_a": sch_a.get("id"), "schedule_b": sch_b.get("id"),
                    "overlap_start": max(s_a, s_b).isoformat(),
                    "overlap_end": min(e_a, e_b).isoformat(),
                },
            ))

        blackouts_unavailable = getattr(snapshot, "blackouts_unavailable", False)
        if not blackouts_unavailable:
            for blackout in snapshot.blackouts():
                if not blackout.get("enabled", False):
                    continue
                b_start = _parse_iso(blackout.get("start"))
                if b_start is None:
                    continue
                b_end = b_start + _parse_duration(blackout.get("duration"))
                for sid, name, sch, s, e, _scope in windows:
                    if _windows_intersect(s, e, b_start, b_end):
                        bo_name = blackout.get("name", f"id={blackout.get('id')}")
                        findings.append(Finding(
                            severity=severity,
                            message=(
                                f"Site '{name}' schedule overlaps blackout "
                                f"'{bo_name}' on {s.date().isoformat()}"
                            ),
                            details={
                                "site_id": sid, "schedule_id": sch.get("id"),
                                "blackout_id": blackout.get("id"),
                            },
                        ))
        else:
            findings.append(Finding(
                severity="info",
                message=(
                    "Blackout-conflict checks skipped: /api/3/blackouts is not "
                    "available on this console. Scan-vs-scan overlaps are still "
                    "checked normally."
                ),
                details={"reason": "blackouts endpoint returned 404"},
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
                "windows_examined": len(windows),
                "findings_count": len(findings),
                "blackouts_unavailable": blackouts_unavailable,
            },
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
