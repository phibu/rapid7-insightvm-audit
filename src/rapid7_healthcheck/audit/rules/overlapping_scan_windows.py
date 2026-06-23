from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from itertools import combinations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding

# ISO 8601 duration parser, minimal: PT[nH][nM][nS]
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")

_DEFAULT_ASSUMED_SCAN_DURATION_MINUTES = 60


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


def _parse_scope(targets: list) -> tuple[list, set[str]]:
    """Split a site's included targets into IP networks and hostnames.

    InsightVM accepts both IP/CIDR and DNS-name scan targets. IP-typed
    targets are parsed into ``ip_network`` objects for subnet-overlap
    comparison; anything that is not a valid IP/CIDR is kept as a
    case-folded hostname string for exact-match comparison. Hostnames are
    not resolved (DNS lookup is out of scope and non-deterministic), so
    only identical names count as overlapping scope — but they are no
    longer silently dropped.
    """
    networks: list = []
    hostnames: set[str] = set()
    for t in targets:
        addr = t.get("address") if isinstance(t, dict) else t
        if not isinstance(addr, str) or not addr.strip():
            continue
        addr = addr.strip()
        try:
            networks.append(ipaddress.ip_network(addr, strict=False))
        except ValueError:
            hostnames.add(addr.casefold())
    return networks, hostnames


def _scopes_intersect(a: tuple[list, set[str]], b: tuple[list, set[str]]) -> bool:
    networks_a, hostnames_a = a
    networks_b, hostnames_b = b
    for na in networks_a:
        for nb in networks_b:
            if na.overlaps(nb):
                return True
    return bool(hostnames_a & hostnames_b)


@register
class OverlappingScanWindowsRule(AuditRule):
    rule_id = "overlapping_scan_windows"
    rule_name = "Overlapping Scan Windows"
    description = (
        "Scheduled scans whose time windows overlap and target the same IP scope."
    )
    default_severity = "warn"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        sites = snapshot.sites()
        # Floor at 1 minute: a zero would collapse the assumed window to
        # a point in time (silently suppressing findings for schedules
        # missing a `duration`); a negative would produce a negative
        # timedelta. Non-numeric strings still raise ValueError, which
        # safe_run surfaces as a status="error" rule card.
        assumed_minutes = max(
            1,
            int(
                rule_config.get(
                    "assumed_scan_duration_minutes",
                    _DEFAULT_ASSUMED_SCAN_DURATION_MINUTES,
                )
            ),
        )
        assumed_duration = timedelta(minutes=assumed_minutes)
        sampled = False
        sample_info = None
        if not full_scan and len(sites) > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {len(snapshot.sites())} sites"

        # The per-site schedule + included-targets fetches are an N+1: two
        # GETs per site with no batch endpoint. Run them concurrently up
        # front so the loop below reads warm caches instead of blocking on
        # ~2N sequential round-trips (the cause of the ~10 min runtime on
        # large consoles). Both calls are read-only GETs.
        site_ids = [s["id"] for s in sites]
        snapshot.prefetch_site_schedules(site_ids)
        snapshot.prefetch_site_included_targets(site_ids)

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
                end = start + duration if duration > timedelta(0) else start + assumed_duration
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

        return self.result(
            findings,
            severity=severity,
            summary={
                "windows_examined": len(windows),
                "findings_count": len(findings),
            },
            # card_summary intentionally None: findings count pairwise overlaps,
            # not windows. On a dense overlap graph (N windows mutually
            # overlapping) the rule emits C(N,2) findings which exceeds N
            # windows. "4 examined, 0 passed, 6 failed" would be visibly
            # nonsensical. Card falls back to per-summary-key rendering.
            sampled=sampled,
            sample_info=sample_info,
        )
