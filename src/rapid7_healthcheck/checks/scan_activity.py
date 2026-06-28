from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, NamedTuple

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.timewindow import parse_iso
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    make_rule_result,
    safe_run_rule,
)
from rapid7_healthcheck.checks._op_runner import OpCheckDescriptor, OpCheckRunner
from rapid7_healthcheck.config import AppConfig

_FAILED_STATUSES = {"aborted", "stopped", "error"}
_MAX_FAILED_FINDINGS = 20

_SRC_SITES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Site"
_SRC_SCANS = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Scan"


class _RecentStatusRule(NamedTuple):
    """One row per recent-status concept tracked inside the scan loop."""
    predicate: Callable[[str], bool]
    message_phrase: str   # e.g. "a {status} scan" / "an unknown-status scan"
    overflow_label: str   # e.g. "failed scans" / "unknown-status scans"


_RECENT_STATUS_RULES: tuple[_RecentStatusRule, ...] = (
    _RecentStatusRule(
        predicate=lambda s: s in _FAILED_STATUSES,
        message_phrase="a {status} scan",
        overflow_label="failed scans",
    ),
    _RecentStatusRule(
        predicate=lambda s: s == "unknown",
        message_phrase="an unknown-status scan",
        overflow_label="unknown-status scans",
    ),
)


def _emit_overflow_rollup(
    findings: list[Finding],
    *,
    total_count: int,
    emitted_count: int,
    overflow_label: str,
    cap: int,
) -> None:
    """Append the 'N additional ... omitted (capped at K)' rollup finding when warranted."""
    if total_count > emitted_count:
        findings.append(Finding(
            severity="warn",
            message=(
                f"{total_count - emitted_count} additional {overflow_label} "
                f"omitted from findings (capped at {cap})"
            ),
        ))


@dataclass(frozen=True)
class _ParsedScan:
    scan_id: int | None
    status: str
    start_time: datetime | None


@dataclass(frozen=True)
class _ParsedSiteScans:
    site_id: int | None
    site_name: str
    scans: tuple[_ParsedScan, ...]
    most_recent_finished: datetime | None
    has_any_scans: bool


def _fetch_parsed_sites(client, snapshot: "EnvSnapshot") -> list[_ParsedSiteScans]:
    """Single I/O pass: fetch each site's recent scans, parse once.

    The result is consumed by every rule class in this module -- each rule
    iterates the list and applies its own concept-specific predicate.
    Site list comes from the shared snapshot (potentially pre-cached by
    the audit); per-site scans are fetched directly here because no
    second consumer exists today.
    API call cost from this function: one GET per site for
    /api/3/sites/{id}/scans?sort=startTime,DESC&size=20. The /api/3/sites
    pagination is owned by the snapshot -- issued at most once across the
    whole run, regardless of how many checks consume it.
    """
    parsed: list[_ParsedSiteScans] = []
    for site in snapshot.sites():
        site_id = site.get("id")
        site_name = site.get("name", f"id={site_id}")
        body = client.get(
            f"/api/3/sites/{site_id}/scans",
            params={"sort": "startTime,DESC", "size": 20},
        )
        raw = body.get("resources", [])
        parsed_scans: list[_ParsedScan] = []
        most_recent_finished: datetime | None = None
        for s in raw:
            start_time = parse_iso(s.get("startTime"))
            status = (s.get("status") or "").lower()
            parsed_scans.append(_ParsedScan(
                scan_id=s.get("id"),
                status=status,
                start_time=start_time,
            ))
            if status == "finished" and start_time is not None:
                if most_recent_finished is None or start_time > most_recent_finished:
                    most_recent_finished = start_time
        parsed.append(_ParsedSiteScans(
            site_id=site_id,
            site_name=site_name,
            scans=tuple(parsed_scans),
            most_recent_finished=most_recent_finished,
            has_any_scans=bool(parsed_scans),
        ))
    return parsed


class SitesNeverScannedRule:
    RULE_ID = "op.scan_activity.sites_never_scanned"
    RULE_NAME = "Sites never scanned"
    DESCRIPTION = "Sites that have no scans on record at all."
    SOURCES = (_SRC_SITES, _SRC_SCANS)
    DEFAULT_SEVERITY = "fail"

    def run(self, parsed_sites: list[_ParsedSiteScans]) -> RuleResult:
        findings: list[Finding] = []
        for ps in parsed_sites:
            if not ps.has_any_scans:
                findings.append(Finding(
                    severity="fail",
                    message=f"Site '{ps.site_name}' has never been scanned",
                    details={"site_id": ps.site_id},
                ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            examined=len(parsed_sites),
            failed=len(findings),
            default_severity=self.DEFAULT_SEVERITY,
        )


class SitesNoSuccessfulScanRule:
    RULE_ID = "op.scan_activity.sites_no_successful_scan"
    RULE_NAME = "Sites with no successful scans"
    DESCRIPTION = (
        "Sites that have scan history but none of the recent scans "
        "finished successfully."
    )
    SOURCES = (_SRC_SCANS,)
    DEFAULT_SEVERITY = "fail"

    def run(self, parsed_sites: list[_ParsedSiteScans]) -> RuleResult:
        findings: list[Finding] = []
        for ps in parsed_sites:
            if ps.has_any_scans and ps.most_recent_finished is None:
                findings.append(Finding(
                    severity="fail",
                    message=f"Site '{ps.site_name}' has no successful scans on record",
                    details={"site_id": ps.site_id},
                ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"count": len(findings)},
            examined=len(parsed_sites),
            failed=len(findings),
            default_severity=self.DEFAULT_SEVERITY,
        )


class StuckScansRule:
    RULE_ID = "op.scan_activity.stuck_scans"
    RULE_NAME = "Stuck scans"
    DESCRIPTION = (
        "Scans in 'running' state past the stuck-scan threshold -- "
        "likely hung or orphaned."
    )
    SOURCES = (_SRC_SCANS,)
    DEFAULT_SEVERITY = "fail"

    def run(self, parsed_sites: list[_ParsedSiteScans], t, now: datetime) -> RuleResult:
        stuck_cutoff = now - timedelta(hours=t.stuck_scan_hours)
        findings: list[Finding] = []
        stuck_count = 0
        for ps in parsed_sites:
            for scan in ps.scans:
                if (
                    scan.status == "running"
                    and scan.start_time is not None
                    and scan.start_time < stuck_cutoff
                ):
                    age_h = (now - scan.start_time).total_seconds() / 3600.0
                    findings.append(Finding(
                        severity="fail",
                        message=(
                            f"Site '{ps.site_name}' has a scan running for {age_h:.1f}h "
                            f"(threshold {t.stuck_scan_hours}h)"
                        ),
                        details={
                            "site_id": ps.site_id,
                            "scan_id": scan.scan_id,
                            "age_hours": round(age_h, 1),
                        },
                    ))
                    stuck_count += 1
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"stuck_count": stuck_count},
            default_severity=self.DEFAULT_SEVERITY,
        )


class RecentFailedScansRule:
    RULE_ID = "op.scan_activity.recent_failed_scans"
    RULE_NAME = "Recent failed scans"
    DESCRIPTION = (
        "Scans within the recent window that finished in a non-success state "
        "(aborted / stopped / error)."
    )
    SOURCES = (_SRC_SCANS,)
    DEFAULT_SEVERITY = "warn"

    def run(self, parsed_sites: list[_ParsedSiteScans], t, now: datetime) -> RuleResult:
        recent_cutoff = now - timedelta(days=t.recent_window_days)
        rule = _RECENT_STATUS_RULES[0]
        findings: list[Finding] = []
        failed_count = 0
        failed_findings_emitted = 0
        for ps in parsed_sites:
            for scan in ps.scans:
                if scan.start_time is None or scan.start_time < recent_cutoff:
                    continue
                if rule.predicate(scan.status):
                    failed_count += 1
                    if failed_findings_emitted < _MAX_FAILED_FINDINGS:
                        findings.append(Finding(
                            severity="warn",
                            message=(
                                f"Site '{ps.site_name}' had "
                                f"{rule.message_phrase.format(status=scan.status)} "
                                f"{scan.start_time.isoformat()}"
                            ),
                            details={
                                "site_id": ps.site_id,
                                "scan_id": scan.scan_id,
                                "status": scan.status,
                            },
                        ))
                        failed_findings_emitted += 1
        _emit_overflow_rollup(
            findings,
            total_count=failed_count,
            emitted_count=failed_findings_emitted,
            overflow_label=rule.overflow_label,
            cap=_MAX_FAILED_FINDINGS,
        )
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"failed_count": failed_count},
            default_severity=self.DEFAULT_SEVERITY,
        )


class RecentUnknownScansRule:
    RULE_ID = "op.scan_activity.recent_unknown_scans"
    RULE_NAME = "Recent scans in unknown state"
    DESCRIPTION = (
        "Scans within the recent window whose status is reported as "
        "'unknown' -- indeterminate scan state, likely needs operator "
        "inspection."
    )
    SOURCES = (_SRC_SCANS,)
    DEFAULT_SEVERITY = "warn"

    def run(self, parsed_sites: list[_ParsedSiteScans], t, now: datetime) -> RuleResult:
        recent_cutoff = now - timedelta(days=t.recent_window_days)
        rule = _RECENT_STATUS_RULES[1]
        findings: list[Finding] = []
        unknown_count = 0
        unknown_findings_emitted = 0
        for ps in parsed_sites:
            for scan in ps.scans:
                if scan.start_time is None or scan.start_time < recent_cutoff:
                    continue
                if rule.predicate(scan.status):
                    unknown_count += 1
                    if unknown_findings_emitted < _MAX_FAILED_FINDINGS:
                        findings.append(Finding(
                            severity="warn",
                            message=(
                                f"Site '{ps.site_name}' had "
                                f"{rule.message_phrase.format(status=scan.status)} "
                                f"{scan.start_time.isoformat()}"
                            ),
                            details={
                                "site_id": ps.site_id,
                                "scan_id": scan.scan_id,
                                "status": scan.status,
                            },
                        ))
                        unknown_findings_emitted += 1
        _emit_overflow_rollup(
            findings,
            total_count=unknown_count,
            emitted_count=unknown_findings_emitted,
            overflow_label=rule.overflow_label,
            cap=_MAX_FAILED_FINDINGS,
        )
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={"unknown_count": unknown_count},
            default_severity=self.DEFAULT_SEVERITY,
        )


class SitesOverdueScansRule:
    RULE_ID = "op.scan_activity.sites_overdue_scans"
    RULE_NAME = "Sites with overdue scans"
    DESCRIPTION = (
        "Sites whose last successful scan is past the recent-window threshold. "
        "Crosses into fail when past the site-no-scan threshold."
    )
    SOURCES = (_SRC_SCANS,)
    DEFAULT_SEVERITY = "warn"

    def run(self, parsed_sites: list[_ParsedSiteScans], t, now: datetime) -> RuleResult:
        recent_cutoff = now - timedelta(days=t.recent_window_days)
        fail_cutoff = now - timedelta(days=t.site_no_scan_days)
        findings: list[Finding] = []
        sites_with_recent_scans = 0
        for ps in parsed_sites:
            if ps.most_recent_finished is None:
                continue
            age_d = (now - ps.most_recent_finished).days
            if ps.most_recent_finished < fail_cutoff:
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Site '{ps.site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.site_no_scan_days}d)"
                    ),
                    details={"site_id": ps.site_id, "age_days": age_d},
                ))
            elif ps.most_recent_finished < recent_cutoff:
                findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Site '{ps.site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.recent_window_days}d)"
                    ),
                    details={"site_id": ps.site_id, "age_days": age_d},
                ))
            else:
                sites_with_recent_scans += 1
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=list(self.SOURCES),
            summary={
                "count": len(findings),
                "sites_with_recent_scans": sites_with_recent_scans,
                "sites_total": len(parsed_sites),
            },
            # examined is sites this rule actually evaluated -- those with at
            # least one finished scan. Sites with no scan history are silently
            # skipped above (and flagged separately by sites_never_scanned /
            # sites_no_successful_scan), so counting them as "passed" here
            # would be misleading.
            examined=sites_with_recent_scans + len(findings),
            failed=len(findings),
            default_severity=self.DEFAULT_SEVERITY,
        )


class ScanActivityCheck:
    name = "Scan Activity"
    description = "Recent scan success/failure, sites with no recent scans, and stuck scans."

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: "EnvSnapshot | None" = None,
        **_kwargs: object,
    ) -> CheckResult:
        if snapshot is None:
            snapshot = EnvSnapshot(client, full_scan=False, sample_size=500)
        descriptor = OpCheckDescriptor(
            name=self.name,
            description=self.description,
            produce_rule_results=self._produce,
        )
        return OpCheckRunner().run(descriptor, client=client, config=config, snapshot=snapshot)

    def _produce(self, client: Any, config: AppConfig, snapshot: Any) -> list[RuleResult]:
        t = config.thresholds.scan_activity
        now = datetime.now(timezone.utc)

        # The per-site scan fetch is shared by all six rules. Memoize it
        # behind a closure so it is attempted exactly once but resolved
        # *inside* each rule's safe_run_rule wrapper. If the fetch raises,
        # the exception is cached and re-raised to every rule, so a single
        # transient API failure surfaces as six isolated error rule cards
        # rather than collapsing the entire check.
        _fetch_cache: dict[str, object] = {}

        def parsed_sites() -> list[_ParsedSiteScans]:
            if "exc" in _fetch_cache:
                raise _fetch_cache["exc"]  # type: ignore[misc]
            if "value" not in _fetch_cache:
                try:
                    _fetch_cache["value"] = _fetch_parsed_sites(client, snapshot)
                except Exception as e:
                    _fetch_cache["exc"] = e
                    raise
            return _fetch_cache["value"]  # type: ignore[return-value]

        never_scanned = SitesNeverScannedRule()
        no_success = SitesNoSuccessfulScanRule()
        stuck = StuckScansRule()
        recent_failed = RecentFailedScansRule()
        recent_unknown = RecentUnknownScansRule()
        overdue = SitesOverdueScansRule()
        rule_results: list[RuleResult] = [
            safe_run_rule(never_scanned, lambda: never_scanned.run(parsed_sites())),
            safe_run_rule(no_success, lambda: no_success.run(parsed_sites())),
            safe_run_rule(stuck, lambda: stuck.run(parsed_sites(), t, now)),
            safe_run_rule(recent_failed, lambda: recent_failed.run(parsed_sites(), t, now)),
            safe_run_rule(recent_unknown, lambda: recent_unknown.run(parsed_sites(), t, now)),
            safe_run_rule(overdue, lambda: overdue.run(parsed_sites(), t, now)),
        ]

        return rule_results
