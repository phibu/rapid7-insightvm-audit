from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    error_rule,
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    safe_run_rule,
    skipped_rule,
)
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)

_EXAMPLES_LIMIT = 10

_SRC_ASSET_SEARCH = "https://help.rapid7.com/insightvm/en-us/api/index.html#operation/findAssets"
_SRC_SITES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Site"
_SRC_FILTERED_SEARCH = "https://docs.rapid7.com/insightvm/filtered-asset-search"
_SRC_DUPLICATE_ASSETS = "https://docs.rapid7.com/insightvm/managing-assets#duplicate-assets"

_KIND_LABEL = {"hostname": "hostnames", "ip": "IP addresses"}


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]



def _oversize_skip_rule(rule, total_assets: int, threshold: int, *, kind: str) -> RuleResult:
    """Build a skipped RuleResult explaining why duplicate detection was bypassed
    at this inventory size. The skipped status is honest — at this scale we
    cannot detect duplicates at all via v3 (no group-by), so reporting "pass"
    would imply we checked and found nothing.

    `rule` is a DuplicateHostnamesRule or DuplicateIpsRule instance — used only
    to read RULE_ID / RULE_NAME / DESCRIPTION / SOURCES. `kind` is "hostname"
    or "ip" and is interpolated into the user-visible reason.
    """
    label = _KIND_LABEL[kind]
    if threshold == 0:
        reason = (
            f"Duplicate {kind} detection disabled "
            f"(duplicate_detection_max_assets=0). "
            f"Review duplicate {label} in the Security Console → Assets."
        )
    else:
        reason = (
            f"{total_assets:,} assets exceed detection ceiling "
            f"({threshold:,}). Walking the full inventory would take too long "
            f"on this console (v3 API has no group-by). Review duplicate "
            f"{label} in the Security Console → Assets, or raise "
            f"duplicate_detection_max_assets to override."
        )
    return RuleResult(
        rule_id=rule.RULE_ID,
        rule_name=rule.RULE_NAME,
        description=rule.DESCRIPTION,
        severity="info",
        status="skipped",
        findings=[],
        summary={
            f"duplicate_{kind}_detection_skipped": True,
            "total_assets": total_assets,
            "threshold": threshold,
            "reason": reason,
        },
        sources=list(rule.SOURCES),
    )


class MissingOsRule:
    RULE_ID = "op.data_quality.missing_os"
    RULE_NAME = "Assets without OS fingerprint"
    DESCRIPTION = "Assets where the operating-system field is empty (fingerprinting failed or never ran)."
    DEFAULT_SEVERITY = "warn"
    SOURCES = (_SRC_FILTERED_SEARCH, _SRC_ASSET_SEARCH)

    def run(self, client: Any, t) -> RuleResult:
        if not t.flag_missing_os:
            return skipped_rule(rule_id=self.RULE_ID, rule_name=self.RULE_NAME, description=self.DESCRIPTION, sources=self.SOURCES)

        rule_start = time.monotonic()
        body = client.post_one(
            "/api/3/assets/search",
            json_body={
                "filters": [{"field": "operating-system", "operator": "is-empty"}],
                "match": "all",
            },
            params={"size": _EXAMPLES_LIMIT},
        )
        total = int(body.get("page", {}).get("totalResources", 0))
        examples = body.get("resources", [])[:_EXAMPLES_LIMIT]
        findings: list[Finding] = []
        if total > 0:
            findings.append(Finding(
                severity="warn",
                message=f"{total} asset(s) have no OS fingerprint",
                details={"total": total, "examples": _example_hostnames(examples)},
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"missing_os_count": total},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class EmptySitesRule:
    RULE_ID = "op.data_quality.empty_sites"
    RULE_NAME = "Sites with zero assets"
    DESCRIPTION = "Sites whose include/exclude scope currently matches no assets."
    DEFAULT_SEVERITY = "warn"
    SOURCES = (_SRC_SITES,)

    def run(self, snapshot: "EnvSnapshot", t) -> RuleResult:
        if not t.flag_empty_sites:
            return skipped_rule(rule_id=self.RULE_ID, rule_name=self.RULE_NAME, description=self.DESCRIPTION, sources=self.SOURCES)

        rule_start = time.monotonic()
        empty_sites: list[dict] = []
        for site in snapshot.sites():
            site_id = site.get("id")
            count = snapshot.site_asset_count(site_id)
            if count == 0:
                empty_sites.append(site)
        findings: list[Finding] = []
        if empty_sites:
            findings.append(Finding(
                severity="warn",
                message=f"{len(empty_sites)} site(s) have zero assets",
                details={
                    "total": len(empty_sites),
                    "examples": [s.get("name", f"id={s.get('id')}") for s in empty_sites[:_EXAMPLES_LIMIT]],
                },
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"empty_sites_count": len(empty_sites)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class StaleAssetsRule:
    RULE_ID = "op.data_quality.stale_assets"
    RULE_NAME = "Long-stale assets"
    DESCRIPTION = (
        "Assets whose last scan is older than the data-quality threshold. "
        "Distinct from Asset Coverage's never-scanned signal — this flags "
        "asset records whose data is so old it's likely unreliable."
    )
    DEFAULT_SEVERITY = "warn"
    SOURCES = (_SRC_FILTERED_SEARCH,)

    def run(self, client: Any, t) -> RuleResult:
        if not t.flag_stale_assets:
            return skipped_rule(rule_id=self.RULE_ID, rule_name=self.RULE_NAME, description=self.DESCRIPTION, sources=self.SOURCES)

        rule_start = time.monotonic()
        body = client.post_one(
            "/api/3/assets/search",
            json_body={
                "filters": [
                    {
                        "field": "last-scan-date",
                        "operator": "is-earlier-than",
                        "value": t.stale_asset_days,
                    }
                ],
                "match": "all",
            },
            params={"size": _EXAMPLES_LIMIT},
        )
        total = int(body.get("page", {}).get("totalResources", 0))
        examples = body.get("resources", [])[:_EXAMPLES_LIMIT]
        findings: list[Finding] = []
        if total > 0:
            findings.append(Finding(
                severity="warn",
                message=(
                    f"{total} asset(s) have not been scanned in over "
                    f"{t.stale_asset_days} days (data is likely stale)"
                ),
                details={
                    "total": total,
                    "stale_asset_days": t.stale_asset_days,
                    "examples": _example_hostnames(examples),
                },
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"stale_assets_count": total},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


def _collect_duplicate_groups(client, t) -> tuple[list[dict], list[dict]]:
    """Single paginate over /api/3/assets, returning host- and IP-keyed duplicate groups.

    Returns ``(host_groups, ip_groups)`` where each list element is a dict with
    ``key``, ``ids``, ``count`` keys. Groups with count <= 1 are dropped.
    Either list may be empty if the corresponding flag (``flag_duplicate_hostnames``
    / ``flag_duplicate_ips``) is False — the caller still receives an empty list,
    not None.
    """
    by_host: dict[str, list[dict]] = defaultdict(list)
    by_ip: dict[str, list[dict]] = defaultdict(list)
    if not (t.flag_duplicate_hostnames or t.flag_duplicate_ips):
        return [], []
    for asset in client.paginate("/api/3/assets"):
        if t.flag_duplicate_hostnames:
            host = (asset.get("hostName") or "").strip().lower()
            if host:
                by_host[host].append(asset)
        if t.flag_duplicate_ips:
            ip = (asset.get("ip") or "").strip()
            if ip:
                by_ip[ip].append(asset)
    host_groups = [
        {"key": k, "ids": [a.get("id") for a in assets], "count": len(assets)}
        for k, assets in by_host.items()
        if len(assets) > 1
    ] if t.flag_duplicate_hostnames else []
    ip_groups = [
        {"key": k, "ids": [a.get("id") for a in assets], "count": len(assets)}
        for k, assets in by_ip.items()
        if len(assets) > 1
    ] if t.flag_duplicate_ips else []
    return host_groups, ip_groups


class DuplicateHostnamesRule:
    RULE_ID = "op.data_quality.duplicate_hostnames"
    RULE_NAME = "Duplicate hostnames"
    DESCRIPTION = (
        "Multiple asset records share the same hostname (case-insensitive). "
        "Classic agent + scan-engine collision; can also indicate stale records."
    )
    DEFAULT_SEVERITY = "warn"
    SOURCES = (_SRC_DUPLICATE_ASSETS,)

    def run(self, groups: list[dict], t) -> RuleResult:
        if not t.flag_duplicate_hostnames:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )
        rule_start = time.monotonic()
        findings: list[Finding] = []
        if groups:
            affected = sum(g["count"] for g in groups)
            findings.append(Finding(
                severity="warn",
                message=(
                    f"{len(groups)} hostname(s) shared by multiple assets "
                    f"({affected} asset records affected)"
                ),
                details={
                    "duplicate_groups": len(groups),
                    "affected_assets": affected,
                    "examples": [
                        {"hostName": g["key"], "ids": g["ids"][:_EXAMPLES_LIMIT]}
                        for g in groups[:_EXAMPLES_LIMIT]
                    ],
                },
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"duplicate_hostname_groups": len(groups)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class DuplicateIpsRule:
    RULE_ID = "op.data_quality.duplicate_ips"
    RULE_NAME = "Duplicate IP addresses"
    DESCRIPTION = (
        "Multiple asset records share the same IP. "
        "Often a DHCP-driven re-IPing where MAC tracking is incomplete."
    )
    DEFAULT_SEVERITY = "warn"
    SOURCES = (_SRC_DUPLICATE_ASSETS,)

    def run(self, groups: list[dict], t) -> RuleResult:
        if not t.flag_duplicate_ips:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )
        rule_start = time.monotonic()
        findings: list[Finding] = []
        if groups:
            affected = sum(g["count"] for g in groups)
            findings.append(Finding(
                severity="warn",
                message=(
                    f"{len(groups)} IP address(es) shared by multiple assets "
                    f"({affected} asset records affected)"
                ),
                details={
                    "duplicate_groups": len(groups),
                    "affected_assets": affected,
                    "examples": [
                        {"ip": g["key"], "ids": g["ids"][:_EXAMPLES_LIMIT]}
                        for g in groups[:_EXAMPLES_LIMIT]
                    ],
                },
            ))
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"duplicate_ip_groups": len(groups)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


def _run_duplicate_detection(
    client: Any,
    t,
    host_rule: "DuplicateHostnamesRule",
    ip_rule: "DuplicateIpsRule",
    snapshot: "EnvSnapshot",
) -> list[RuleResult]:
    """Run the host+ip duplicate-detection pair through peek -> oversize check
    -> full paginate. Returns the two RuleResults the orchestrator will
    append. Errors at peek or paginate are converted to per-rule error
    results so the rest of the check keeps running.

    Caller has already verified at least one of `flag_duplicate_hostnames`
    or `flag_duplicate_ips` is True; the both-off skip path stays inline in
    DataQualityCheck.run.
    """
    try:
        total_assets = snapshot.total_asset_count()
    except Exception as e:
        logger.exception("snapshot.total_asset_count raised")
        return [
            error_rule(
                rule_id=host_rule.RULE_ID,
                rule_name=host_rule.RULE_NAME,
                description=host_rule.DESCRIPTION,
                sources=host_rule.SOURCES,
                error=e,
            ),
            error_rule(
                rule_id=ip_rule.RULE_ID,
                rule_name=ip_rule.RULE_NAME,
                description=ip_rule.DESCRIPTION,
                sources=ip_rule.SOURCES,
                error=e,
            ),
        ]

    cap = t.duplicate_detection_max_assets
    if cap == 0 or total_assets > cap:
        return [
            _oversize_skip_rule(host_rule, total_assets, cap, kind="hostname"),
            _oversize_skip_rule(ip_rule, total_assets, cap, kind="ip"),
        ]

    try:
        host_groups, ip_groups = _collect_duplicate_groups(client, t)
    except Exception as e:
        logger.exception("data_quality._collect_duplicate_groups raised")
        return [
            error_rule(
                rule_id=host_rule.RULE_ID,
                rule_name=host_rule.RULE_NAME,
                description=host_rule.DESCRIPTION,
                sources=host_rule.SOURCES,
                error=e,
            ),
            error_rule(
                rule_id=ip_rule.RULE_ID,
                rule_name=ip_rule.RULE_NAME,
                description=ip_rule.DESCRIPTION,
                sources=ip_rule.SOURCES,
                error=e,
            ),
        ]

    return [
        safe_run_rule(host_rule, lambda: host_rule.run(host_groups, t)),
        safe_run_rule(ip_rule, lambda: ip_rule.run(ip_groups, t)),
    ]


class DataQualityCheck:
    name = "Data Quality"
    description = (
        "Assets without OS fingerprint, sites with zero assets, "
        "long-stale assets, and duplicate hostnames/IPs."
    )

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
        start = time.monotonic()
        t = config.thresholds.data_quality
        rule_results: list[RuleResult] = []

        # Per-rule isolation: a single rule's API call timing out or 400-ing
        # must not blackhole the rest of the check. Mirrors the audit
        # orchestrator's pattern.
        missing_os = MissingOsRule()
        empty_sites = EmptySitesRule()
        stale = StaleAssetsRule()
        rule_results.append(safe_run_rule(missing_os, lambda: missing_os.run(client, t)))
        rule_results.append(safe_run_rule(empty_sites, lambda: empty_sites.run(snapshot, t)))
        rule_results.append(safe_run_rule(stale, lambda: stale.run(client, t)))

        # Duplicate detection — single paginate, two rules. On large consoles
        # the paginate is infeasible (v3 has no group-by, ~45s/page on 500k
        # assets), so peek totalResources first and skip with a Console-UI
        # pointer above the configured ceiling.
        host_rule = DuplicateHostnamesRule()
        ip_rule = DuplicateIpsRule()

        if not (t.flag_duplicate_hostnames or t.flag_duplicate_ips):
            # Both flags off: take the existing skipped path. Do NOT peek
            # (avoid a wasted API request when the user has explicitly
            # disabled both rules).
            rule_results.append(safe_run_rule(host_rule, lambda: host_rule.run([], t)))
            rule_results.append(safe_run_rule(ip_rule, lambda: ip_rule.run([], t)))
        else:
            rule_results.extend(_run_duplicate_detection(client, t, host_rule, ip_rule, snapshot))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=rule_summary(rule_results),
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )

