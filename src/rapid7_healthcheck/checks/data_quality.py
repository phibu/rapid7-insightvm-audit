from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Callable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    error_rule,
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    skipped_rule,
)
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)

_EXAMPLES_LIMIT = 10

_SRC_ASSET_SEARCH = "https://help.rapid7.com/insightvm/en-us/api/index.html#operation/findAssets"
_SRC_SITES = "https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Site"
_SRC_FILTERED_SEARCH = "https://docs.rapid7.com/insightvm/filtered-asset-search"
_SRC_DUPLICATE_ASSETS = "https://docs.rapid7.com/insightvm/managing-assets#duplicate-assets"


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class DataQualityCheck:
    name = "Data Quality"
    description = (
        "Assets without OS fingerprint, sites with zero assets, "
        "long-stale assets, and duplicate hostnames/IPs."
    )

    def run(self, client: Any, config: AppConfig, **_kwargs: object) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.data_quality
        rule_results: list[RuleResult] = []

        # Per-rule isolation: a single rule's API call timing out or 400-ing
        # must not blackhole the rest of the check. Mirrors the audit
        # orchestrator's pattern. Each rule's identity is duplicated here
        # because the helper synthesizes a RuleResult shell when the rule
        # method itself raises before returning.
        rule_results.append(self._safe(
            lambda: self._missing_os(client, t),
            rid="op.data_quality.missing_os",
            name="Assets without OS fingerprint",
            desc="Assets where the operating-system field is empty (fingerprinting failed or never ran).",
            sources=[_SRC_FILTERED_SEARCH, _SRC_ASSET_SEARCH],
        ))
        rule_results.append(self._safe(
            lambda: self._empty_sites(client, t),
            rid="op.data_quality.empty_sites",
            name="Sites with zero assets",
            desc="Sites whose include/exclude scope currently matches no assets.",
            sources=[_SRC_SITES],
        ))
        rule_results.append(self._safe(
            lambda: self._stale_assets(client, t),
            rid="op.data_quality.stale_assets",
            name="Long-stale assets",
            desc=(
                "Assets whose last scan is older than the data-quality threshold. "
                "Distinct from Asset Coverage's never-scanned signal — this flags "
                "asset records whose data is so old it's likely unreliable."
            ),
            sources=[_SRC_FILTERED_SEARCH],
        ))

        # Duplicate detection — single paginate, two rules. If the paginate
        # itself fails, both rules surface as errors (the helper synthesizes
        # one error_rule per concept so the report still shows both rule cards).
        try:
            dup_rules = self._duplicates(client, t)
            rule_results.extend(dup_rules)
        except Exception as e:
            logger.exception("data_quality._duplicates raised")
            rule_results.append(error_rule(
                rule_id="op.data_quality.duplicate_hostnames",
                rule_name="Duplicate hostnames",
                description="Assets with the same hostName (case-insensitive) — likely duplicate records.",
                sources=[_SRC_DUPLICATE_ASSETS],
                error=e,
            ))
            rule_results.append(error_rule(
                rule_id="op.data_quality.duplicate_ips",
                rule_name="Duplicate IPs",
                description="Assets sharing an IP — usually two records for one host (re-imaged, agent + scan).",
                sources=[_SRC_DUPLICATE_ASSETS],
                error=e,
            ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=rule_summary(rule_results),
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )

    def _safe(
        self,
        fn: Callable[[], RuleResult],
        *,
        rid: str,
        name: str,
        desc: str,
        sources: list[str],
    ) -> RuleResult:
        """Run a rule producer; on any exception, return an error RuleResult.

        Identity (rid/name/desc/sources) is supplied here because the rule
        method may raise before returning, so we cannot read its internal
        constants reflectively. Stays in sync with each rule method's
        own constants — drift is caught by the data_quality unit tests.
        """
        rule_start = time.monotonic()
        try:
            return fn()
        except Exception as e:
            logger.exception("data_quality rule %s raised", rid)
            return error_rule(
                rule_id=rid,
                rule_name=name,
                description=desc,
                sources=sources,
                error=e,
                duration_ms=int((time.monotonic() - rule_start) * 1000),
            )

    # ----- per-concept rules -----

    def _missing_os(self, client: Any, t) -> RuleResult:
        rid = "op.data_quality.missing_os"
        name = "Assets without OS fingerprint"
        desc = "Assets where the operating-system field is empty (fingerprinting failed or never ran)."
        sources = [_SRC_FILTERED_SEARCH, _SRC_ASSET_SEARCH]

        if not t.flag_missing_os:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

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
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"missing_os_count": total},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _empty_sites(self, client: Any, t) -> RuleResult:
        rid = "op.data_quality.empty_sites"
        name = "Sites with zero assets"
        desc = "Sites whose include/exclude scope currently matches no assets."
        sources = [_SRC_SITES]

        if not t.flag_empty_sites:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        rule_start = time.monotonic()
        empty_sites: list[dict] = []
        for site in client.paginate("/api/3/sites"):
            site_id = site.get("id")
            body = client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
            total = int(body.get("page", {}).get("totalResources", 0))
            if total == 0:
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
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"empty_sites_count": len(empty_sites)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _stale_assets(self, client: Any, t) -> RuleResult:
        rid = "op.data_quality.stale_assets"
        name = "Long-stale assets"
        desc = (
            "Assets whose last scan is older than the data-quality threshold. "
            "Distinct from Asset Coverage's never-scanned signal — this flags "
            "asset records whose data is so old it's likely unreliable."
        )
        sources = [_SRC_FILTERED_SEARCH]

        if not t.flag_stale_assets:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

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
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"stale_assets_count": total},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _duplicates(self, client: Any, t) -> list[RuleResult]:
        host_rid = "op.data_quality.duplicate_hostnames"
        host_name = "Duplicate hostnames"
        host_desc = (
            "Multiple asset records share the same hostname (case-insensitive). "
            "Classic agent + scan-engine collision; can also indicate stale records."
        )
        ip_rid = "op.data_quality.duplicate_ips"
        ip_name = "Duplicate IP addresses"
        ip_desc = (
            "Multiple asset records share the same IP. "
            "Often a DHCP-driven re-IPing where MAC tracking is incomplete."
        )
        sources = [_SRC_DUPLICATE_ASSETS]

        # Fast path: both disabled — return two skipped rules, no paginate.
        if not (t.flag_duplicate_hostnames or t.flag_duplicate_ips):
            return [
                skipped_rule(rule_id=host_rid, rule_name=host_name, description=host_desc, sources=sources),
                skipped_rule(rule_id=ip_rid, rule_name=ip_name, description=ip_desc, sources=sources),
            ]

        rule_start = time.monotonic()
        by_host: dict[str, list[dict]] = defaultdict(list)
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for asset in client.paginate("/api/3/assets"):
            if t.flag_duplicate_hostnames:
                host = (asset.get("hostName") or "").strip().lower()
                if host:
                    by_host[host].append(asset)
            if t.flag_duplicate_ips:
                ip = (asset.get("ip") or "").strip()
                if ip:
                    by_ip[ip].append(asset)
        elapsed_ms = int((time.monotonic() - rule_start) * 1000)

        results: list[RuleResult] = []

        if t.flag_duplicate_hostnames:
            groups = [
                {"key": k, "ids": [a.get("id") for a in assets], "count": len(assets)}
                for k, assets in by_host.items()
                if len(assets) > 1
            ]
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
            results.append(make_rule_result(
                rule_id=host_rid,
                rule_name=host_name,
                description=host_desc,
                findings=findings,
                sources=sources,
                summary={"duplicate_hostname_groups": len(groups)},
                duration_ms=elapsed_ms,
            ))
        else:
            results.append(skipped_rule(
                rule_id=host_rid, rule_name=host_name, description=host_desc, sources=sources,
            ))

        if t.flag_duplicate_ips:
            groups = [
                {"key": k, "ids": [a.get("id") for a in assets], "count": len(assets)}
                for k, assets in by_ip.items()
                if len(assets) > 1
            ]
            findings = []
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
            results.append(make_rule_result(
                rule_id=ip_rid,
                rule_name=ip_name,
                description=ip_desc,
                findings=findings,
                sources=sources,
                summary={"duplicate_ip_groups": len(groups)},
                duration_ms=elapsed_ms,
            ))
        else:
            results.append(skipped_rule(
                rule_id=ip_rid, rule_name=ip_name, description=ip_desc, sources=sources,
            ))

        return results
