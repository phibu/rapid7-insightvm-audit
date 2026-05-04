from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.client import Rapid7ClientError

if TYPE_CHECKING:
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    make_rule_result,
    rollup_check_status,
    rule_summary,
    skipped_rule,
)
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10
_SRC_FILTERED_SEARCH = "https://docs.rapid7.com/insightvm/filtered-asset-search"
_SRC_ASSET_GROUPS = "https://docs.rapid7.com/insightvm/asset-groups/"
_SRC_INSIGHT_AGENT = "https://docs.rapid7.com/insightvm/insight-agent-overview/"


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(self, client: Any, config: AppConfig, *, snapshot: "EnvSnapshot | None" = None) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.asset_coverage
        rule_results: list[RuleResult] = [
            self._stale_assets(client, t),
            self._never_scanned_assets(client, t),
            self._dead_asset_groups(snapshot, t),
            self._unauth_only_assets(client, t),
            self._no_services_detected(client, t),
            self._agent_only_assets(snapshot, client, t, config.audit),
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

    def _stale_assets(self, client: Any, t) -> RuleResult:
        rid = "op.asset_coverage.stale_assets"
        name = "Stale assets"
        desc = (
            "Assets whose last scan is older than the stale threshold "
            "(coverage gap, but not yet expired)."
        )
        sources = [_SRC_FILTERED_SEARCH]

        rule_start = time.monotonic()
        body = {
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-earlier-than",
                    "value": t.stale_asset_days,
                }
            ],
            "match": "all",
        }
        stale = list(client.paginate_post("/api/3/assets/search", json_body=body))
        findings: list[Finding] = []
        if stale:
            findings.append(Finding(
                severity="warn",
                message=f"{len(stale)} stale asset(s) (no scan in last {t.stale_asset_days} days)",
                details={"total": len(stale), "examples": _example_hostnames(stale)},
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"stale_count": len(stale), "stale_asset_days": t.stale_asset_days},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _never_scanned_assets(self, client: Any, t) -> RuleResult:
        rid = "op.asset_coverage.never_scanned_assets"
        name = "Never-scanned assets"
        desc = (
            "Assets whose last scan exceeds the never-scanned threshold — "
            "treated as effectively unscanned."
        )
        sources = [_SRC_FILTERED_SEARCH]

        if not t.flag_unscanned_assets:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        rule_start = time.monotonic()
        body = {
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-earlier-than",
                    "value": t.never_scanned_days,
                }
            ],
            "match": "all",
        }
        unscanned = list(client.paginate_post("/api/3/assets/search", json_body=body))
        findings: list[Finding] = []
        if unscanned:
            findings.append(Finding(
                severity="fail",
                message=(
                    f"{len(unscanned)} asset(s) have not been scanned in the last "
                    f"{t.never_scanned_days} days"
                ),
                details={"total": len(unscanned), "examples": _example_hostnames(unscanned)},
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"unscanned_count": len(unscanned), "never_scanned_days": t.never_scanned_days},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
            default_severity="fail",
        )

    def _dead_asset_groups(self, snapshot: "EnvSnapshot | None", t) -> RuleResult:
        rid = "op.asset_coverage.dead_asset_groups"
        name = "Asset groups with zero members"
        desc = (
            "Asset groups whose membership criteria match no assets — orphaned "
            "RBAC/report scopes that were probably created for a project that "
            "ended or for assets that have since been removed."
        )
        sources = [_SRC_ASSET_GROUPS]

        if not t.flag_dead_asset_groups:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        if snapshot is None:
            # make_rule_result derives status from finding severity (no "error" mapping); construct directly.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message="snapshot required but not provided to check")],
                summary={"dead_groups_count": 0, "error": "snapshot required"},
                sources=sources,
            )

        rule_start = time.monotonic()
        groups = snapshot.asset_groups()
        dead = [g for g in groups if int(g.get("assets") or 0) == 0]
        findings: list[Finding] = []
        if dead:
            findings.append(Finding(
                severity="warn",
                message=f"{len(dead)} asset group(s) have zero members",
                details={
                    "total": len(dead),
                    "examples": [
                        {
                            "group_id": g.get("id"),
                            "group_name": g.get("name", f"id={g.get('id')}"),
                            "type": g.get("type"),
                        }
                        for g in dead[:_EXAMPLES_LIMIT]
                    ],
                },
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"dead_groups_count": len(dead), "total_groups": len(groups)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _unauth_only_assets(self, client: Any, t) -> RuleResult:
        rid = "op.asset_coverage.unauth_only_assets"
        name = "Assets scanned but not authenticated"
        desc = (
            "Assets where vulnerability-assessed=false — they were discovered "
            "and possibly port-scanned but never assessed for vulnerabilities. "
            "Surface-level visibility only; masks real risk."
        )
        sources = [_SRC_FILTERED_SEARCH]

        if not t.flag_unauth_only_assets:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        rule_start = time.monotonic()
        body = {
            "filters": [
                {"field": "vulnerability-assessed", "operator": "is", "value": False},
            ],
            "match": "all",
        }
        try:
            unauth = list(client.paginate_post("/api/3/assets/search", json_body=body))
        except Rapid7ClientError as e:
            msg = (
                "filter not supported by this console version"
                if getattr(e, "status_code", None) == 400
                else str(e)[:200]
            )
            # make_rule_result derives status from finding severity (no "error" mapping); construct directly.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="fail",
                status="error",
                findings=[Finding(severity="warn", message=msg)],
                summary={"unauth_only_count": 0, "error": msg},
                sources=sources,
                duration_ms=int((time.monotonic() - rule_start) * 1000),
            )

        findings: list[Finding] = []
        if unauth:
            findings.append(Finding(
                severity="fail",
                message=f"{len(unauth)} asset(s) scanned but never authenticated",
                details={"total": len(unauth), "examples": _example_hostnames(unauth)},
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"unauth_only_count": len(unauth)},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
            default_severity="fail",
        )

    def _no_services_detected(self, client: Any, t) -> RuleResult:
        rid = "op.asset_coverage.no_services_detected"
        name = "Recently scanned assets with zero services detected"
        desc = (
            "Assets scanned within the stale-asset window but where the scan "
            "found zero services. Usually a firewall blocking the scan engine "
            "or a misconfigured site scope. Excludes already-stale assets to "
            "avoid double-counting with the stale_assets rule."
        )
        sources = [_SRC_FILTERED_SEARCH]

        if not t.flag_no_services_detected:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        rule_start = time.monotonic()
        body = {
            "filters": [
                {"field": "service-count", "operator": "is", "value": 0},
                {"field": "last-scan-date", "operator": "is-within-the-last", "value": t.stale_asset_days},
            ],
            "match": "all",
        }
        try:
            silent = list(client.paginate_post("/api/3/assets/search", json_body=body))
        except Rapid7ClientError as e:
            msg = (
                "filter not supported by this console version"
                if getattr(e, "status_code", None) == 400
                else str(e)[:200]
            )
            # make_rule_result derives status from finding severity (no "error" mapping); construct directly.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message=msg)],
                summary={"no_services_count": 0, "error": msg},
                sources=sources,
                duration_ms=int((time.monotonic() - rule_start) * 1000),
            )

        findings: list[Finding] = []
        if silent:
            findings.append(Finding(
                severity="warn",
                message=f"{len(silent)} recently-scanned asset(s) with zero services detected",
                details={"total": len(silent), "examples": _example_hostnames(silent)},
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={"no_services_count": len(silent), "stale_asset_days": t.stale_asset_days},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    def _agent_only_assets(self, snapshot: "EnvSnapshot | None", client: Any, t, audit_cfg) -> RuleResult:
        rid = "op.asset_coverage.agent_only_assets"
        name = "Insight Agent assets outside scheduled scan scope"
        desc = (
            "Assets reporting via Insight Agent whose IP falls outside every "
            "site's configured included_targets. These assets only get "
            "opportunistic agent data; they're never reached by scheduled scans."
        )
        sources = [_SRC_INSIGHT_AGENT]

        if not t.flag_agent_only_assets:
            return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

        if snapshot is None:
            # make_rule_result derives status from finding severity (no "error" mapping); construct directly.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message="snapshot required but not provided to check")],
                summary={"agent_only_count": 0, "error": "snapshot required"},
                sources=sources,
            )

        if not audit_cfg.full_scan:
            return skipped_rule(
                rule_id=rid,
                rule_name=name,
                description=desc + " (Requires audit.full_scan=true to run.)",
                sources=sources,
            )

        if snapshot.is_agents_unavailable():
            return skipped_rule(
                rule_id=rid,
                rule_name=f"{name} (agents endpoint unavailable on this console)",
                description=desc,
                sources=sources,
            )

        rule_start = time.monotonic()
        agent_ids = snapshot.agent_asset_ids()
        targets = snapshot.all_included_targets()

        if targets is None:
            # snapshot fake / edge case — treat as no scope coverage info, rule indeterminate.
            return RuleResult(
                rule_id=rid,
                rule_name=name,
                description=desc,
                severity="warn",
                status="error",
                findings=[Finding(severity="warn", message="all_included_targets() returned None")],
                summary={"agent_only_count": 0, "error": "no targets"},
                sources=sources,
            )

        outsiders: list[dict] = []
        fetched_count = 0
        for aid in agent_ids:
            try:
                asset = client.get(f"/api/3/assets/{aid}")
            except Rapid7ClientError as e:
                logger.warning("agent_only_assets: skipping asset %s due to error: %s", aid, e)
                continue
            fetched_count += 1
            ip_str = asset.get("ip")
            if not ip_str:
                continue
            if not targets.contains(str(ip_str)):
                outsiders.append({
                    "asset_id": aid,
                    "ip": str(ip_str),
                    "hostname": asset.get("hostName"),
                })

        findings: list[Finding] = []
        if outsiders:
            findings.append(Finding(
                severity="warn",
                message=f"{len(outsiders)} agent-managed asset(s) outside every site's scan scope",
                details={
                    "total": len(outsiders),
                    "examples": outsiders[:_EXAMPLES_LIMIT],
                },
            ))
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=findings,
            sources=sources,
            summary={
                "agent_only_count": len(outsiders),
                "total_agents_checked": fetched_count,
                "total_agents": len(agent_ids),
            },
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )
