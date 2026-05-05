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
    safe_run,
    skipped_rule,
)
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10
_PER_ITEM_FINDING_CAP = 500
_SRC_FILTERED_SEARCH = "https://docs.rapid7.com/insightvm/filtered-asset-search"
_SRC_ASSET_GROUPS = "https://docs.rapid7.com/insightvm/asset-groups/"
_SRC_INSIGHT_AGENT = "https://docs.rapid7.com/insightvm/insight-agent-overview/"


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


def _asset_label(asset: dict) -> str:
    return asset.get("hostName") or asset.get("ip") or f"id={asset.get('id')}"


def _per_asset_findings(
    assets: list[dict],
    severity: str,
    message_for,
    extra_details: dict | None = None,
) -> list[Finding]:
    """Emit one Finding per asset, capped at _PER_ITEM_FINDING_CAP.

    Beyond the cap, append a single rollup Finding so the report's findings
    count stays bounded while still reflecting the actual affected-asset count
    in the row. ``message_for(asset) -> str`` builds the per-asset message.
    """
    findings: list[Finding] = []
    head = assets[:_PER_ITEM_FINDING_CAP]
    for asset in head:
        details: dict = {
            "asset_id": asset.get("id"),
            "hostName": asset.get("hostName"),
            "ip": asset.get("ip"),
        }
        if extra_details:
            details.update(extra_details)
        findings.append(Finding(
            severity=severity,
            message=message_for(asset),
            details=details,
        ))
    remainder = len(assets) - len(head)
    if remainder > 0:
        rollup_details: dict = {
            "remainder": remainder,
            "total": len(assets),
            "cap": _PER_ITEM_FINDING_CAP,
        }
        if extra_details:
            rollup_details.update(extra_details)
        findings.append(Finding(
            severity=severity,
            message=f"+ {remainder} more asset(s) (truncated; showing first {_PER_ITEM_FINDING_CAP})",
            details=rollup_details,
        ))
    return findings


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(self, client: Any, config: AppConfig, *, snapshot: "EnvSnapshot | None" = None) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.asset_coverage
        rule_results: list[RuleResult] = [
            safe_run(
                lambda: self._stale_assets(client, t),
                rule_id="op.asset_coverage.stale_assets",
                rule_name="Stale assets",
                description=(
                    "Assets whose last scan is older than the stale threshold "
                    "(coverage gap, but not yet expired)."
                ),
                sources=[_SRC_FILTERED_SEARCH],
            ),
            safe_run(
                lambda: self._never_scanned_assets(client, t),
                rule_id="op.asset_coverage.never_scanned_assets",
                rule_name="Never-scanned assets",
                description=(
                    "Assets whose last scan exceeds the never-scanned threshold — "
                    "treated as effectively unscanned."
                ),
                sources=[_SRC_FILTERED_SEARCH],
                default_severity="fail",
            ),
            safe_run(
                lambda: self._dead_asset_groups(snapshot, t),
                rule_id="op.asset_coverage.dead_asset_groups",
                rule_name="Dead asset groups",
                description=(
                    "Asset groups whose membership criteria match zero assets. "
                    "Orphaned RBAC/report scopes."
                ),
                sources=[_SRC_ASSET_GROUPS],
            ),
            safe_run(
                lambda: self._agent_only_assets(snapshot, client, t, config.audit),
                rule_id="op.asset_coverage.agent_only_assets",
                rule_name="Insight Agent assets outside scheduled scan scope",
                description=(
                    "Assets reporting via Insight Agent whose IP falls outside "
                    "every site's configured included_targets. These assets only "
                    "get opportunistic agent data; they're never reached by "
                    "scheduled scans."
                ),
                sources=[_SRC_INSIGHT_AGENT],
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
        findings = _per_asset_findings(
            stale,
            severity="warn",
            message_for=lambda a: (
                f"Stale asset {_asset_label(a)}: no scan in last {t.stale_asset_days} days"
            ),
            extra_details={"stale_asset_days": t.stale_asset_days},
        )
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
        findings = _per_asset_findings(
            unscanned,
            severity="fail",
            message_for=lambda a: (
                f"Never-scanned asset {_asset_label(a)}: no scan in last {t.never_scanned_days} days"
            ),
            extra_details={"never_scanned_days": t.never_scanned_days},
        )
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
        head = dead[:_PER_ITEM_FINDING_CAP]
        for g in head:
            label = g.get("name") or f"id={g.get('id')}"
            findings.append(Finding(
                severity="warn",
                message=f"Asset group '{label}' has zero members",
                details={
                    "group_id": g.get("id"),
                    "group_name": g.get("name"),
                    "type": g.get("type"),
                },
            ))
        remainder = len(dead) - len(head)
        if remainder > 0:
            findings.append(Finding(
                severity="warn",
                message=f"+ {remainder} more group(s) (truncated; showing first {_PER_ITEM_FINDING_CAP})",
                details={"remainder": remainder, "total": len(dead), "cap": _PER_ITEM_FINDING_CAP},
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
        head = outsiders[:_PER_ITEM_FINDING_CAP]
        for o in head:
            label = o.get("hostname") or o.get("ip") or f"id={o.get('asset_id')}"
            findings.append(Finding(
                severity="warn",
                message=f"Agent-managed asset {label} is outside every site's scan scope",
                details=o,
            ))
        remainder = len(outsiders) - len(head)
        if remainder > 0:
            findings.append(Finding(
                severity="warn",
                message=f"+ {remainder} more asset(s) (truncated; showing first {_PER_ITEM_FINDING_CAP})",
                details={"remainder": remainder, "total": len(outsiders), "cap": _PER_ITEM_FINDING_CAP},
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
