from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.audit import RuleResult
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


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(self, client: Any, config: AppConfig, *, snapshot: Any = None) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.asset_coverage
        rule_results: list[RuleResult] = [
            self._stale_assets(client, t),
            self._never_scanned_assets(client, t),
            self._dead_asset_groups(snapshot, t),
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

    def _dead_asset_groups(self, snapshot: Any, t) -> RuleResult:
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
