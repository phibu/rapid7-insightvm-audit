from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any, Callable

logger = logging.getLogger(__name__)

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.client import Rapid7ClientError

if TYPE_CHECKING:
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.checks._op_rule import (
    make_rule_result,
    safe_run_rule,
    skipped_rule,
)
from rapid7_healthcheck.checks._op_runner import OpCheckDescriptor, OpCheckRunner
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


def _capped_findings_with_rollup(
    items: list,
    build_finding: Callable[[dict], Finding],
    severity: str,
    label: str,
    cap: int = _PER_ITEM_FINDING_CAP,
    rollup_details_extra: dict | None = None,
    total: int | None = None,
) -> list[Finding]:
    """Build per-item findings up to ``cap``; append one rollup Finding for the
    remainder.

    ``label`` is the noun used in the rollup message:
    ``"+ N more <label>(s) (truncated; showing first <cap>)"``.
    ``rollup_details_extra`` is merged into the rollup finding's ``details``
    dict (alongside the canonical ``remainder`` / ``total`` / ``cap`` keys).

    ``total`` overrides the affected-population size used for the rollup
    math. By default the population is ``len(items)`` — correct when the
    caller materialized the whole result set. When the caller deliberately
    fetched only a bounded head (e.g. the first ``cap`` rows, with the
    true count read from ``page.totalResources``), it MUST pass ``total``
    so the rollup remainder and ``details["total"]`` reflect the real
    population rather than the truncated ``items`` length. ``total`` must
    be ``>= len(items)``.
    """
    findings: list[Finding] = []
    head = items[:cap]
    for item in head:
        findings.append(build_finding(item))
    effective_total = len(items) if total is None else max(total, len(items))
    remainder = effective_total - len(head)
    if remainder > 0:
        rollup_details: dict = {
            "remainder": remainder,
            "total": effective_total,
            "cap": cap,
        }
        if rollup_details_extra:
            rollup_details.update(rollup_details_extra)
        findings.append(Finding(
            severity=severity,
            message=(
                f"+ {remainder} more {label}(s) "
                f"(truncated; showing first {cap})"
            ),
            details=rollup_details,
        ))
    return findings


def _per_asset_findings(
    assets: list[dict],
    severity: str,
    message_for,
    extra_details: dict | None = None,
    total: int | None = None,
) -> list[Finding]:
    """Emit one Finding per asset, capped at _PER_ITEM_FINDING_CAP.

    Beyond the cap, append a single rollup Finding so the report's findings
    count stays bounded while still reflecting the actual affected-asset count
    in the row. ``message_for(asset) -> str`` builds the per-asset message.

    ``total`` is forwarded to ``_capped_findings_with_rollup`` — pass it when
    ``assets`` is a bounded head of a larger population so the rollup count
    stays accurate without materializing the whole result set.
    """
    def _build(asset: dict) -> Finding:
        details: dict = {
            "asset_id": asset.get("id"),
            "hostName": asset.get("hostName"),
            "ip": asset.get("ip"),
        }
        if extra_details:
            details.update(extra_details)
        return Finding(
            severity=severity,
            message=message_for(asset),
            details=details,
        )

    return _capped_findings_with_rollup(
        assets,
        _build,
        severity=severity,
        label="asset",
        rollup_details_extra=extra_details,
        total=total,
    )


def _bounded_asset_search(
    client: Any,
    json_body: dict,
    *,
    cap: int = _PER_ITEM_FINDING_CAP,
) -> tuple[list[dict], int]:
    """Fetch only the first ``cap`` matching assets, plus the exact total.

    Returns ``(head, total)``:
        - ``head``: at most ``cap`` asset dicts — enough to fill the
          per-asset findings the report actually renders.
        - ``total``: exact match count from ``page.totalResources``.

    Why this exists: the report caps per-asset findings at
    ``_PER_ITEM_FINDING_CAP`` and shows the rest as a single rollup. Fully
    paginating the result set (``paginate_post``) to then discard everything
    past the cap is the bug this replaces — on a console with 50k stale
    assets that was ~100 sequential POSTs (~19 min) to render 500 rows.

    Issues ``ceil(cap / page_size)`` POSTs — normally **one**, since the
    default page size (500) equals the cap. The exact total still comes
    from the first page's metadata, so ``summary`` counts and the rollup
    remainder are byte-identical to the old full-enumeration behavior.

    Read-only: ``/api/3/assets/search`` is the lone allowlisted POST path;
    this issues only POSTs to it.
    """
    head: list[dict] = []
    total = 0
    page = 0
    page_size = 500
    while len(head) < cap:
        body = client.post_one(
            "/api/3/assets/search",
            json_body=json_body,
            params={"page": page, "size": page_size},
        )
        if page == 0:
            total = int(body.get("page", {}).get("totalResources", 0))
        resources = body.get("resources", []) or []
        if not resources:
            break
        head.extend(resources)
        meta = body.get("page", {})
        total_pages = int(meta.get("totalPages", 0))
        page += 1
        if total_pages and page >= total_pages:
            break
    return head[:cap], total


class StaleAssetsRule:
    RULE_ID = "op.asset_coverage.stale_assets"
    RULE_NAME = "Stale assets"
    DESCRIPTION = (
        "Assets whose last scan is older than the stale threshold "
        "(coverage gap, but not yet expired)."
    )
    SOURCES = (_SRC_FILTERED_SEARCH,)
    DEFAULT_SEVERITY = "warn"

    def run(self, client: Any, t) -> RuleResult:
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
        stale, stale_total = _bounded_asset_search(client, body)
        findings = _per_asset_findings(
            stale,
            severity="warn",
            message_for=lambda a: (
                f"Stale asset {_asset_label(a)}: no scan in last {t.stale_asset_days} days"
            ),
            extra_details={"stale_asset_days": t.stale_asset_days},
            total=stale_total,
        )
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"stale_count": stale_total, "stale_asset_days": t.stale_asset_days},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class NeverScannedAssetsRule:
    RULE_ID = "op.asset_coverage.never_scanned_assets"
    RULE_NAME = "Never-scanned assets"
    DESCRIPTION = (
        "Assets whose last scan exceeds the never-scanned threshold — "
        "treated as effectively unscanned."
    )
    SOURCES = (_SRC_FILTERED_SEARCH,)
    DEFAULT_SEVERITY = "fail"

    def run(self, client: Any, t) -> RuleResult:
        if not t.flag_unscanned_assets:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )

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
        unscanned, unscanned_total = _bounded_asset_search(client, body)
        findings = _per_asset_findings(
            unscanned,
            severity="fail",
            message_for=lambda a: (
                f"Never-scanned asset {_asset_label(a)}: no scan in last {t.never_scanned_days} days"
            ),
            extra_details={"never_scanned_days": t.never_scanned_days},
            total=unscanned_total,
        )
        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={"unscanned_count": unscanned_total, "never_scanned_days": t.never_scanned_days},
            duration_ms=int((time.monotonic() - rule_start) * 1000),
            default_severity="fail",
        )


class DeadAssetGroupsRule:
    RULE_ID = "op.asset_coverage.dead_asset_groups"
    RULE_NAME = "Asset groups with zero members"
    DESCRIPTION = (
        "Asset groups whose membership criteria match no assets — orphaned "
        "RBAC/report scopes that were probably created for a project that "
        "ended or for assets that have since been removed."
    )
    SOURCES = (_SRC_ASSET_GROUPS,)
    DEFAULT_SEVERITY = "warn"

    def run(self, snapshot: "EnvSnapshot | None", t) -> RuleResult:
        if not t.flag_dead_asset_groups:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )

        if snapshot is None:
            # An error RuleResult carries no findings — the reason lives in
            # summary, matching the error_rule() helper. A warn-severity
            # finding inside an error rule would leak into flatten_findings
            # and the delta signature index.
            return RuleResult(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                severity=self.DEFAULT_SEVERITY,
                status="error",
                findings=[],
                summary={"dead_groups_count": 0, "error": "snapshot required"},
                error="snapshot required but not provided to check",
                sources=self.SOURCES,
            )

        rule_start = time.monotonic()
        groups = snapshot.asset_groups()

        # Pass 1: classify by inline count.
        zero_inline: list[dict] = []      # inline == 0 → definitely dead
        missing_inline: list[dict] = []   # inline is None / non-numeric → fallback candidate
        for g in groups:
            inline = g.get("assets")
            if inline is None:
                missing_inline.append(g)
                continue
            try:
                if int(inline) == 0:
                    zero_inline.append(g)
            except (TypeError, ValueError):
                # Non-numeric inline value: treat as missing for safety.
                missing_inline.append(g)
            # else: inline > 0, alive, skip.

        # Pass 2: resolve fallback candidates up to the cap.
        fallback_cap = int(t.dead_groups_fallback_cap)
        fallback_calls = 0
        fallback_errors = 0
        fallback_dead: list[dict] = []
        error_findings: list[Finding] = []
        for g in missing_inline:
            if fallback_calls >= fallback_cap:
                break
            count = snapshot.asset_group_member_count(g.get("id"))
            fallback_calls += 1
            if count is None:
                fallback_errors += 1
                gid = g.get("id")
                gname = g.get("name") or f"id={gid}"
                error_findings.append(Finding(
                    severity="info",
                    message=(
                        f"Could not resolve membership for asset group "
                        f"'{gname}' (HTTP error); excluded from dead-group "
                        f"analysis."
                    ),
                    details={
                        "group_id": gid,
                        "group_name": g.get("name"),
                        "type": g.get("type"),
                    },
                ))
            elif count == 0:
                fallback_dead.append(g)
            # else: alive, skip.

        fallback_cap_reached = fallback_calls < len(missing_inline)
        fallback_skipped = len(missing_inline) - fallback_calls

        dead = zero_inline + fallback_dead
        # Track which groups came from the fallback path so we can label them.
        # API group IDs are unique per console, so g["id"] is the natural key.
        fallback_dead_ids = {g.get("id") for g in fallback_dead}
        def _build_dead_group(g: dict) -> Finding:
            label = g.get("name") or f"id={g.get('id')}"
            details = {
                "group_id": g.get("id"),
                "group_name": g.get("name"),
                "type": g.get("type"),
            }
            if g.get("id") in fallback_dead_ids:
                details["resolved_via"] = "per_group_fallback"
            return Finding(
                severity="warn",
                message=f"Asset group '{label}' has zero members",
                details=details,
            )

        findings: list[Finding] = _capped_findings_with_rollup(
            dead,
            _build_dead_group,
            severity="warn",
            label="group",
        )

        # Append fallback diagnostics as info-severity findings.
        findings.extend(error_findings)
        if fallback_cap_reached:
            findings.append(Finding(
                severity="info",
                message=(
                    f"+ {fallback_skipped} more group(s) had missing inline "
                    f"counts; per-group fallback skipped (cap={fallback_cap}). "
                    f"Raise dead_groups_fallback_cap to inspect more."
                ),
                details={
                    "missing_inline_total": len(missing_inline),
                    "fallback_calls_made": fallback_calls,
                    "fallback_cap": fallback_cap,
                },
            ))

        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={
                "dead_groups_count": len(dead),
                "total_groups": len(groups),
                "groups_with_missing_count": len(missing_inline),
                "fallback_calls_made": fallback_calls,
                "fallback_cap_reached": fallback_cap_reached,
                "fallback_errors": fallback_errors,
            },
            examined=len(groups),
            failed=len(dead),
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class AgentOnlyAssetsRule:
    RULE_ID = "op.asset_coverage.agent_only_assets"
    RULE_NAME = "Insight Agent assets outside scheduled scan scope"
    DESCRIPTION = (
        "Assets reporting via Insight Agent whose IP falls outside "
        "every site's configured included_targets. These assets only "
        "get opportunistic agent data; they're never reached by "
        "scheduled scans.\n\n"
        "Sampled. Inspects up to audit.sample_size agents (default "
        "100) drawn in API default order from /api/3/agents. Result "
        "is a directional estimate, not a complete inventory — for "
        "environments with hundreds of thousands of agents, full "
        "enumeration is intentionally avoided. Increase "
        "audit.sample_size for a tighter estimate at the cost of "
        "more API calls."
    )
    SOURCES = (_SRC_INSIGHT_AGENT,)
    DEFAULT_SEVERITY = "warn"

    def run(
        self,
        snapshot: "EnvSnapshot | None",
        client: Any,
        t,
        audit_settings,
    ) -> RuleResult:
        if not t.flag_agent_only_assets:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )

        if snapshot is None:
            # An error RuleResult carries no findings — the reason lives in
            # summary, matching the error_rule() helper. A warn-severity
            # finding inside an error rule would leak into flatten_findings
            # and the delta signature index.
            return RuleResult(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                severity=self.DEFAULT_SEVERITY,
                status="error",
                findings=[],
                summary={"agent_only_count_sampled": 0, "error": "snapshot required"},
                error="snapshot required but not provided to check",
                sources=self.SOURCES,
            )

        rule_start = time.monotonic()

        # Prime _agents_unavailable via the sampled accessor — its head probe
        # is the only thing that flips the flag for this rule's code path.
        # Calling is_agents_unavailable() before this would always see the
        # initial False and miss the genuine 404 → empty-fleet ambiguity.
        sample_ids, total_agents = snapshot.agent_asset_ids_sampled()

        if snapshot.is_agents_unavailable():
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=f"{self.RULE_NAME} (agents endpoint unavailable on this console)",
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )

        targets = snapshot.all_included_targets()

        if targets is None:
            # snapshot fake / edge case — no scope coverage info, rule
            # indeterminate. An error RuleResult carries no findings; the
            # reason lives in summary/error (matches the error_rule() helper).
            return RuleResult(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                severity=self.DEFAULT_SEVERITY,
                status="error",
                findings=[],
                summary={"agent_only_count_sampled": 0, "error": "no targets"},
                error="all_included_targets() returned None",
                sources=self.SOURCES,
            )

        logger.info(
            "agent_only_assets: sampling %d of %d agents (sample_size=%d)",
            len(sample_ids),
            total_agents,
            audit_settings.sample_size,
        )

        # Empty fleet: short-circuit with an informational pass.
        if total_agents == 0:
            sample_info = (
                f"strategy=first-n; sampled=0; configured_sample_size="
                f"{audit_settings.sample_size}; population=0"
            )
            return make_rule_result(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                findings=[Finding(
                    severity="info",
                    message="No Insight Agents deployed in this environment.",
                )],
                sources=self.SOURCES,
                summary={
                    "agent_only_count_sampled": 0,
                    "sample_size": 0,
                    "sample_size_configured": audit_settings.sample_size,
                    "sampled_fetched": 0,
                    "total_agents": 0,
                    "sampled_outside_scope_pct": 0.0,
                    "estimated_outsiders_fleetwide": 0,
                },
                sampled=True,
                sample_info=sample_info,
                duration_ms=int((time.monotonic() - rule_start) * 1000),
            )

        outsiders: list[dict] = []
        fetched_count = 0
        for aid in sample_ids:
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

        denom = fetched_count if fetched_count > 0 else 1
        pct = round(len(outsiders) / denom * 100, 1)
        estimate = round(len(outsiders) / denom * total_agents) if total_agents else 0

        # Summary finding (always present): describes the sample + extrapolation.
        summary_severity = "warn" if outsiders else "info"
        sample_share_pct = round(fetched_count / total_agents * 100, 1) if total_agents else 0.0
        summary_finding = Finding(
            severity=summary_severity,
            message=(
                f"Sampled {fetched_count} of {total_agents} agents "
                f"({sample_share_pct}%): "
                f"{len(outsiders)} of sample ({pct}%) are outside every site's "
                f"scan scope. Extrapolated estimate: ≈{estimate} of {total_agents} "
                f"agents fleet-wide. Sample is first-N by API default order; "
                f"result is directional."
            ),
            details={
                "sample_size": len(sample_ids),
                "sample_size_configured": audit_settings.sample_size,
                "sampled_fetched": fetched_count,
                "total_agents": total_agents,
                "outsiders_in_sample": len(outsiders),
                "sampled_outside_scope_pct": pct,
                "estimated_outsiders_fleetwide": estimate,
            },
        )

        findings: list[Finding] = [summary_finding]

        def _build_outsider(o: dict) -> Finding:
            label = o.get("hostname") or o.get("ip") or f"id={o.get('asset_id')}"
            return Finding(
                severity="warn",
                message=f"Agent-managed asset {label} is outside every site's scan scope",
                details=o,
            )

        findings.extend(_capped_findings_with_rollup(
            outsiders,
            _build_outsider,
            severity="warn",
            label="asset",
        ))

        sample_info = (
            f"strategy=first-n; sampled={len(sample_ids)}; "
            f"configured_sample_size={audit_settings.sample_size}; "
            f"population={total_agents}; "
            f"note=Sample is first-N by API default order, not uniform random. "
            f"Result is directional."
        )

        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={
                "agent_only_count_sampled": len(outsiders),
                "sample_size": len(sample_ids),
                "sample_size_configured": audit_settings.sample_size,
                "sampled_fetched": fetched_count,
                "total_agents": total_agents,
                "sampled_outside_scope_pct": pct,
                "estimated_outsiders_fleetwide": estimate,
            },
            sampled=True,
            sample_info=sample_info,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class GhostAssetsRule:
    RULE_ID = "op.asset_coverage.ghost_assets"
    RULE_NAME = "Ghost assets (no OS AND no hostname)"
    DESCRIPTION = (
        "Assets the console knows about but cannot identify — neither an OS "
        "fingerprint nor a hostname. Typically the result of stale agent "
        "registrations, network-only scans of unreachable hosts, or import "
        "errors. Stricter than the data-quality 'missing OS' rule, which "
        "flags on either gap alone."
    )
    SOURCES = (_SRC_FILTERED_SEARCH,)
    DEFAULT_SEVERITY = "fail"

    def run(self, client: Any, t) -> RuleResult:
        if not t.flag_ghost_assets:
            return skipped_rule(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                description=self.DESCRIPTION,
                sources=self.SOURCES,
            )

        rule_start = time.monotonic()
        # Server-side: assets with no OS fingerprint (small candidate set).
        # The v3 spec does not verify a server-side `host-name is-empty`
        # filter, so we narrow on hostName client-side instead.
        body = client.post_one(
            "/api/3/assets/search",
            json_body={
                "filters": [{"field": "operating-system", "operator": "is-empty"}],
                "match": "all",
            },
            params={"size": _PER_ITEM_FINDING_CAP * 2},
        )
        candidates = body.get("resources", []) or []

        # Client-side narrow: also missing hostName (whitespace-only counts as empty).
        ghosts = [
            a for a in candidates
            if not (a.get("hostName") or "").strip()
        ]

        findings: list[Finding] = []
        emitted = 0
        for ghost in ghosts:
            if emitted >= _PER_ITEM_FINDING_CAP:
                break
            findings.append(Finding(
                severity="fail",
                message=f"Asset id={ghost.get('id')} has no OS and no hostname (ghost record)",
                details={
                    "id": ghost.get("id"),
                    "ip": ghost.get("ip"),
                    "mac": ghost.get("mac"),
                },
            ))
            emitted += 1

        if len(ghosts) > emitted:
            findings.append(Finding(
                severity="warn",
                message=(
                    f"{len(ghosts) - emitted} additional ghost assets omitted "
                    f"from findings (capped at {_PER_ITEM_FINDING_CAP})"
                ),
                details={
                    "remainder": len(ghosts) - emitted,
                    "total": len(ghosts),
                    "cap": _PER_ITEM_FINDING_CAP,
                },
            ))

        return make_rule_result(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=self.DESCRIPTION,
            findings=findings,
            sources=self.SOURCES,
            summary={
                "ghost_count": len(ghosts),
                "candidates_examined": len(candidates),
            },
            examined=len(candidates),
            failed=len(ghosts),
            default_severity=self.DEFAULT_SEVERITY,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: "EnvSnapshot | None" = None,
        **_kwargs: object,
    ) -> CheckResult:
        descriptor = OpCheckDescriptor(
            name=self.name,
            description=self.description,
            produce_rule_results=self._produce,
        )
        return OpCheckRunner().run(descriptor, client=client, config=config, snapshot=snapshot)

    def _produce(self, client: Any, config: AppConfig, snapshot: Any) -> list[RuleResult]:
        t = config.thresholds.asset_coverage
        stale = StaleAssetsRule()
        never = NeverScannedAssetsRule()
        dead = DeadAssetGroupsRule()
        agent_only = AgentOnlyAssetsRule()
        ghost = GhostAssetsRule()
        return [
            safe_run_rule(stale, lambda: stale.run(client, t)),
            safe_run_rule(never, lambda: never.run(client, t)),
            safe_run_rule(dead, lambda: dead.run(snapshot, t)),
            safe_run_rule(agent_only, lambda: agent_only.run(snapshot, client, t, config.audit)),
            safe_run_rule(ghost, lambda: ghost.run(client, t)),
        ]
