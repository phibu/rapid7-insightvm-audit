from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules._agent_version import (
    LATEST_KNOWN_INSIGHT_AGENT_VERSION,
    find_agent_version,
)
from rapid7_healthcheck.checks import Finding

_ASSET_ID_SAMPLE_CAP = 50


def _format_version(v: tuple[int, int, int, int]) -> str:
    return ".".join(str(x) for x in v)


def _parse_version_string(s: str) -> tuple[int, int, int, int] | None:
    """Parse a 4-part dotted version string into a tuple. Returns None on
    any malformedness — the caller decides whether to skip or fall back."""
    if not isinstance(s, str):
        return None
    parts = s.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        ints = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return (ints[0], ints[1], ints[2], ints[3])


def _resolve_mode(rule_config: dict) -> tuple[str, tuple[int, int, int, int] | None, str | None]:
    """Resolve the (mode, reference_tuple, raw_pinned_string) triple."""
    pinned_raw = rule_config.get("pinned_version")
    if pinned_raw is not None:
        parsed = _parse_version_string(pinned_raw)
        return ("pinned", parsed, pinned_raw if parsed is None else None)
    if rule_config.get("use_latest_known"):
        return ("latest_known", LATEST_KNOWN_INSIGHT_AGENT_VERSION, None)
    return ("fleet_newest", None, None)


def _agent_asset_id(agent: dict) -> int | None:
    aid = agent.get("id")
    if isinstance(aid, int) and not isinstance(aid, bool):
        return aid
    return None


def _capped_asset_ids(agents: list[dict]) -> tuple[list[int], bool]:
    """Return up to _ASSET_ID_SAMPLE_CAP asset IDs from `agents` plus a
    `truncated` flag. Drops agents without a numeric asset id."""
    ids: list[int] = []
    for a in agents:
        aid = _agent_asset_id(a)
        if aid is not None:
            ids.append(aid)
    truncated = len(ids) > _ASSET_ID_SAMPLE_CAP
    return (ids[:_ASSET_ID_SAMPLE_CAP], truncated)


@register
class InsightAgentVersionCurrencyRule:
    rule_id = "insight_agent_version_currency"
    rule_name = "Insight Agent Version Currency"
    description = (
        "Reports Insight Agent version drift across the fleet, aggregated "
        "per version (one finding = one observed version, with the count of "
        "assets on it). Three modes, in precedence order: (1) pinned — "
        "`pinned_version: \"4.1.0.2\"` requires every agent to match exactly; "
        "both behind-pin and ahead-of-pin versions are flagged (the latter "
        "is a change-control gap). (2) latest-known — `use_latest_known: "
        "true` compares against a tool-maintained 'current latest' version, "
        "with `version_drift_minor` tolerance. (3) fleet-newest (default) — "
        "self-bootstrapping comparison against the newest version observed "
        "in the fleet, with `version_drift_minor` tolerance. Also reports "
        "the count of assets without any Insight Agent installed."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/insight-agent-overview/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        drift_threshold = rule_config.get("version_drift_minor", 1)
        try:
            drift_threshold = int(drift_threshold)
        except (TypeError, ValueError):
            drift_threshold = 1

        mode, reference, raw_pinned = _resolve_mode(rule_config)

        # Pinned mode with unparseable input — skip loudly.
        if mode == "pinned" and reference is None:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"pinned_version '{raw_pinned}' is not a parseable "
                        f"4-part version (e.g. '4.1.0.2'). Fix config or "
                        f"remove the knob to fall back to drift detection."
                    ),
                    details={"reason": "unparseable pinned_version", "pinned_version_raw": raw_pinned},
                )],
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": "pinned",
                    "reference_version": None,
                },
                sources=list(self.sources),
            )

        agents, total = snapshot.agents()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "/api/3/agents could not be enumerated (returned 404, or "
                        "timed out / network-errored). Either this console does "
                        "not expose the Insight Agent fleet via API, or the "
                        "endpoint is too slow on this environment. Audit agent "
                        "versions via the Security Console UI."
                    ),
                    details={"reason": "agents endpoint unavailable"},
                )],
                summary={
                    "agents_total": 0,
                    "endpoint_available": False,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        if total == 0:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message="No Insight Agents deployed — nothing to compare.",
                    details={"reason": "empty fleet"},
                )],
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        # Bucket agents by parsed version. Unparseable agents go into
        # their own bucket, surfaced as a single info finding.
        version_buckets: dict[tuple[int, int, int, int], list[dict]] = defaultdict(list)
        unparseable_agents: list[dict] = []
        for agent in agents:
            v = find_agent_version(agent)
            if v is None:
                unparseable_agents.append(agent)
            else:
                version_buckets[v].append(agent)

        agents_examined = sum(len(v) for v in version_buckets.values())

        # Fleet-newest needs >=2 parseable agents to compute drift; pinned and
        # latest-known only need >=1 (they have an external reference).
        min_required = 2 if mode == "fleet_newest" else 1
        if agents_examined < min_required:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"Only {agents_examined} agent(s) had parseable Insight Agent "
                        f"version strings; need at least {min_required} for "
                        f"{mode} mode."
                    ),
                    details={"reason": "insufficient parseable versions"},
                )],
                summary={
                    "agents_total": total,
                    "agents_examined": agents_examined,
                    "agents_unparseable": len(unparseable_agents),
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        # Resolve fleet-newest reference now that buckets are known.
        if mode == "fleet_newest":
            reference = max(version_buckets.keys())

        findings: list[Finding] = []
        drifted_assets = 0
        ahead_of_pin_assets = 0
        versions_drifted = 0

        for version in sorted(version_buckets.keys()):
            bucket = version_buckets[version]
            count = len(bucket)
            asset_ids, truncated = _capped_asset_ids(bucket)

            if mode == "pinned":
                if version == reference:
                    continue  # exact match — not a finding
                versions_drifted += 1
                drifted_assets += count
                if version > reference:
                    ahead_of_pin_assets += count
                    direction = "ahead"
                    msg = (
                        f"{count} asset(s) on Insight Agent {_format_version(version)} — "
                        f"ahead of pinned version {_format_version(reference)} "
                        f"(change-control gap)."
                    )
                else:
                    direction = "behind"
                    msg = (
                        f"{count} asset(s) on Insight Agent {_format_version(version)} — "
                        f"behind pinned version {_format_version(reference)}."
                    )
                findings.append(Finding(
                    severity=severity,
                    message=msg,
                    details={
                        "observed_version": _format_version(version),
                        "pinned_version": _format_version(reference),
                        "drift_direction": direction,
                        "asset_count": count,
                        "asset_ids_sample": asset_ids,
                        "asset_ids_truncated": truncated,
                    },
                ))
            else:
                # fleet_newest or latest_known — minor-drift logic.
                minor_drift = (reference[0] - version[0]) * 1000 + (reference[1] - version[1])
                if minor_drift > drift_threshold:
                    versions_drifted += 1
                    drifted_assets += count
                    if mode == "latest_known":
                        msg = (
                            f"{count} asset(s) on Insight Agent {_format_version(version)} — "
                            f"behind known-current {_format_version(reference)} by "
                            f"{minor_drift} minor version(s)."
                        )
                    else:  # fleet_newest
                        msg = (
                            f"{count} asset(s) on Insight Agent {_format_version(version)} — "
                            f"{minor_drift} minor version(s) behind newest "
                            f"({_format_version(reference)})."
                        )
                    findings.append(Finding(
                        severity=severity,
                        message=msg,
                        details={
                            "observed_version": _format_version(version),
                            "reference_version": _format_version(reference),
                            "minor_drift": minor_drift,
                            "asset_count": count,
                            "asset_ids_sample": asset_ids,
                            "asset_ids_truncated": truncated,
                        },
                    ))

        # Unparseable bucket — single info finding.
        if unparseable_agents:
            sample_hosts = [
                a.get("hostName") for a in unparseable_agents[:10]
                if isinstance(a.get("hostName"), str)
            ]
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(unparseable_agents)} agent(s) reported an unparseable "
                    f"Insight Agent version string."
                ),
                details={
                    "agent_count": len(unparseable_agents),
                    "sample_host_names": sample_hosts,
                },
            ))

        # "No Agent" bucket — assets with no Insight Agent correlated.
        # Derived as total_asset_count - len(agent_asset_ids). Counts every
        # asset including scan-only assets that may never have been intended
        # for agent install — labelled accordingly so the meaning is clear.
        try:
            total_assets = snapshot.total_asset_count()
        except Exception:
            total_assets = 0
        try:
            with_agent_ids = snapshot.agent_asset_ids()
        except Exception:
            with_agent_ids = set()
        with_agent = len(with_agent_ids)
        without_agent = max(0, total_assets - with_agent)
        if without_agent > 0:
            findings.append(Finding(
                severity="info",
                message=(
                    f"{without_agent} asset(s) have no Insight Agent installed "
                    f"(of {total_assets} total assets)."
                ),
                details={
                    "asset_count": without_agent,
                    "total_assets": total_assets,
                    "assets_with_agent": with_agent,
                },
            ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        summary: dict = {
            "agents_total": total,
            "agents_examined": agents_examined,
            "agents_unparseable": len(unparseable_agents),
            "agents_drifted": drifted_assets,
            "versions_observed": len(version_buckets),
            "versions_drifted": versions_drifted,
            "reference_version": _format_version(reference),
            "reference_mode": mode,
            "assets_total": total_assets,
            "assets_with_agent": with_agent,
            "assets_without_agent": without_agent,
        }
        if mode == "pinned":
            summary["agents_ahead_of_pin"] = ahead_of_pin_assets
        else:
            summary["drift_threshold"] = drift_threshold

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary=summary,
            sources=list(self.sources),
        )
