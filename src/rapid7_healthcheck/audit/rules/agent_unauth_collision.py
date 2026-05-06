from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding


@register
class AgentUnauthCollisionRule:
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that "
        "already have the Insight Agent installed. The agent produces strictly "
        "richer authenticated data; redundant unauth scans add load, cause "
        "asset-correlation drift, and (prior to console release 6.6.229) could "
        "degrade results. Detection is grounded in the authoritative agent "
        "inventory at /api/3/agents (one fetch, cached) — site-asset listings "
        "are intersected by asset id, which is reliably populated. In fast "
        "mode (`full_scan: false`), per-site enumeration is bounded by "
        "`audit.sample_size` and short-circuits on the first agent-managed "
        "asset; sites that exceed the cap without a match are listed in a "
        "single aggregate info finding so the gap is visible. Run with "
        "`full_scan: true` to remove the cap."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/release-notes/insightvm/20231129/",
        "https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/",
        "https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Prime the unavailable flag via agent_count() before checking it,
        # then branch: 404 -> existing skip path; oversize -> new skip path;
        # else -> existing main loop.
        total_agents = snapshot.agent_count()

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
                        "Skipped: /api/3/agents is unavailable on this console "
                        "(404). Cannot determine agent-managed assets without "
                        "the agent inventory endpoint. Verify agent/unauth "
                        "scan overlap manually in the Security Console."
                    ),
                    details={"agents_endpoint_unavailable": True},
                )],
                summary={
                    "sites_examined": 0,
                    "sites_flagged": 0,
                    "sites_truncated": 0,
                    "per_site_cap": None,
                    "agent_asset_ids": 0,
                },
                sources=list(self.sources),
            )

        max_agents = rule_config.get("max_agents", 50000)
        if total_agents > max_agents:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"Skipped: Insight Agent inventory ({total_agents} agents) "
                        f"exceeds the configured cap (max_agents = {max_agents}) "
                        f"under audit.rules.agent_unauth_collision.knobs. Full "
                        f"pagination of /api/3/agents at this scale is too slow "
                        f"for a health-check pass. Raise the cap (set to 0 to "
                        f"disable the ceiling) or audit agent/unauth scan "
                        f"overlap manually in the Security Console."
                    ),
                    details={
                        "agent_count": total_agents,
                        "max_agents_cap": max_agents,
                        "inventory_oversize": True,
                    },
                )],
                summary={
                    "sites_examined": 0,
                    "sites_flagged": 0,
                    "sites_truncated": 0,
                    "per_site_cap": None,
                    "agent_asset_ids": 0,
                    "agent_count": total_agents,
                    "max_agents_cap": max_agents,
                },
                sources=list(self.sources),
            )

        agent_ids = snapshot.agent_asset_ids()

        per_site_cap = None if full_scan else sample_size

        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        truncated_sites: list[dict] = []  # {site_id, name, total_assets}

        for site in snapshot.sites():
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            if _site_has_credentials(snapshot, sid):
                continue

            sites_examined += 1
            total_assets = snapshot.site_asset_count(sid)

            examined = 0
            agent_found = False
            for asset in snapshot.iter_site_assets(sid):
                examined += 1
                asset_id = asset.get("id")
                if (
                    isinstance(asset_id, int)
                    and not isinstance(asset_id, bool)
                    and asset_id in agent_ids
                ):
                    agent_found = True
                    break
                if per_site_cap is not None and examined >= per_site_cap:
                    break

            if agent_found:
                sites_flagged += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' runs unauthenticated vuln scans, and at "
                        f"least 1 of {examined} sampled assets is Insight "
                        f"Agent-managed (total site assets: {total_assets}). "
                        f"Stop unauth scanning where the agent already covers "
                        f"the host."
                    ),
                    details={
                        "site_id": sid,
                        "scan_template_id": tpl_id,
                        "examined": examined,
                        "total_assets": total_assets,
                        "sampled": per_site_cap is not None and examined >= 1 and total_assets > examined,
                        "short_circuited": True,
                    },
                ))
            elif per_site_cap is not None and examined >= per_site_cap and total_assets > examined:
                truncated_sites.append({
                    "site_id": sid,
                    "name": name,
                    "total_assets": total_assets,
                })

        if truncated_sites:
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(truncated_sites)} sites exceeded the per-site sample "
                    f"cap ({per_site_cap} assets) without finding an Insight "
                    f"Agent — verify in the Security Console UI: "
                    f"{', '.join(s['name'] for s in truncated_sites[:20])}."
                ),
                details={
                    "truncated_site_count": len(truncated_sites),
                    "cap": per_site_cap,
                    "truncated_sites": truncated_sites[:20],
                },
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
                "sites_examined": sites_examined,
                "sites_flagged": sites_flagged,
                "sites_truncated": len(truncated_sites),
                "per_site_cap": per_site_cap,
                "agent_asset_ids": len(agent_ids),
            },
            sources=list(self.sources),
        )
