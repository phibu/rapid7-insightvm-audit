from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding

_DEFAULT_AGENT_SITE_NAME = "Rapid7 Insight Agents"


@register
class AgentUnauthCollisionRule(AuditRule):
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that "
        "already have the Insight Agent installed. The agent produces strictly "
        "richer authenticated data; redundant unauth scans add load and cause "
        "asset-correlation drift. Detection is server-side and exact: for each "
        "candidate site (vulnerability-enabled scan template, no site "
        "credentials) one /api/3/assets/search query counts the assets shared "
        "with the Insight Agent site (resolved by name; its id varies per "
        "console). The exact overlap count comes from the result metadata -- no "
        "asset bodies fetched, no sampling, and the rule always runs (no agent-"
        "fleet-size ceiling). 'Has an Insight Agent' means membership in the "
        "agent site (the only agent signal expressible in a server-side query)."
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
        agent_site_name = (rule_config or {}).get("agent_site_name", _DEFAULT_AGENT_SITE_NAME)
        agent_site_id = snapshot.agent_site_id_by_name(agent_site_name)

        if agent_site_id is None:
            return self.result(
                [Finding(
                    severity="info",
                    message=(
                        f"No site named '{agent_site_name}' was found -- no Insight "
                        f"Agent site to compare against. (Set "
                        f"audit.rules.agent_unauth_collision.agent_site_name if your "
                        f"agent site is named differently.)"
                    ),
                    details={"agent_site_name": agent_site_name},
                )],
                severity=severity,
                summary={
                    "candidates_examined": 0,
                    "candidates_flagged": 0,
                    "candidates_failed": 0,
                    "agent_site_id": None,
                },
                examined=0,
                failed=0,
            )

        # Build candidate sites: vuln-enabled template, NOT the agent site.
        # Compute the template-eligible set first (template reads are cached
        # per distinct id), then prefetch those sites' credentials in one
        # concurrent fan-out before the per-site no-credentials test.
        template_eligible: list[dict] = []
        for site in snapshot.sites():
            sid = site.get("id")
            if sid is None or sid == agent_site_id:
                continue
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            template_eligible.append(site)

        snapshot.prefetch_site_credentials(
            [s["id"] for s in template_eligible if s.get("id") is not None]
        )

        candidate_sites: list[dict] = []
        for site in template_eligible:
            sid = site["id"]
            if _site_has_credentials(snapshot, sid):
                continue
            candidate_sites.append(site)

        candidate_ids = [s["id"] for s in candidate_sites]
        overlaps, failed_ids = snapshot.candidate_agent_overlaps(candidate_ids, agent_site_id)

        name_by_id = {s["id"]: s.get("name", f"id={s['id']}") for s in candidate_sites}
        tpl_by_id = {s["id"]: snapshot.site_scan_template_id(s) for s in candidate_sites}

        findings: list[Finding] = []
        flagged = 0
        for cid, count in sorted(overlaps.items()):
            if count <= 0:
                continue
            flagged += 1
            name = name_by_id.get(cid, f"id={cid}")
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{name}' runs unauthenticated vulnerability scans, and "
                    f"{count} of its assets are also in the Insight Agent site "
                    f"('{agent_site_name}') -- the agent already provides "
                    f"authenticated coverage. Stop unauth scanning where the agent "
                    f"covers the host."
                ),
                details={
                    "site_id": cid,
                    "scan_template_id": tpl_by_id.get(cid),
                    "overlap_count": count,
                    "agent_site_id": agent_site_id,
                },
            ))

        if failed_ids:
            names = ", ".join(name_by_id.get(cid, f"id={cid}") for cid in sorted(failed_ids)[:20])
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(failed_ids)} candidate site(s) could not be checked "
                    f"(agent-overlap query failed -- transient API error): {names}."
                ),
                details={"failed_site_ids": sorted(failed_ids)[:20], "failed_count": len(failed_ids)},
            ))

        if flagged == 0 and not failed_ids:
            findings.append(Finding(
                severity="info",
                message=(
                    f"No unauthenticated site overlaps the Insight Agent site "
                    f"('{agent_site_name}'): every candidate site's assets are "
                    f"either absent from the agent site or already credentialed."
                ),
                details={"agent_site_id": agent_site_id, "candidates_examined": len(candidate_ids)},
            ))

        return self.result(
            findings,
            severity=severity,
            summary={
                "candidates_examined": len(candidate_ids),
                "candidates_flagged": flagged,
                "candidates_failed": len(failed_ids),
                "agent_site_id": agent_site_id,
            },
            examined=len(candidate_ids),
            # card-summary `failed` is the count of problems found (flagged
            # candidates), the card convention -- distinct from
            # summary["candidates_failed"], which counts candidates whose
            # overlap query *errored* and were skip-disclosed, not flagged.
            failed=flagged,
        )
