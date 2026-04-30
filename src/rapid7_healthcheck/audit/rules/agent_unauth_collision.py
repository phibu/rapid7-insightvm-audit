from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding


def _has_agent_history(history: list[dict]) -> bool:
    return any((h.get("type") or "").upper() == "AGENT-IMPORT" for h in history)


@register
class AgentUnauthCollisionRule:
    # Performance note (0.2.2): originally this rule called snapshot.asset_history
    # for every asset in the per-site sample. At fleet scale (>100k assets across
    # many sites) that fans out to thousands of GET /api/3/assets/{id}/history
    # calls, exceeding the request_timeout_seconds * max_retries budget on slow
    # consoles. Now we prefer the agent-presence signal that the assets endpoint
    # already returns; asset_history is the fallback for assets whose record
    # doesn't carry that signal.
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that already have "
        "the Insight Agent installed. The agent produces strictly richer authenticated data; "
        "redundant unauth scans add load, cause asset-correlation drift, and (prior to console "
        "release 6.6.229) could degrade results."
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
        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        any_sampled = False
        site_samples: list[tuple[int, int]] = []

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
            assets, total = snapshot.asset_sample(sid)
            if total > len(assets):
                any_sampled = True
            site_samples.append((len(assets), total))

            agent_count = 0
            for asset in assets:
                cheap = snapshot.asset_has_agent(asset)
                if cheap is True:
                    agent_count += 1
                elif cheap is False:
                    continue
                else:
                    # Fallback for assets whose record didn't carry the signal.
                    if _has_agent_history(snapshot.asset_history(asset["id"])):
                        agent_count += 1

            if agent_count > 0:
                pct = (agent_count / max(len(assets), 1)) * 100
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' runs unauthenticated vuln scans, but {agent_count}/"
                        f"{len(assets)} sampled assets are Insight Agent-managed ({pct:.0f}%)"
                    ),
                    details={
                        "site_id": sid, "scan_template_id": tpl_id,
                        "agent_count": agent_count,
                        "sample_size": len(assets), "total_assets": total,
                    },
                ))
                sites_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        sample_info = None
        if any_sampled:
            total_assets_examined = sum(s for s, _ in site_samples)
            total_assets = sum(t for _, t in site_samples)
            sample_info = (
                f"checked {total_assets_examined} of {total_assets} assets "
                f"across {sites_examined} sites"
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sampled=any_sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
