from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding


def _has_agent_history(history) -> bool:
    if not isinstance(history, list):
        return False
    return any((h.get("type") or "").upper() == "AGENT-IMPORT" for h in history)


def _asset_is_agent_managed(snapshot, asset: dict) -> bool:
    """Combine the cheap signal with the inline-history fallback."""
    cheap = snapshot.asset_has_agent(asset)
    if cheap is True:
        return True
    if cheap is False:
        return False
    return _has_agent_history(asset.get("history"))


@register
class AgentUnauthCollisionRule:
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that "
        "already have the Insight Agent installed. The agent produces strictly "
        "richer authenticated data; redundant unauth scans add load, cause "
        "asset-correlation drift, and (prior to console release 6.6.229) could "
        "degrade results. In fast mode (`full_scan: false`), per-site asset "
        "enumeration is bounded by `audit.sample_size` and short-circuits on "
        "the first agent-managed asset found. Sites that exceed the per-site "
        "cap without a match are listed in a single aggregate info finding so "
        "the gap is visible. Run with `full_scan: true` to remove the cap."
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
                if _asset_is_agent_managed(snapshot, asset):
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
            },
            sources=list(self.sources),
        )
