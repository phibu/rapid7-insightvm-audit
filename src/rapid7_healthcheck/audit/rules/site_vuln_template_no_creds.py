from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


def _site_has_credentials(snapshot, site_id: int) -> bool:
    site_creds = snapshot.site_credentials(site_id)
    if any(c.get("enabled", False) for c in site_creds):
        return True
    for shared in snapshot.shared_credentials():
        if not shared.get("enabled", False):
            continue
        sites_restriction = shared.get("sites")
        if sites_restriction is None:
            return True
        if site_id in sites_restriction:
            return True
    return False


@register
class SiteVulnTemplateNoCredsRule:
    rule_id = "site_vuln_template_no_creds"
    rule_name = "Vulnerability Template Without Credentials"
    description = (
        "Sites whose scan template has Vulnerability checks enabled but have no enabled "
        "credentials configured. Without credentials, vuln scans fall back to remote checks "
        "only and silently degrade risk-score accuracy."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
        "https://docs.rapid7.com/insightvm/configuring-scan-credentials/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        for site in snapshot.sites():
            sites_examined += 1
            site_id = site.get("id")
            site_name = site.get("name", f"id={site_id}")
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            if snapshot.site_asset_count(site_id) <= 0:
                continue
            if _site_has_credentials(snapshot, site_id):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{site_name}' uses vuln-check template '{tpl.get('name', tpl_id)}' "
                    f"but has no enabled credentials"
                ),
                details={"site_id": site_id, "template_id": tpl_id, "template_name": tpl.get("name")},
            ))
            sites_flagged += 1

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
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sources=list(self.sources),
        )
