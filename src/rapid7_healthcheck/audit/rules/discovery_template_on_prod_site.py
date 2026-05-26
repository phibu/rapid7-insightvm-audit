from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_PROD_IMPORTANCE = {"normal", "high", "very_high"}
_MIN_ASSETS = 10


@register
class DiscoveryTemplateOnProdSiteRule:
    rule_id = "discovery_template_on_prod_site"
    rule_name = "Discovery Template on Production Site"
    description = (
        "Sites with normal+ importance and >10 assets that use a Discovery-only template. "
        "Heuristic: the site looks like it should be running vulnerability assessment but isn't."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        sites_examined = 0
        for site in snapshot.sites():
            site_id = site.get("id")
            importance = site.get("importance", "normal")
            if importance not in _PROD_IMPORTANCE:
                continue
            if snapshot.site_asset_count(site_id) <= _MIN_ASSETS:
                continue
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            sites_examined += 1
            tpl = snapshot.scan_template(tpl_id)
            if snapshot.template_vuln_enabled(tpl):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{site.get('name', site_id)}' (importance: {importance}, "
                    f"{snapshot.site_asset_count(site_id)} assets) uses Discovery-only template "
                    f"'{tpl.get('name', tpl_id)}' — no vulnerabilities will be reported"
                ),
                details={"site_id": site_id, "template_id": tpl_id,
                         "importance": importance,
                         "asset_count": snapshot.site_asset_count(site_id)},
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
            summary={"sites_flagged": len(findings)},
            card_summary={
                "examined": sites_examined,
                "passed": max(0, sites_examined - len(findings)),
                "failed": len(findings),
            },
            sources=list(self.sources),
        )
