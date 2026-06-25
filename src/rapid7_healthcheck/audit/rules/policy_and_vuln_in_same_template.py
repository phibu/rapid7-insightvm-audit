from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding


@register
class PolicyAndVulnInSameTemplateRule(AuditRule):
    rule_id = "policy_and_vuln_in_same_template"
    rule_name = "Policy and Vulnerability in Same Template"
    description = (
        "Scan templates with both Policy checks and Vulnerability checks enabled. "
        "Rapid7 recommends separating these into distinct templates."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        in_use: dict[str, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            tpl_id = snapshot.site_scan_template_id(site)
            if tpl_id:
                in_use[tpl_id].append(site["id"])

        findings: list[Finding] = []
        for tpl_id, site_ids in in_use.items():
            tpl = snapshot.scan_template(tpl_id)
            policy_on = bool(tpl.get("policyEnabled"))
            vuln_on = snapshot.template_vuln_enabled(tpl)
            if policy_on and vuln_on:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{tpl.get('name', tpl_id)}' has both Policy and Vulnerability "
                        f"checks enabled -- Rapid7 recommends separate templates"
                    ),
                    details={"template_id": tpl_id, "sites_using": site_ids},
                ))

        return self.result(
            findings,
            severity=severity,
            summary={"templates_examined": len(in_use), "templates_flagged": len(findings)},
            examined=len(in_use),
            failed=len(findings),
        )
