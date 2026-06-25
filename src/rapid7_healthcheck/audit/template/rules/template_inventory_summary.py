from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import Finding


@register_template_rule
class TemplateInventorySummaryRule(AuditRule):
    rule_id = "template.template_inventory_summary"
    rule_name = "Template Inventory Summary"
    description = (
        "Informational inventory of scan templates on the Security Console: "
        "total count plus a breakdown by vulnerability-enabled, "
        "policy-enabled, and discovery-only. Emits no findings -- this rule "
        "is context for the rest of the Template Configuration Audit and "
        "always passes."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()
        total = len(templates)
        vuln_enabled = sum(1 for t in templates if EnvSnapshot.template_vuln_enabled(t))
        policy_enabled = sum(1 for t in templates if t.get("policyEnabled"))
        discovery_only = sum(1 for t in templates if t.get("discoveryOnly"))

        findings: list[Finding] = []

        return self.result(
            findings,
            severity=severity,
            summary={
                "total": total,
                "vuln_enabled": vuln_enabled,
                "policy_enabled": policy_enabled,
                "discovery_only": discovery_only,
            },
            examined=total,
            failed=0,
        )
