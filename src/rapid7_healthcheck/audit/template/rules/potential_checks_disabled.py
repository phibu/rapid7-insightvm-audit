from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class PotentialChecksDisabledRule(AuditRule):
    rule_id = "template.potential_checks_disabled"
    rule_name = "Potential Vulnerability Checks Disabled"
    description = (
        "Vulnerability-enabled templates with `checks.potential` explicitly set "
        "to false. Potential checks fill the gap when authenticated information "
        "is missing or version banners are ambiguous — disabling them hides "
        "roughly 30% of findings on a typical environment. Missing key means "
        "the platform default (enabled) applies and is not flagged."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        vuln_enabled = [t for t in templates if EnvSnapshot.template_vuln_enabled(t)]

        findings: list[Finding] = []
        for t in vuln_enabled:
            checks = t.get("checks") or {}
            if checks.get("potential") is False:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has potential vulnerability "
                        f"checks disabled — hides roughly 30% of findings."
                    ),
                    details={
                        "template_id": t.get("id"),
                        "template_name": t.get("name"),
                    },
                ))

        failed = len(findings)
        examined = len(vuln_enabled)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
            },
            examined=examined,
            failed=failed,
        )
