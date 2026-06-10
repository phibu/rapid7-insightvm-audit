from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class PotentialChecksDisabledRule:
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
                "templates_examined": examined,
                "templates_flagged": failed,
            },
            card_summary={
                "examined": examined,
                "passed": max(0, examined - failed),
                "failed": failed,
            },
            sources=list(self.sources),
        )
