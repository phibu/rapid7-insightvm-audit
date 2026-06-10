from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class CorrelateDisabledRule:
    rule_id = "template.correlate_disabled"
    rule_name = "Vulnerability Check Correlation Disabled"
    description = (
        "Vulnerability-enabled templates with `checks.correlate` explicitly "
        "set to false. Correlation deduplicates findings that match the same "
        "vulnerability via multiple signatures (CVE + product version + "
        "service banner); disabling it produces duplicate findings on the "
        "same vulnerability and inflates the report. Missing key means the "
        "platform default (enabled) applies and is not flagged."
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
            if checks.get("correlate") is False:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has vulnerability check "
                        f"correlation disabled — expect duplicate findings."
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
