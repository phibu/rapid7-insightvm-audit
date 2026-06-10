from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class UnsafeChecksDisabledRule:
    rule_id = "template.unsafe_checks_disabled"
    rule_name = "Unsafe Vulnerability Checks Disabled"
    description = (
        "Vulnerability-enabled templates with `checks.unsafe` explicitly set "
        "to false. Unsafe checks (denial-of-service probes, crash-the-service "
        "exploits) are disabled by default for production safety — this rule "
        "is awareness-only and emits info findings so the operator knows "
        "which templates skip the unsafe class. Per the project convention, "
        "info findings do not escalate check status."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        vuln_enabled = [t for t in templates if t.get("vulnerabilityEnabled")]

        findings: list[Finding] = []
        for t in vuln_enabled:
            checks = t.get("checks") or {}
            if checks.get("unsafe") is False:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has unsafe vulnerability "
                        f"checks disabled (informational — this is often "
                        f"intentional for production safety)."
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
