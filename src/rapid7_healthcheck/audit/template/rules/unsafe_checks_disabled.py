from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class UnsafeChecksDisabledRule(AuditRule):
    rule_id = "template.unsafe_checks_disabled"
    rule_name = "Unsafe Vulnerability Checks Disabled"
    description = (
        "Vulnerability-enabled templates with `checks.unsafe` explicitly set "
        "to false. Unsafe checks (denial-of-service probes, crash-the-service "
        "exploits) are disabled by default for production safety -- this rule "
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

        vuln_enabled = [t for t in templates if EnvSnapshot.template_vuln_enabled(t)]

        findings: list[Finding] = []
        for t in vuln_enabled:
            checks = t.get("checks") or {}
            if checks.get("unsafe") is False:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has unsafe vulnerability "
                        f"checks disabled (informational -- this is often "
                        f"intentional for production safety)."
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
