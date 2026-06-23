from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class WindowsServicesDisabledRule:
    rule_id = "template.windows_services_disabled"
    rule_name = "Windows Services Not Enabled During Scan"
    description = (
        "Vulnerability-enabled templates where `enableWindowsServices` is "
        "false or absent (the API/UI default is unchecked/false). When an "
        "organization blocks remote registry access, this option lets the "
        "scan temporarily enable Windows services to complete a remote-"
        "registry scan — Rapid7 recommends enabling it for Windows assets. "
        "This rule is INFO and UNSCOPED: it cannot tell from the template "
        "alone whether the bound sites contain Windows assets, so it flags "
        "every vuln-enabled template with the setting off and asks the "
        "operator to verify. A future revision will scope this to templates "
        "bound to sites with Windows (CIFS/SMB) credentials and raise "
        "severity to warn (see backlog)."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Gate: vuln-enabled only. enableWindowsServices affects remote-registry
        # checks during vulnerability assessment; a discovery-only template has
        # no vuln checks, so the setting is inert there.
        vuln_enabled = [
            t for t in snapshot.templates_full()
            if EnvSnapshot.template_vuln_enabled(t)
        ]

        findings: list[Finding] = []
        for t in vuln_enabled:
            value = t.get("enableWindowsServices")
            if value is True:
                continue  # compliant
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' does not enable Windows "
                    f"services during scans"
                    + ("" if value is False else " (field absent, default is off)")
                    + " — if this template scans Windows assets behind blocked "
                    "remote-registry, authenticated checks may be bypassed. "
                    "Verify the bound sites are non-Windows or enable it."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "enable_windows_services": (
                        False if value is False else "absent (defaults to false)"
                    ),
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
            summary={"templates_examined": examined, "templates_flagged": failed},
            card_summary={
                "examined": examined,
                "passed": max(0, examined - failed),
                "failed": failed,
            },
            sources=list(self.sources),
        )
