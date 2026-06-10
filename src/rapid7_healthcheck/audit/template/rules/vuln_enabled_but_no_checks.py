from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


def _enabled_types(template: dict) -> list:
    checks = template.get("checks") or {}
    types = checks.get("types") or {}
    return types.get("enabled") or []


def _enabled_categories(template: dict) -> list:
    checks = template.get("checks") or {}
    cats = checks.get("categories") or {}
    return cats.get("enabled") or []


@register_template_rule
class VulnEnabledButNoChecksRule:
    rule_id = "template.vuln_enabled_but_no_checks"
    rule_name = "Vulnerability Scan Enabled With No Checks Selected"
    description = (
        "Scan templates with vulnerability assessment enabled but no check "
        "types or check categories selected. The scan will run and produce "
        "no vulnerability findings — a silent coverage gap that looks like "
        "a clean environment in the report."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        vuln_enabled = [t for t in templates if EnvSnapshot.template_vuln_enabled(t)]

        findings: list[Finding] = []
        for t in vuln_enabled:
            if _enabled_types(t) or _enabled_categories(t):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has vulnerability scanning enabled "
                    f"but no check types or categories selected — the scan will "
                    f"produce no vulnerability findings."
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
