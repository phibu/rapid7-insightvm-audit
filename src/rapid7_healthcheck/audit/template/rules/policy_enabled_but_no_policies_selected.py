from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class PolicyEnabledButNoPoliciesSelectedRule:
    rule_id = "template.policy_enabled_but_no_policies_selected"
    rule_name = "Policy Engine Enabled With No Policies Selected"
    description = (
        "Templates with `policyEnabled: true` but an empty `policy.enabled` "
        "list (or no `policy` block at all). The policy engine runs and "
        "produces no policy findings — the same silent-coverage-gap shape as "
        "vuln-enabled-with-no-checks but for the policy vertical."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        policy_enabled = [t for t in templates if t.get("policyEnabled")]

        findings: list[Finding] = []
        for t in policy_enabled:
            policy = t.get("policy") or {}
            enabled_list = policy.get("enabled") or []
            if len(enabled_list) == 0:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has the policy engine "
                        f"enabled but no policies selected — the scan will "
                        f"produce no policy findings."
                    ),
                    details={
                        "template_id": t.get("id"),
                        "template_name": t.get("name"),
                    },
                ))

        failed = len(findings)
        examined = len(policy_enabled)

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
