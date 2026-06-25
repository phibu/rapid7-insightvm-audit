from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class DisabledChecksInIndividualOverridesRule(AuditRule):
    rule_id = "template.disabled_checks_in_individual_overrides"
    rule_name = "Excessive Individually Disabled Checks"
    description = (
        "Templates with many individually disabled checks under "
        "`checks.individual.disabled`. A short list is normal (legitimate "
        "exceptions for false positives or known irrelevant checks); a long "
        "list is a drift signal -- operators have been silencing checks "
        "without re-evaluating, building up technical debt that hides real "
        "findings. The threshold is configurable via the "
        "`max_disabled_individual_checks` knob (default 20)."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        threshold = max(1, int(rule_config.get("max_disabled_individual_checks", 20)))

        templates = snapshot.templates_full()

        findings: list[Finding] = []
        for t in templates:
            checks = t.get("checks") or {}
            individual = checks.get("individual") or {}
            disabled = individual.get("disabled") or []
            count = len(disabled)
            if count > threshold:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{t.get('name')}' has {count} individually "
                        f"disabled checks (threshold {threshold}) -- review for "
                        f"silenced findings that should be re-evaluated."
                    ),
                    details={
                        "template_id": t.get("id"),
                        "template_name": t.get("name"),
                        "disabled_check_count": count,
                        "threshold": threshold,
                    },
                ))

        failed = len(findings)
        examined = len(templates)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
                "threshold": threshold,
            },
            examined=examined,
            failed=failed,
        )
