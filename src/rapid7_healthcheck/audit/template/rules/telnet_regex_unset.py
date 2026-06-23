from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


_TELNET_FIELDS = (
    "loginRegex",
    "passwordPromptRegex",
    "failedLoginRegex",
    "questionableLoginRegex",
)


def _telnet_block(template: dict) -> dict | None:
    t = template.get("telnet")
    return t if isinstance(t, dict) else None


@register_template_rule
class TelnetRegexUnsetRule(AuditRule):
    rule_id = "template.telnet_regex_unset"
    rule_name = "Telnet Regex Fields All Unset"
    description = (
        "Templates with a `telnet` configuration block but all four telnet "
        "prompt-matching regex fields empty (loginRegex, passwordPromptRegex, "
        "failedLoginRegex, questionableLoginRegex). Cosmetic — telnet auth is "
        "rare today — but signals an untuned template. Templates with no "
        "telnet block at all are skipped (the field set is not applicable)."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()
        # Examined = templates that actually have a telnet block. Templates
        # without a telnet block are not applicable to this rule and counting
        # them would inflate the "passed" denominator with irrelevant
        # population. Same pattern as 0.7.0's sites_overdue_scans fix.
        templates_with_telnet = [t for t in templates if _telnet_block(t) is not None]
        examined = len(templates_with_telnet)

        findings: list[Finding] = []
        for t in templates_with_telnet:
            telnet = _telnet_block(t)
            if any(telnet.get(f) or "" for f in _TELNET_FIELDS):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has a telnet configuration "
                    f"block but all four telnet regex fields are empty."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                },
            ))

        failed = len(findings)

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
