from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
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
class TelnetRegexUnsetRule:
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
        examined = len(templates)

        findings: list[Finding] = []
        for t in templates:
            telnet = _telnet_block(t)
            if telnet is None:
                # No telnet block — not applicable, skip silently.
                continue
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
