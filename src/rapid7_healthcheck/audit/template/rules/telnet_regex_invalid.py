from __future__ import annotations

import re

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
class TelnetRegexInvalidRule(AuditRule):
    rule_id = "template.telnet_regex_invalid"
    rule_name = "Telnet Regex Fails To Compile"
    description = (
        "Templates where one or more telnet prompt-matching regex fields "
        "contain a value that fails Python re.compile(). At scan time the "
        "scanner will silently degrade and the telnet login flow will not "
        "match prompts -- producing no telnet findings without surfacing the "
        "regex error in the console UI."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        findings: list[Finding] = []
        examined = 0
        for t in templates:
            telnet = _telnet_block(t)
            if telnet is None:
                continue
            # Collect non-empty regex values keyed by field.
            non_empty: dict[str, str] = {}
            for f in _TELNET_FIELDS:
                v = telnet.get(f)
                if isinstance(v, str) and v:
                    non_empty[f] = v
            if not non_empty:
                continue
            examined += 1
            broken: list[dict] = []
            for field, pattern in non_empty.items():
                try:
                    re.compile(pattern)
                except re.error as e:
                    broken.append({"field": field, "pattern": pattern, "error": str(e)})
            if not broken:
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has {len(broken)} telnet "
                    f"regex field(s) that fail to compile -- scan-time telnet "
                    f"prompt matching will silently fail."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "invalid_regex_fields": broken,
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
