from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


def _checks(template: dict) -> dict:
    return template.get("checks") or {}


def _list(checks: dict, group: str, key: str) -> list:
    return ((checks.get(group) or {}).get(key)) or []


def _has_no_check_configuration(template: dict) -> bool:
    """True when a template carries NO vulnerability-check configuration at all.

    Rapid7's inclusion model is *enable-minus-disable* (see the
    ``ScanTemplateVulnerabilityChecks`` schema): the effective check set is
    enabled categories/types, minus their disabled lists, plus
    ``individual.enabled``. Crucially the **baseline is unknown** from the
    template JSON — an empty ``categories.enabled`` does NOT mean "no
    categories"; the common pattern is "all on by default, a few disabled".

    So we cannot prove "this template produces zero findings". We can only
    prove the weaker "nobody configured any checks" — when EVERY enable/disable
    list is empty:

      - ``categories.enabled`` / ``categories.disabled``
      - ``types.enabled`` / ``types.disabled``
      - ``individual.enabled``

    A non-empty ``disabled`` list proves a non-empty baseline was being curated
    (you can't disable from nothing); ``individual.enabled`` adds coverage
    directly. ``individual.disabled`` is ignored (it can only remove, never
    add) and ``unsafe`` / ``potential`` are filters, not enablers.
    """
    checks = _checks(template)
    return not (
        _list(checks, "categories", "enabled")
        or _list(checks, "categories", "disabled")
        or _list(checks, "types", "enabled")
        or _list(checks, "types", "disabled")
        or _list(checks, "individual", "enabled")
    )


@register_template_rule
class VulnEnabledButNoChecksRule(AuditRule):
    rule_id = "template.vuln_enabled_but_no_checks"
    rule_name = "Vulnerability Scan Enabled With No Check Configuration"
    description = (
        "Scan templates with vulnerability assessment enabled but no check "
        "configuration present — every enable AND disable list (categories, "
        "types, individual) is empty. Such a template looks unconfigured: "
        "nobody selected or curated any checks. This is a warning, not a hard "
        "fail, because Rapid7's enable-minus-disable inclusion model means the "
        "true baseline of checks is not knowable from the template object — we "
        "can flag 'no check configuration present', not 'will produce no "
        "findings'."
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
            if not _has_no_check_configuration(t):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has vulnerability scanning "
                    f"enabled but no check configuration is present — no check "
                    f"categories, types, or individual checks are selected or "
                    f"curated."
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
