from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.template.rules._applicability import performs_discovery
from rapid7_healthcheck.checks import Finding


def _tcp_reset_value(template: dict):
    return ((template.get("discovery") or {}).get("asset") or {}).get(
        "treatTcpResetAsAsset"
    )


@register_template_rule
class TcpResetTreatedAsAssetRule:
    rule_id = "template.tcp_reset_treated_as_asset"
    rule_name = "TCP Reset Responses Treated As Live Assets"
    description = (
        "Discovery-active templates where `discovery.asset.treatTcpResetAsAsset` "
        "is true OR absent. The v3 API defaults this field to `true`, and "
        "firewalls/IDS devices commonly send TCP resets for non-existent hosts "
        "— treating those resets as live floods the console with tens of "
        "thousands of ghost assets (no hostname, no OS). Rapid7 highly "
        "recommends disabling it for nearly all environments. Because the "
        "dangerous value is the API default, this rule flags the absent case "
        "too (unlike the other discovery rules, which skip-absent) — see "
        "docs/adr/0001-tcp-reset-rule-flags-absent.md."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        applicable = [t for t in snapshot.templates_full() if performs_discovery(t)]

        findings: list[Finding] = []
        for t in applicable:
            value = _tcp_reset_value(t)
            if value is False:
                continue  # explicit opt-out — compliant
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' "
                    + ("treats TCP reset responses as live assets"
                       if value is True else
                       "does not disable treating TCP reset responses as live "
                       "assets (API default is true)")
                    + " — risks flooding the console with ghost assets."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "treat_tcp_reset_as_asset": (
                        True if value is True else "absent (defaults to true)"
                    ),
                },
            ))

        failed = len(findings)
        examined = len(applicable)

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
