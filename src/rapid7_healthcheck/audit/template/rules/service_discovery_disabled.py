from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


def _tcp_ports(template: dict) -> list:
    return ((template.get("discovery") or {}).get("asset") or {}).get("tcpPorts") or []


def _udp_ports(template: dict) -> list:
    return ((template.get("discovery") or {}).get("asset") or {}).get("udpPorts") or []


@register_template_rule
class ServiceDiscoveryDisabledRule:
    rule_id = "template.service_discovery_disabled"
    rule_name = "Vulnerability Template With Service Discovery Disabled"
    description = (
        "Vulnerability-enabled scan templates with no TCP or UDP service "
        "discovery ports configured. Without service discovery the scanner "
        "cannot identify listening services and most service-bound "
        "vulnerability checks degrade or are skipped — silently reducing "
        "coverage even when checks themselves are enabled."
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
            if _tcp_ports(t) or _udp_ports(t):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has vulnerability scanning "
                    f"enabled but no TCP or UDP discovery ports configured — "
                    f"service-bound checks will degrade or be skipped."
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
