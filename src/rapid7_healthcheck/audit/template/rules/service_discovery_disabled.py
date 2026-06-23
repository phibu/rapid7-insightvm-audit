from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


def _tcp_ports(template: dict) -> list:
    return ((template.get("discovery") or {}).get("asset") or {}).get("tcpPorts") or []


def _udp_ports(template: dict) -> list:
    return ((template.get("discovery") or {}).get("asset") or {}).get("udpPorts") or []


@register_template_rule
class ServiceDiscoveryDisabledRule(AuditRule):
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
