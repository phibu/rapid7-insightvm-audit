from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.template.rules._applicability import performs_discovery
from rapid7_healthcheck.checks import Finding


def _udp_ports_mode(template: dict):
    return (
        ((template.get("discovery") or {}).get("service") or {}).get("udp") or {}
    ).get("ports")


@register_template_rule
class UdpAllPortsRule(AuditRule):
    rule_id = "template.udp_all_ports"
    rule_name = "UDP Service Discovery Set To All Ports"
    description = (
        "Discovery-active templates whose UDP service discovery is set to "
        "`all` (`discovery.service.udp.ports == \"all\"`). Rapid7 explicitly "
        "warns never to scan all 65,535 UDP ports — UDP scan duration can "
        "exceed a month. The API default is `well-known`; templates without "
        "the field set use that default and are not examined (skip-absent)."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Examined = discovery-active templates that explicitly set udp.ports.
        # Absent field → default well-known → not applicable.
        applicable = [
            t for t in snapshot.templates_full()
            if performs_discovery(t) and _udp_ports_mode(t) is not None
        ]

        findings: list[Finding] = []
        for t in applicable:
            if _udp_ports_mode(t) != "all":
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' scans all UDP ports "
                    f"(udp.ports = 'all') — UDP scans of all 65,535 ports can "
                    f"run for weeks. Rapid7 recommends 'well-known'."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "udp_ports": "all",
                },
            ))

        failed = len(findings)
        examined = len(applicable)

        return self.result(
            findings,
            severity=severity,
            summary={"templates_examined": examined, "templates_flagged": failed},
            examined=examined,
            failed=failed,
        )
