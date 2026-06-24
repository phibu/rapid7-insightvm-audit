from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding

# Service-discovery `ports` values that mean "scan nothing". Rapid7 emits the
# port set as a string: "well-known" (default), "all", "none", or an explicit
# list/range (e.g. "1-1040,8080"). Only "none" / empty disables the protocol.
_EMPTY_PORTS = {"", "none"}


def _service(template: dict) -> dict:
    return ((template.get("discovery") or {}).get("service") or {})


def _protocol_scans_nothing(proto: dict | None) -> bool:
    """True when a service-discovery protocol (tcp/udp) is *explicitly* set to
    scan no ports.

    A protocol scans nothing only when it carries an explicit ``ports`` key
    whose value is empty/``"none"`` AND has no ``additionalPorts`` to
    compensate. ``"well-known"`` / ``"all"`` / any explicit list means it
    scans.

    A protocol with **no** ``ports`` key (absent block, or block present but
    ``ports`` omitted) returns ``False`` — Rapid7 applies the ``"well-known"``
    default server-side, so an unset value means default scanning, not
    disabled. Flagging the absent case would reintroduce the #31 false
    positive (ADR-0001 skip-absent norm: only flag absent when the API
    default is itself dangerous; ``"well-known"`` is benign).
    """
    proto = proto or {}
    if "ports" not in proto:
        return False
    ports = str(proto.get("ports") or "").strip().lower()
    additional = str(proto.get("additionalPorts") or "").strip()
    return ports in _EMPTY_PORTS and not additional


@register_template_rule
class ServiceDiscoveryDisabledRule(AuditRule):
    rule_id = "template.service_discovery_disabled"
    rule_name = "Vulnerability Template With Service Discovery Disabled"
    description = (
        "Vulnerability-enabled scan templates where BOTH TCP and UDP service "
        "discovery scan no ports — the scanner cannot identify listening "
        "services and most service-bound vulnerability checks degrade or are "
        "skipped, silently reducing coverage even when checks are enabled. "
        "Service discovery defaults to the 'well-known' port set, so this is "
        "rare and indicates a deliberately blanked port configuration. Asset "
        "discovery (host-liveness packets) is a separate phase and is NOT "
        "examined here — its being off is a valid configuration."
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
            service = _service(t)
            tcp_dead = _protocol_scans_nothing(service.get("tcp"))
            udp_dead = _protocol_scans_nothing(service.get("udp"))
            # Flag only when service discovery is dead on BOTH protocols: if
            # either scans ports, the scanner still discovers services.
            if not (tcp_dead and udp_dead):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has vulnerability scanning "
                    f"enabled but both TCP and UDP service discovery scan no "
                    f"ports — service-bound checks will degrade or be skipped."
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
