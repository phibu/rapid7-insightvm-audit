from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.service_discovery_disabled import (
    ServiceDiscoveryDisabledRule,
)


def test_issue_31_asset_discovery_off_but_service_discovery_configured_passes(fake_snapshot):
    """Issue #31: a template with Asset Discovery packets disabled but
    Service Discovery scanning ``well-known`` ports is fully functional —
    it must NOT be flagged. The old rule read ``discovery.asset.*`` (the
    wrong subtree) and false-flagged exactly this config.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "scada-audit",
            "name": "SCADA audit",
            "vulnerabilityEnabled": True,
            "discovery": {
                # Asset Discovery: "send TCP/UDP packets" disabled (empty arrays)
                "asset": {"tcpPorts": [], "udpPorts": []},
                # Service Discovery: scanning well-known ports — healthy
                "service": {
                    "tcp": {"ports": "well-known", "additionalPorts": "1-1040"},
                    "udp": {"ports": "well-known"},
                },
            },
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_flags_when_both_protocols_scan_no_ports(fake_snapshot):
    """The rule's real purpose: a vuln-enabled template whose service
    discovery is genuinely blanked on BOTH protocols (ports 'none', no
    additionalPorts) is flagged.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "blanked",
            "name": "Blanked Service Discovery",
            "vulnerabilityEnabled": True,
            "discovery": {
                "service": {
                    "tcp": {"ports": "none", "additionalPorts": ""},
                    "udp": {"ports": "none"},
                },
            },
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "blanked"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_tcp_alive_udp_dead_passes(fake_snapshot):
    """If only one protocol scans ports, the scanner still discovers
    services — not 'disabled'. Both must be dead to flag.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "tcp-only",
            "name": "TCP only",
            "vulnerabilityEnabled": True,
            "discovery": {
                "service": {
                    "tcp": {"ports": "well-known"},
                    "udp": {"ports": "none"},
                },
            },
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_additional_ports_rescues_empty_ports(fake_snapshot):
    """An explicit ``additionalPorts`` means the protocol still scans even
    when ``ports`` is empty/none.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "additional",
            "name": "Additional Ports",
            "vulnerabilityEnabled": True,
            "discovery": {
                "service": {
                    "tcp": {"ports": "none", "additionalPorts": "8080,9090"},
                    "udp": {"ports": "none", "additionalPorts": "161"},
                },
            },
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_vuln_disabled_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "disco-only",
            "name": "Discovery Only",
            "vulnerabilityEnabled": False,
            "discovery": {
                "service": {"tcp": {"ports": "none"}, "udp": {"ports": "none"}},
            },
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_missing_service_block_does_not_flag(fake_snapshot):
    """A vuln-enabled template with no service-discovery block in its JSON
    must NOT be flagged: Rapid7 applies the 'well-known' default server-side
    when the field is omitted, so an absent block means default (healthy)
    scanning, not disabled. Flagging it would reintroduce the #31 false
    positive and violate the category's skip-absent norm (ADR-0001 — only
    flag absent when the API default is itself dangerous; 'well-known' is
    benign).
    """
    fake_snapshot.set_templates_full([
        {
            "id": "no-service",
            "name": "No Service Block",
            "vulnerabilityEnabled": True,
            "discovery": {},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}
