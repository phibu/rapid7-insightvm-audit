from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.service_discovery_disabled import (
    ServiceDiscoveryDisabledRule,
)


def test_flags_vuln_enabled_with_empty_ports(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "NoPorts",
            "vulnerabilityEnabled": True,
            "discovery": {"asset": {"tcpPorts": [], "udpPorts": []}},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "t1"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_no_finding_when_tcpPorts_populated(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t2",
            "name": "WithTCP",
            "vulnerabilityEnabled": True,
            "discovery": {"asset": {"tcpPorts": [22, 80, 443], "udpPorts": []}},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_no_finding_when_udpPorts_populated(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t3",
            "name": "WithUDP",
            "vulnerabilityEnabled": True,
            "discovery": {"asset": {"tcpPorts": [], "udpPorts": [53, 161]}},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_vuln_disabled_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t4",
            "name": "VulnDisabled",
            "vulnerabilityEnabled": False,
            "discovery": {"asset": {"tcpPorts": [], "udpPorts": []}},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_old_shape_vuln_enabled_is_examined(fake_snapshot):
    """Old-shape consoles expose vuln enabled at vulnerabilityChecks.enabled."""
    fake_snapshot.set_templates_full([
        {
            "id": "t5",
            "name": "OldShape",
            "vulnerabilityChecks": {"enabled": True},
            "discovery": {"asset": {}},
        },
    ])
    r = ServiceDiscoveryDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}
