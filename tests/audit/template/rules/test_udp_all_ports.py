from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.udp_all_ports import UdpAllPortsRule


def _udp(template, ports):
    template.setdefault("discovery", {}).setdefault("service", {}).setdefault(
        "udp", {})["ports"] = ports
    return template


def test_flags_all(fake_snapshot):
    fake_snapshot.set_templates_full([
        _udp({"id": "t1", "name": "AllUdp", "vulnerabilityEnabled": True}, "all"),
    ])
    r = UdpAllPortsRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_well_known_not_flagged(fake_snapshot):
    fake_snapshot.set_templates_full([
        _udp({"id": "t2", "name": "WK", "vulnerabilityEnabled": True}, "well-known"),
    ])
    r = UdpAllPortsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_absent_skipped_default_well_known(fake_snapshot):
    """No udp.ports field → API default `well-known` → compliant, skip-absent."""
    fake_snapshot.set_templates_full([
        {"id": "t3", "name": "NoUdpField", "vulnerabilityEnabled": True},
    ])
    r = UdpAllPortsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_policy_only_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        _udp({"id": "t4", "name": "Policy", "policyEnabled": True,
              "vulnerabilityEnabled": False}, "all"),
    ])
    r = UdpAllPortsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0
