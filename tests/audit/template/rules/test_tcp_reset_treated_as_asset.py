from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.tcp_reset_treated_as_asset import (
    TcpResetTreatedAsAssetRule,
)


def _asset(template, **kw):
    template.setdefault("discovery", {}).setdefault("asset", {}).update(kw)
    return template


def test_flags_explicit_true(fake_snapshot):
    fake_snapshot.set_templates_full([
        _asset({"id": "t1", "name": "Vuln", "vulnerabilityEnabled": True},
               treatTcpResetAsAsset=True),
    ])
    r = TcpResetTreatedAsAssetRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_flags_absent_default_is_true(fake_snapshot):
    """ADR-0001: the API default is `true` (the dangerous value), so an absent
    field is non-compliant and must be flagged — unlike every other discovery
    rule which skips-absent."""
    fake_snapshot.set_templates_full([
        {"id": "t2", "name": "Untouched", "vulnerabilityEnabled": True},
    ])
    r = TcpResetTreatedAsAssetRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["treat_tcp_reset_as_asset"] == "absent (defaults to true)"


def test_explicit_false_is_compliant(fake_snapshot):
    fake_snapshot.set_templates_full([
        _asset({"id": "t3", "name": "Good", "vulnerabilityEnabled": True},
               treatTcpResetAsAsset=False),
    ])
    r = TcpResetTreatedAsAssetRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_discovery_only_template_examined(fake_snapshot):
    """Discovery-only templates are the purest discovery case — they MUST be
    examined even though they are not vuln-enabled."""
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "DiscoOnly", "discoveryOnly": True},
    ])
    r = TcpResetTreatedAsAssetRule().run(fake_snapshot, "warn", False, 500, {})
    assert len(r.findings) == 1


def test_policy_only_template_not_examined(fake_snapshot):
    """A policy-only template performs no discovery — its discovery settings
    are inert and must not be examined or flagged."""
    fake_snapshot.set_templates_full([
        {"id": "t5", "name": "PolicyOnly", "policyEnabled": True,
         "vulnerabilityEnabled": False, "discoveryOnly": False},
    ])
    r = TcpResetTreatedAsAssetRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
