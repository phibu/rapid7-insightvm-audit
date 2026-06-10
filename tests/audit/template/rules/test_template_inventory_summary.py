from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.template_inventory_summary import (
    TemplateInventorySummaryRule,
)


def test_summary_counts_split_across_categories(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Vuln", "vulnerabilityEnabled": True},
        {"id": "t2", "name": "VulnNested",
         "vulnerabilityChecks": {"enabled": True}},
        {"id": "t3", "name": "PolicyOnly",
         "vulnerabilityEnabled": False, "policyEnabled": True},
        {"id": "t4", "name": "Discovery",
         "vulnerabilityEnabled": False, "discoveryOnly": True},
        {"id": "t5", "name": "Empty", "vulnerabilityEnabled": False},
    ])
    r = TemplateInventorySummaryRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
    assert r.summary == {
        "total": 5,
        "vuln_enabled": 2,
        "policy_enabled": 1,
        "discovery_only": 1,
    }
    assert r.card_summary == {"examined": 5, "passed": 5, "failed": 0}


def test_zero_templates_summary(fake_snapshot):
    fake_snapshot.set_templates_full([])
    r = TemplateInventorySummaryRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
    assert r.summary == {
        "total": 0,
        "vuln_enabled": 0,
        "policy_enabled": 0,
        "discovery_only": 0,
    }
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_always_passes_even_when_all_empty(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "X", "vulnerabilityEnabled": False},
    ])
    r = TemplateInventorySummaryRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
    assert r.summary["total"] == 1
    assert r.summary["vuln_enabled"] == 0
