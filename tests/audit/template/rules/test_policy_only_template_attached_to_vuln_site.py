from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.policy_only_template_attached_to_vuln_site import (
    PolicyOnlyTemplateAttachedToVulnSiteRule,
)


_POLICY_ONLY = {
    "id": "policy-only",
    "name": "Policy Only",
    "policyEnabled": True,
    "vulnerabilityEnabled": False,
}


def test_flags_policy_only_template_on_high_importance_site(fake_snapshot):
    fake_snapshot.set_templates_full([_POLICY_ONLY])
    fake_snapshot.set_sites([
        {
            "id": 1,
            "name": "Prod DB",
            "importance": "high",
            "scanTemplate": "policy-only",
        },
    ])
    r = PolicyOnlyTemplateAttachedToVulnSiteRule().run(fake_snapshot, "info", False, 500, {})
    # info-severity findings don't escalate check status.
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "policy-only"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_flags_when_scanTemplate_is_nested_object(fake_snapshot):
    fake_snapshot.set_templates_full([_POLICY_ONLY])
    fake_snapshot.set_sites([
        {
            "id": 1,
            "name": "Crown Jewel",
            "importance": "very_high",
            "scanTemplate": {"id": "policy-only", "name": "Policy Only"},
        },
    ])
    r = PolicyOnlyTemplateAttachedToVulnSiteRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1


def test_no_finding_when_bound_site_is_normal_importance(fake_snapshot):
    fake_snapshot.set_templates_full([_POLICY_ONLY])
    fake_snapshot.set_sites([
        {
            "id": 1,
            "name": "Normal Site",
            "importance": "normal",
            "scanTemplate": "policy-only",
        },
    ])
    r = PolicyOnlyTemplateAttachedToVulnSiteRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_no_finding_when_template_is_not_policy_only(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "vuln-and-policy",
            "name": "Vuln+Policy",
            "policyEnabled": True,
            "vulnerabilityEnabled": True,
        },
    ])
    fake_snapshot.set_sites([
        {
            "id": 1,
            "name": "Prod",
            "importance": "high",
            "scanTemplate": "vuln-and-policy",
        },
    ])
    r = PolicyOnlyTemplateAttachedToVulnSiteRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_no_sites_no_findings(fake_snapshot):
    fake_snapshot.set_templates_full([_POLICY_ONLY])
    fake_snapshot.set_sites([])
    r = PolicyOnlyTemplateAttachedToVulnSiteRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}
