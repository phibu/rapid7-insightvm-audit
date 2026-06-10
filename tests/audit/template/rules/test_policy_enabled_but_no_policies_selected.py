from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.policy_enabled_but_no_policies_selected import (
    PolicyEnabledButNoPoliciesSelectedRule,
)


def test_flags_when_policy_enabled_and_list_empty(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "policyEnabled": True,
            "policy": {"enabled": []},
        },
    ])
    r = PolicyEnabledButNoPoliciesSelectedRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_one_policy_selected(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "policyEnabled": True,
            "policy": {"enabled": ["cis-windows"]},
        },
    ])
    r = PolicyEnabledButNoPoliciesSelectedRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_flags_when_policy_enabled_but_no_policy_block(fake_snapshot):
    # Missing block with policyEnabled:true is the same shape bug.
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "policyEnabled": True},
    ])
    r = PolicyEnabledButNoPoliciesSelectedRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1


def test_policy_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "policyEnabled": False,
            "policy": {"enabled": []},
        },
    ])
    r = PolicyEnabledButNoPoliciesSelectedRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
