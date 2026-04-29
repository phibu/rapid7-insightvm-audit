from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.disabled_user_with_role_bindings import (
    DisabledUserWithRoleBindingsRule,
)


def test_pass_when_disabled_users_have_no_bindings(fake_snapshot):
    fake_snapshot.set_users([
        {"id": 1, "login": "ghost", "enabled": False, "role": {}},  # no role.id
    ])
    r = DisabledUserWithRoleBindingsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_pass_when_users_with_bindings_are_enabled(fake_snapshot):
    fake_snapshot.set_users([
        {"id": 1, "login": "alice", "enabled": True, "role": {"id": "global-admin"}},
    ])
    r = DisabledUserWithRoleBindingsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_info_finding_for_disabled_user_with_role(fake_snapshot):
    fake_snapshot.set_users([
        {"id": 1, "login": "stale", "enabled": False, "role": {"id": "user", "name": "User"}},
    ])
    r = DisabledUserWithRoleBindingsRule().run(fake_snapshot, "info", False, 500, {})
    # Info-only findings keep status at pass per the existing rollup logic.
    assert r.status == "pass"
    assert r.summary["users_flagged"] == 1
    assert "stale" in r.findings[0].message


def test_finding_severity_inherits_rule_severity(fake_snapshot):
    """If operator overrides severity to warn, status escalates."""
    fake_snapshot.set_users([
        {"id": 1, "login": "stale", "enabled": False, "role": {"id": "user"}},
    ])
    r = DisabledUserWithRoleBindingsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
