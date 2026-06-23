from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.superuser_flag_outside_global_admin import (
    SuperuserFlagOutsideGlobalAdminRule,
)


def test_pass_when_superuser_only_on_global_admin(fake_user_snapshot):
    fake_user_snapshot.set_users([
        {"id": 1, "login": "alice", "enabled": True,
         "role": {"id": "global-admin", "name": "Global Admin", "superuser": True}},
        {"id": 2, "login": "bob", "enabled": True,
         "role": {"id": "user", "name": "User", "superuser": False}},
    ])
    r = SuperuserFlagOutsideGlobalAdminRule().run(fake_user_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_fails_when_superuser_on_custom_role(fake_user_snapshot):
    fake_user_snapshot.set_users([
        {"id": 1, "login": "backdoor", "enabled": True,
         "role": {"id": "custom-role", "name": "Custom", "superuser": True}},
    ])
    r = SuperuserFlagOutsideGlobalAdminRule().run(fake_user_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert "backdoor" in r.findings[0].message
    assert r.findings[0].details["role_id"] == "custom-role"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_disabled_user_with_superuser_still_flagged(fake_user_snapshot):
    """A disabled superuser flag is still a misconfiguration to clean up."""
    fake_user_snapshot.set_users([
        {"id": 1, "login": "stale", "enabled": False,
         "role": {"id": "custom-role", "superuser": True}},
    ])
    r = SuperuserFlagOutsideGlobalAdminRule().run(fake_user_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
