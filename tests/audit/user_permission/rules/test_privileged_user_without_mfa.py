from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.privileged_user_without_mfa import (
    PrivilegedUserWithoutMfaRule,
)


def _user(uid: int, login: str, role_id: str = "user", *, enabled: bool = True, superuser: bool = False) -> dict:
    return {
        "id": uid,
        "login": login,
        "enabled": enabled,
        "role": {"id": role_id, "name": role_id, "superuser": superuser},
    }


def test_pass_when_all_privileged_users_have_mfa(fake_snapshot):
    fake_snapshot.set_users([
        _user(1, "alice", "global-admin"),
        _user(2, "bob", "user"),  # not privileged, ignored
    ])
    fake_snapshot.set_user_2fa_enabled(1, True)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_fails_when_global_admin_lacks_mfa(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice", "global-admin")])
    fake_snapshot.set_user_2fa_enabled(1, False)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert r.summary["users_without_mfa"] == 1
    assert "alice" in r.findings[0].message


def test_superuser_flag_treated_as_privileged(fake_snapshot):
    """A non-global-admin role with role.superuser=true is privileged."""
    fake_snapshot.set_users([_user(1, "su", "custom-role", superuser=True)])
    fake_snapshot.set_user_2fa_enabled(1, False)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"


def test_disabled_privileged_users_ignored(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice", "global-admin", enabled=False)])
    fake_snapshot.set_user_2fa_enabled(1, False)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.summary["privileged_users"] == 0


def test_mfa_exempt_logins_suppress_findings(fake_snapshot):
    fake_snapshot.set_users([
        _user(1, "alice", "global-admin"),
        _user(2, "healthcheck-svc", "global-admin"),
    ])
    fake_snapshot.set_user_2fa_enabled(1, True)
    fake_snapshot.set_user_2fa_enabled(2, False)
    r = PrivilegedUserWithoutMfaRule().run(
        fake_snapshot, "fail", False, 500,
        {"mfa_exempt_logins": ["healthcheck-svc"]},
    )
    assert r.status == "pass"
    assert r.summary["users_exempt"] == 1
    assert r.summary["users_without_mfa"] == 0


def test_skipped_when_2fa_endpoint_unavailable(fake_snapshot):
    """If the 2FA endpoint returns None for any user, the rule self-skips."""
    fake_snapshot.set_users([_user(1, "alice", "global-admin")])
    fake_snapshot.set_user_2fa_enabled(1, None)  # endpoint unavailable
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "skipped"
    assert r.summary["endpoint_available"] is False
