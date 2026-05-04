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


def test_self_skip_when_all_users_return_401(fake_snapshot):
    """If every privileged user's 2FA endpoint returns 401, the calling key
    likely lacks Global Administrator — self-skip with an info finding."""
    from rapid7_healthcheck.client import Rapid7ClientError

    fake_snapshot.set_users([
        _user(1, "alice", "global-admin"),
        _user(2, "bob", "global-admin"),
        _user(3, "carol", "custom-role", superuser=True),
    ])
    err = Rapid7ClientError("401 at /api/3/users/X/2FA: auth", status_code=401)
    fake_snapshot.set_user_2fa_raises(1, err)
    fake_snapshot.set_user_2fa_raises(2, err)
    fake_snapshot.set_user_2fa_raises(3, err)

    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "skipped"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "info"
    msg = r.findings[0].message.lower()
    assert "global administrator" in msg or "401" in msg


def test_findings_when_some_users_succeed_others_401(fake_snapshot):
    """Mixed 200/401: 401 → treat as no-MFA-configured (a finding)."""
    from rapid7_healthcheck.client import Rapid7ClientError

    fake_snapshot.set_users([
        _user(1, "alice", "global-admin"),   # False  → finding
        _user(2, "bob", "global-admin"),     # True   → no finding
        _user(3, "carol", "global-admin"),   # 401    → finding (disambiguation)
    ])
    fake_snapshot.set_user_2fa_enabled(1, False)
    fake_snapshot.set_user_2fa_enabled(2, True)
    fake_snapshot.set_user_2fa_raises(3, Rapid7ClientError("401", status_code=401))

    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})

    assert len(r.findings) == 2
    logins = {f.details["login"] for f in r.findings}
    assert logins == {"alice", "carol"}


def test_findings_when_all_users_return_explicit_status(fake_snapshot):
    """All users returned a 2FA status (no 401s); no disambiguation needed."""
    fake_snapshot.set_users([
        _user(1, "alice", "global-admin"),
        _user(2, "bob", "global-admin"),
        _user(3, "carol", "global-admin"),
    ])
    fake_snapshot.set_user_2fa_enabled(1, False)
    fake_snapshot.set_user_2fa_enabled(2, False)
    fake_snapshot.set_user_2fa_enabled(3, True)

    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})

    assert len(r.findings) == 2
    logins = {f.details["login"] for f in r.findings}
    assert logins == {"alice", "bob"}


def _user_with_auth(uid: int, login: str, auth_type: str | None, role_id: str = "global-admin") -> dict:
    """Helper: build a user dict with an explicit authentication.type."""
    u = {
        "id": uid,
        "login": login,
        "enabled": True,
        "role": {"id": role_id, "name": role_id, "superuser": False},
    }
    if auth_type is not None:
        u["authentication"] = {"type": auth_type}
    return u


def test_external_saml_user_skipped_no_2fa_call(fake_snapshot):
    """SAML-authenticated privileged user must NOT trigger a 2FA endpoint call;
    they appear in a single aggregate info finding instead."""
    fake_snapshot.set_users([_user_with_auth(1, "saml-admin", "saml")])
    # Deliberately do NOT set_user_2fa_enabled — if the rule calls it, the fake
    # returns False (default) and we'd see a fail finding. We assert there is none.
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.summary["users_external_auth"] == 1
    assert r.summary["users_without_mfa"] == 0
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert "external sources" in info_findings[0].message.lower()
    assert info_findings[0].details["external_auth_user_count"] == 1
    assert info_findings[0].details["external_auth_users"] == [
        {"login": "saml-admin", "auth_type": "saml"},
    ]
