from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.local_account_when_sso_configured import (
    LocalAccountWhenSsoConfiguredRule,
)


def _user(uid: int, login: str, auth_type: str = "normal", *, enabled: bool = True) -> dict:
    return {
        "id": uid, "login": login, "enabled": enabled,
        "authentication": {"type": auth_type},
        "role": {"id": "user"},
    }


def test_skipped_when_no_external_sso_source(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "local", "external": False, "type": "normal"}])
    fake_snapshot.set_users([_user(1, "alice")])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "skipped"


def test_pass_when_local_count_within_threshold(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "ldap", "external": True, "type": "ldap"}])
    fake_snapshot.set_users([
        _user(1, "break-glass-1"),
        _user(2, "break-glass-2"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"  # 2 <= 2


def test_warn_when_local_count_exceeds_threshold(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_snapshot.set_users([
        _user(1, "alice"),
        _user(2, "bob"),
        _user(3, "carol"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.findings[0].details["local_user_count"] == 3


def test_threshold_knob_overrides_default(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_snapshot.set_users([_user(i, f"u{i}") for i in range(5)])
    r = LocalAccountWhenSsoConfiguredRule().run(
        fake_snapshot, "warn", False, 500, {"max_local_accounts_when_sso": 5},
    )
    assert r.status == "pass"  # 5 <= 5


def test_disabled_local_accounts_ignored(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_snapshot.set_users([
        _user(1, "alice"),
        _user(2, "bob", enabled=False),
        _user(3, "carol", enabled=False),
        _user(4, "dave", enabled=False),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"  # only alice (1) is enabled+local


def test_external_users_ignored(fake_snapshot):
    fake_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_snapshot.set_users([
        _user(1, "alice", "saml"),
        _user(2, "bob", "ldap"),
        _user(3, "carol", "kerberos"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
