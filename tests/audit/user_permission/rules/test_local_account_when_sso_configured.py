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


def test_skipped_when_no_external_sso_source(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "local", "external": False, "type": "normal"}])
    fake_user_snapshot.set_users([_user(1, "alice")])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "skipped"


def test_pass_when_local_count_within_threshold(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "ldap", "external": True, "type": "ldap"}])
    fake_user_snapshot.set_users([
        _user(1, "break-glass-1"),
        _user(2, "break-glass-2"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "pass"  # 2 <= 2


def test_warn_when_local_count_exceeds_threshold(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_user_snapshot.set_users([
        _user(1, "alice"),
        _user(2, "bob"),
        _user(3, "carol"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.findings[0].details["local_user_count"] == 3
    assert r.card_summary == {"examined": 3, "passed": 0, "failed": 3}


def test_threshold_knob_overrides_default(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_user_snapshot.set_users([_user(i, f"u{i}") for i in range(5)])
    r = LocalAccountWhenSsoConfiguredRule().run(
        fake_user_snapshot, "warn", False, 500, {"max_local_accounts_when_sso": 5},
    )
    assert r.status == "pass"  # 5 <= 5


def test_disabled_local_accounts_ignored(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_user_snapshot.set_users([
        _user(1, "alice"),
        _user(2, "bob", enabled=False),
        _user(3, "carol", enabled=False),
        _user(4, "dave", enabled=False),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "pass"  # only alice (1) is enabled+local


def test_external_users_ignored(fake_user_snapshot):
    fake_user_snapshot.set_authentication_sources([{"name": "saml", "external": True, "type": "saml"}])
    fake_user_snapshot.set_users([
        _user(1, "alice", "saml"),
        _user(2, "bob", "ldap"),
        _user(3, "carol", "kerberos"),
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_external_source_detected_via_type_field(fake_user_snapshot):
    """A console may expose external auth sources with a `type` field
    (saml/ldap/kerberos) and no `external` key. The rule must still
    detect them — otherwise it self-skips and produces a false pass."""
    fake_user_snapshot.set_authentication_sources([
        {"name": "corp-saml", "type": "saml"},  # external, no `external` key
    ])
    fake_user_snapshot.set_users([
        {"id": 1, "login": "a", "enabled": True, "authentication": {"type": "normal"}},
        {"id": 2, "login": "b", "enabled": True, "authentication": {"type": "normal"}},
        {"id": 3, "login": "c", "enabled": True, "authentication": {"type": "normal"}},
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(
        fake_user_snapshot, "warn", False, 500, {"max_local_accounts_when_sso": 2},
    )
    # 3 local users > threshold 2, and the SAML source IS detected → warn,
    # not a skipped false pass.
    assert r.status == "warn"
    assert r.summary["external_source_count"] == 1


def test_normal_type_source_not_treated_as_external(fake_user_snapshot):
    """A source whose `type` is `normal` (the local store) is not external."""
    fake_user_snapshot.set_authentication_sources([{"name": "builtin", "type": "normal"}])
    fake_user_snapshot.set_users([])
    r = LocalAccountWhenSsoConfiguredRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "skipped"


def test_external_source_detected_when_external_flag_false_but_type_set(fake_user_snapshot):
    """A source with external explicitly False but a non-normal `type`
    (e.g. ldap) must still be detected — the `external` flag arm rejects,
    the `type` arm accepts."""
    fake_user_snapshot.set_authentication_sources([
        {"name": "corp-ldap", "external": False, "type": "ldap"},
    ])
    fake_user_snapshot.set_users([
        {"id": 1, "login": "a", "enabled": True, "authentication": {"type": "normal"}},
        {"id": 2, "login": "b", "enabled": True, "authentication": {"type": "normal"}},
        {"id": 3, "login": "c", "enabled": True, "authentication": {"type": "normal"}},
    ])
    r = LocalAccountWhenSsoConfiguredRule().run(
        fake_user_snapshot, "warn", False, 500, {"max_local_accounts_when_sso": 2},
    )
    assert r.status == "warn"
    assert r.summary["external_source_count"] == 1
