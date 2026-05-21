from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.multiple_global_administrators import (
    MultipleGlobalAdministratorsRule,
)


def _ga(uid: int, login: str, *, enabled: bool = True) -> dict:
    return {"id": uid, "login": login, "enabled": enabled, "role": {"id": "global-admin"}}


def _user(uid: int, login: str) -> dict:
    return {"id": uid, "login": login, "enabled": True, "role": {"id": "user"}}


def test_pass_with_two_gas(fake_snapshot):
    fake_snapshot.set_users([_ga(1, "alice"), _ga(2, "bob"), _user(3, "carol")])
    r = MultipleGlobalAdministratorsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_with_three_gas(fake_snapshot):
    fake_snapshot.set_users([_ga(1, "a"), _ga(2, "b"), _ga(3, "c")])
    r = MultipleGlobalAdministratorsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.findings[0].details["ga_count"] == 3
    assert sorted(r.findings[0].details["ga_logins"]) == ["a", "b", "c"]


def test_disabled_gas_not_counted(fake_snapshot):
    fake_snapshot.set_users([_ga(1, "a"), _ga(2, "b"), _ga(3, "c", enabled=False)])
    r = MultipleGlobalAdministratorsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"  # only 2 enabled GAs


def test_threshold_knob(fake_snapshot):
    fake_snapshot.set_users([_ga(i, f"a{i}") for i in range(5)])
    r = MultipleGlobalAdministratorsRule().run(
        fake_snapshot, "warn", False, 500, {"max_global_administrators": 5},
    )
    assert r.status == "pass"


def test_zero_global_admins_hard_fails(fake_snapshot):
    """No enabled Global Administrator at all is a hard failure — a console
    no one can administer. The finding is `fail` even when the rule's
    configured severity is `info`."""
    fake_snapshot.set_users([
        {"id": 1, "login": "ga-was-disabled", "enabled": False,
         "role": {"id": "global-admin"}},
        {"id": 2, "login": "regular", "enabled": True,
         "role": {"id": "security-manager"}},
    ])
    r = MultipleGlobalAdministratorsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "fail"
    assert "no enabled global administrator" in r.findings[0].message.lower()
    assert r.summary["ga_count"] == 0


def test_one_global_admin_passes(fake_snapshot):
    """One enabled GA is below max_ga — still a pass, no finding."""
    fake_snapshot.set_users([
        {"id": 1, "login": "ga", "enabled": True, "role": {"id": "global-admin"}},
    ])
    r = MultipleGlobalAdministratorsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
