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
