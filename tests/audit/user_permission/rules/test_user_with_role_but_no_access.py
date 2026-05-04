from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.user_with_role_but_no_access import (
    UserWithRoleButNoAccessRule,
)


def _user(uid, login, *, role_id="user", all_sites=False, all_groups=False, superuser=False, enabled=True):
    return {
        "id": uid, "login": login, "enabled": enabled,
        "role": {
            "id": role_id, "name": role_id,
            "allSites": all_sites, "allAssetGroups": all_groups,
            "superuser": superuser,
        },
    }


def test_pass_when_user_has_explicit_site_access(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice")])
    fake_snapshot.set_user_sites(1, [{"id": 10}])
    fake_snapshot.set_user_asset_groups(1, [])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_pass_when_user_has_all_sites(fake_snapshot):
    """Wildcard role.allSites means access — not a candidate at all."""
    fake_snapshot.set_users([_user(1, "alice", all_sites=True)])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.summary["candidates"] == 0


def test_global_admin_skipped(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice", role_id="global-admin")])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "info", False, 500, {})
    assert r.summary["candidates"] == 0


def test_superuser_skipped(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice", role_id="custom", superuser=True)])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "info", False, 500, {})
    assert r.summary["candidates"] == 0


def test_finding_when_user_has_role_but_no_bindings(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice")])
    fake_snapshot.set_user_sites(1, [])
    fake_snapshot.set_user_asset_groups(1, [])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.summary["users_flagged"] == 1
    assert "alice" in r.findings[0].message


def test_disabled_user_skipped(fake_snapshot):
    fake_snapshot.set_users([_user(1, "alice", enabled=False)])
    r = UserWithRoleButNoAccessRule().run(fake_snapshot, "info", False, 500, {})
    assert r.summary["candidates"] == 0
