from __future__ import annotations

from rapid7_healthcheck.audit.user_permission.rules.locked_user_account import (
    LockedUserAccountRule,
)


def test_pass_when_no_locked_users(fake_user_snapshot):
    fake_user_snapshot.set_users([
        {"id": 1, "login": "alice", "enabled": True, "locked": False, "role": {"id": "user"}},
    ])
    r = LockedUserAccountRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.summary["locked_count"] == 0


def test_warn_with_locked_users(fake_user_snapshot):
    fake_user_snapshot.set_users([
        {"id": 1, "login": "alice", "enabled": True, "locked": True, "role": {"id": "user"}},
        {"id": 2, "login": "bob", "enabled": True, "locked": False, "role": {"id": "user"}},
    ])
    r = LockedUserAccountRule().run(fake_user_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.summary["locked_count"] == 1
    assert "alice" in r.findings[0].message
    assert r.card_summary == {"examined": 2, "passed": 1, "failed": 1}
