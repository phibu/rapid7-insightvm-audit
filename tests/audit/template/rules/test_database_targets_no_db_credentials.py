from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.database_targets_no_db_credentials import (
    DatabaseTargetsNoDbCredentialsRule,
)


def test_no_finding_when_oracle_cred_present(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "tpl-oracle", "name": "Oracle", "database": {"oracle": ["FINANCE"]}},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "DB", "scanTemplate": "tpl-oracle"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "oracle"}},
    ])
    r = DatabaseTargetsNoDbCredentialsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_flags_postgres_target_without_any_db_creds(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "tpl-pg", "name": "PG", "database": {"postgres": "appdb"}},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "DB", "scanTemplate": "tpl-pg"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "ssh"}},
    ])
    r = DatabaseTargetsNoDbCredentialsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "tpl-pg"
    assert r.findings[0].details["db_target_kinds"] == ["postgres"]
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_template_with_no_db_targets_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "nodb", "name": "NoDB", "database": {"oracle": [], "postgres": "", "db2": ""}},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "Foo", "scanTemplate": "nodb"},
    ])
    r = DatabaseTargetsNoDbCredentialsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_db2_target_db2_cred_passes(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "tpl-db2", "name": "DB2", "database": {"db2": "PROD"}},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "DB", "scanTemplate": "tpl-db2"},
    ])
    fake_snapshot.set_site_credentials(1, [
        {"account": {"service": "db2"}},
    ])
    r = DatabaseTargetsNoDbCredentialsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []


def test_db_template_no_bound_sites_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "tpl-oracle", "name": "Oracle", "database": {"oracle": ["FIN"]}},
    ])
    fake_snapshot.set_sites([])
    r = DatabaseTargetsNoDbCredentialsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_database_targets_prefetches_bound_site_credentials():
    """The rule warms site_credentials for the union of DB-template-bound
    sites via one prefetch call before the per-site loop."""
    from tests.audit.conftest import FakeSnapshot

    snap = FakeSnapshot()
    # One template with a postgres DB target, bound to sites 1 and 2.
    snap.set_templates_full([
        {"id": "tpl-db", "name": "DB Audit", "database": {"postgres": "prod"}},
    ])
    snap.set_sites([
        {"id": 1, "name": "site-1", "scanTemplate": "tpl-db"},
        {"id": 2, "name": "site-2", "scanTemplate": "tpl-db"},
    ])
    snap.set_site_credentials(1, [])   # no DB cred
    snap.set_site_credentials(2, [])   # no DB cred

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    def _spy(site_ids):
        prefetched.append(list(site_ids))
        return orig(site_ids)
    snap.prefetch_site_credentials = _spy

    rule = DatabaseTargetsNoDbCredentialsRule()
    result = rule.run(snap, "warn", True, 500, {})

    # Prefetch was called once with both bound site ids.
    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2]
    # Behavior unchanged: the template is flagged (no DB creds on either site).
    assert result.summary["templates_flagged"] == 1
