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
