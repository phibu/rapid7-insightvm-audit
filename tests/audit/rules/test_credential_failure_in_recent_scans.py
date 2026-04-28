from __future__ import annotations

from rapid7_healthcheck.audit.rules.credential_failure_in_recent_scans import (
    CredentialFailureInRecentScansRule,
)


def test_pass_when_no_recent_credential_failures(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished", "messages": ["Credential Success on 10.0.0.5"]},
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_recent_scan_shows_credential_failure(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished",
         "messages": ["Credential Failure on 10.0.0.7", "Credential Success on 10.0.0.5"]},
        {"id": 99, "status": "finished",
         "messages": ["No Credentials Used on 10.0.0.7"]},
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_skip_sites_with_no_credentials(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "NoAuth"}])
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_diagnostic_when_scan_messages_field_missing(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished"},
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert any(f.severity == "info" for f in r.findings)
    assert not any(f.severity == "warn" for f in r.findings)


def test_sampling_enforced(fake_snapshot):
    fake_snapshot.set_sites([{"id": i, "name": f"S{i}"} for i in range(10)])
    for i in range(10):
        fake_snapshot.set_site_credentials(i, [{"id": 1, "enabled": True}])
        fake_snapshot.set_site_recent_scans(i, [{"id": 100, "status": "finished",
                                                  "messages": ["Credential Success"]}])
    fake_snapshot.set_shared_credentials([])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 3, {})
    assert r.sampled
    assert "checked 3" in r.sample_info
