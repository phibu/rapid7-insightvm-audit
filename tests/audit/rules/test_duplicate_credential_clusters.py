from __future__ import annotations

from rapid7_healthcheck.audit.rules.duplicate_credential_clusters import (
    DuplicateCredentialClustersRule,
)


def _cred(name, service="ssh", username="root", host=None, cid=None):
    c = {"id": cid or name, "name": name, "account": {"service": service, "username": username}}
    if host is not None:
        c["hostRestriction"] = host
    return c


def test_duplicate_cluster_across_sites_is_flagged(fake_snapshot):
    """Two credentials with the same identity in different sites form a
    duplicate cluster."""
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_cred("dup", cid="c1")])
    fake_snapshot.set_site_credentials(2, [_cred("dup", cid="c2")])

    r = DuplicateCredentialClustersRule().run(fake_snapshot, "info", True, 500, {})
    assert r.summary["clusters"] == 1
    assert any("duplicat" in f.message.lower() or "copies" in f.message.lower()
               for f in r.findings)
    assert DuplicateCredentialClustersRule.expensive is True


def test_cluster_with_differing_names_escalates_to_warn(fake_snapshot):
    """Same identity, different names = uncoordinated copies → warn."""
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_cred("svc-prod-root", cid="c1")])
    fake_snapshot.set_site_credentials(2, [_cred("ssh-root-acct", cid="c2")])
    r = DuplicateCredentialClustersRule().run(fake_snapshot, "info", True, 500, {})
    assert r.status == "warn"
    assert r.findings[0].severity == "warn"
    assert r.findings[0].details["disagree"] is True


def test_no_cluster_when_all_unique(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_cred("a", username="alice")])
    fake_snapshot.set_site_credentials(2, [_cred("b", username="bob")])
    r = DuplicateCredentialClustersRule().run(fake_snapshot, "info", True, 500, {})
    assert r.summary["clusters"] == 0
    assert r.findings == []


def test_site_and_shared_dup_forms_cluster(fake_snapshot):
    """A site cred and a shared cred with the same identity cluster together."""
    fake_snapshot.set_sites([{"id": 1, "name": "A"}])
    fake_snapshot.set_site_credentials(1, [_cred("local-copy", cid="c1")])
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "local-copy", "account": {"service": "ssh", "username": "root"}},
    ])
    r = DuplicateCredentialClustersRule().run(fake_snapshot, "info", True, 500, {})
    assert r.summary["clusters"] == 1
    sources = r.findings[0].details["sources"]
    assert "shared" in sources
    assert any(s.startswith("site:") for s in sources)


def test_fast_mode_bounds_sites_and_discloses(fake_snapshot):
    fake_snapshot.set_sites([{"id": i, "name": f"S{i}"} for i in range(5)])
    fake_snapshot.set_shared_credentials([])
    for i in range(5):
        fake_snapshot.set_site_credentials(i, [_cred("x", cid=f"c{i}")])
    # full_scan=False, sample_size=2 → only 2 sites scanned
    r = DuplicateCredentialClustersRule().run(fake_snapshot, "info", False, 2, {})
    assert r.summary["sites_examined"] == 2
    assert r.summary["sites_truncated"] == 3
    assert r.sampled is True
    assert any("not scanned" in f.message.lower() for f in r.findings)
