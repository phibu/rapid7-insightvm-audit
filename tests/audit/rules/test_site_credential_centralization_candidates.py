from __future__ import annotations

from rapid7_healthcheck.audit.rules.site_credential_centralization_candidates import (
    SiteCredentialCentralizationCandidatesRule,
)


def _site_cred(name, service="ssh", username="root", domain=None, host=None, port=None):
    acct = {"service": service, "username": username}
    if domain is not None:
        acct["domain"] = domain
    cred = {"id": name, "name": name, "account": acct}
    if host is not None:
        cred["hostRestriction"] = host
    if port is not None:
        cred["portRestriction"] = port
    return cred


def test_same_cred_in_two_sites_is_centralization_candidate(fake_snapshot):
    """A site-specific credential whose (service, username, ...) matches a
    credential in another site could be a shared credential."""
    fake_snapshot.set_sites([{"id": 1, "name": "Site A"}, {"id": 2, "name": "Site B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_site_cred("svc-linux-root")])
    fake_snapshot.set_site_credentials(2, [_site_cred("svc-linux-root")])

    r = SiteCredentialCentralizationCandidatesRule().run(fake_snapshot, "info", True, 500, {})
    assert r.status == "pass"  # info severity never escalates
    # one finding describing the centralization cluster (ssh/root used in 2 sites)
    assert any("centraliz" in f.message.lower() or "shared" in f.message.lower()
               for f in r.findings)
    assert r.severity == "info"
    assert r.summary["centralization_candidates"] == 1


def test_cred_in_only_one_site_is_not_flagged(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_site_cred("svc-a", username="alice")])
    fake_snapshot.set_site_credentials(2, [_site_cred("svc-b", username="bob")])
    r = SiteCredentialCentralizationCandidatesRule().run(fake_snapshot, "info", True, 500, {})
    assert r.findings == []
    assert r.summary["centralization_candidates"] == 0


def test_local_named_creds_excluded(fake_snapshot):
    """Creds matching the intentional-local pattern are excluded even when they
    recur across sites."""
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_site_cred("LOCAL_db_admin")])
    fake_snapshot.set_site_credentials(2, [_site_cred("LOCAL_db_admin")])
    r = SiteCredentialCentralizationCandidatesRule().run(fake_snapshot, "info", True, 500, {})
    assert r.findings == []


def test_custom_local_pattern_knob(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_credentials(1, [_site_cred("keep-x")])
    fake_snapshot.set_site_credentials(2, [_site_cred("keep-x")])
    r = SiteCredentialCentralizationCandidatesRule().run(
        fake_snapshot, "info", True, 500, {"local_name_pattern": r"^keep-"}
    )
    assert r.findings == []


def test_shared_cred_used_in_one_site_flagged(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "A"}])
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "shared-but-not", "account": {"service": "ssh", "username": "root"},
         "siteAssignment": "specific-sites", "sites": [1]},
    ])
    r = SiteCredentialCentralizationCandidatesRule().run(fake_snapshot, "info", True, 500, {})
    assert r.summary["single_use_shared_credentials"] == 1
    assert any("only one site" in f.message.lower() for f in r.findings)


def test_shared_cred_assigned_all_sites_not_flagged(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "A"}])
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "global", "account": {"service": "ssh", "username": "root"},
         "siteAssignment": "all-sites"},
    ])
    r = SiteCredentialCentralizationCandidatesRule().run(fake_snapshot, "info", True, 500, {})
    assert r.summary["single_use_shared_credentials"] == 0


def test_centralization_prefetches_all_site_credentials(fake_snapshot):
    """The rule warms site_credentials for every site via one prefetch call
    before the per-site loop."""
    fake_snapshot.set_sites([
        {"id": 1, "name": "a"},
        {"id": 2, "name": "b"},
        {"id": 3, "name": "c"},
    ])
    for sid in (1, 2, 3):
        fake_snapshot.set_site_credentials(sid, [])
    fake_snapshot.set_shared_credentials([])

    prefetched: list[list[int]] = []
    orig = fake_snapshot.prefetch_site_credentials
    fake_snapshot.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    rule = SiteCredentialCentralizationCandidatesRule()
    rule.run(fake_snapshot, "info", True, 500, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2, 3]
