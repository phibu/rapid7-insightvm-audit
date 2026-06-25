from __future__ import annotations

from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import (
    SiteVulnTemplateNoCredsRule,
)


def test_no_findings_when_creds_present(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_finding_when_vuln_template_and_no_creds(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "fail"
    assert "Prod" in r.findings[0].message
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_skip_when_template_has_no_vuln_checks(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "DiscOnly", "scanTemplate": {"id": "tpl-disc"}}])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_skip_empty_site(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Empty", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 0)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_shared_credential_specific_sites_covers_site(fake_snapshot):
    """A shared credential assigned to specific sites (siteAssignment=
    "specific-sites", sites=[1]) covers site 1. Per the v3 spec a
    SharedCredential has NO `enabled` field -- the rule must not gate on
    one. Site is covered → pass, and the per-site site_credentials GET
    is never made (site_credentials is not registered, so the fixture
    would raise AssertionError if it were called)."""
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "Domain Admin", "siteAssignment": "specific-sites", "sites": [1]},
    ])
    fake_snapshot.set_site_asset_count(1, 100)
    # Deliberately NOT registering set_site_credentials(1, ...): if the rule
    # makes the per-site call, FakeSnapshot raises AssertionError.
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_shared_credential_all_sites_covers_every_site(fake_snapshot):
    """A shared credential with siteAssignment="all-sites" has sites=null
    and covers every site. The per-site site_credentials GET must be
    skipped for all sites -- this is the optimization that turns a
    ~15-minute run into one cheap shared_credentials() GET."""
    fake_snapshot.set_sites([
        {"id": 1, "name": "Prod-A", "scanTemplate": {"id": "tpl-vuln"}},
        {"id": 2, "name": "Prod-B", "scanTemplate": {"id": "tpl-vuln"}},
    ])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "Global Cred", "siteAssignment": "all-sites", "sites": None},
    ])
    fake_snapshot.set_site_asset_count(1, 100)
    fake_snapshot.set_site_asset_count(2, 100)
    # No set_site_credentials for either site -- rule must not call it.
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_shared_credential_not_covering_site_falls_back_to_site_creds(fake_snapshot):
    """When no shared credential covers a site, the rule falls back to the
    per-site site_credentials GET. An enabled site credential → pass."""
    fake_snapshot.set_sites([{"id": 7, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    # Shared credential covers a DIFFERENT site, not 7.
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "Other", "siteAssignment": "specific-sites", "sites": [99]},
    ])
    fake_snapshot.set_site_credentials(7, [{"id": 5, "enabled": True}])
    fake_snapshot.set_site_asset_count(7, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_flagged_when_no_shared_and_no_site_creds(fake_snapshot):
    """No shared credential covers the site AND no enabled site credential
    → flagged. This is the rule's real positive case."""
    fake_snapshot.set_sites([{"id": 7, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_shared_credentials([
        {"id": 9, "name": "Other", "siteAssignment": "specific-sites", "sites": [99]},
    ])
    fake_snapshot.set_site_credentials(7, [{"id": 5, "enabled": False}])  # present but disabled
    fake_snapshot.set_site_asset_count(7, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert "Prod" in r.findings[0].message


def test_severity_override_warns(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.findings[0].severity == "warn"
