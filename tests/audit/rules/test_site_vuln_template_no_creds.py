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


def test_shared_credentials_count(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([{"id": 9, "enabled": True, "sites": [1]}])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


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
