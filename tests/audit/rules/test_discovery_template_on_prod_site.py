from __future__ import annotations

from rapid7_healthcheck.audit.rules.discovery_template_on_prod_site import (
    DiscoveryTemplateOnProdSiteRule,
)


def _site(site_id, name, tpl_id, importance="normal"):
    return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}, "importance": importance}


def test_pass_when_vuln_template_assigned(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Prod", "tpl-vuln", importance="high")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_discovery_template_on_high_importance(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Prod", "tpl-disc", importance="high")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_skip_low_importance_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Junk", "tpl-disc", importance="very_low")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_skip_small_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Tiny", "tpl-disc", importance="normal")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 5)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_handles_string_scanTemplate_and_top_level_vuln_field(fake_snapshot):
    """Rapid7-hosted consoles return scanTemplate as a bare string id, and
    use top-level vulnerabilityEnabled instead of nested vulnerabilityChecks.
    The rule must work against this shape."""
    fake_snapshot.set_sites([{
        "id": 1, "name": "Prod", "importance": "high",
        "scanTemplate": "tpl-disc",  # bare string, not a dict
    }])
    fake_snapshot.set_scan_template("tpl-disc", {
        "id": "tpl-disc", "name": "Discovery",
        "vulnerabilityEnabled": False,
    })
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert any("Discovery" in f.message for f in r.findings)


def test_top_level_vuln_enabled_passes(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Prod", "tpl-vuln", importance="high")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityEnabled": True,
    })
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
