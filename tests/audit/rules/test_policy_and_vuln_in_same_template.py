from __future__ import annotations

from rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template import (
    PolicyAndVulnInSameTemplateRule,
)


def _site(site_id, name, tpl_id): return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_template_separates_concerns(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln Only",
                                                  "vulnerabilityChecks": {"enabled": True},
                                                  "policyEnabled": False})
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_template_has_both(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl-mixed"), _site(2, "B", "tpl-mixed")])
    fake_snapshot.set_scan_template("tpl-mixed", {"id": "tpl-mixed", "name": "Mixed",
                                                   "vulnerabilityChecks": {"enabled": True},
                                                   "policyEnabled": True})
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert "Mixed" in r.findings[0].message
    assert sorted(r.findings[0].details["sites_using"]) == [1, 2]


def test_template_only_evaluated_when_in_use(fake_snapshot):
    fake_snapshot.set_sites([])
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
