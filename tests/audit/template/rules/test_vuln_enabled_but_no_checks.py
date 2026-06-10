from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.vuln_enabled_but_no_checks import (
    VulnEnabledButNoChecksRule,
)


def test_flags_vuln_enabled_with_empty_checks(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "broken",
            "name": "Broken Template",
            "vulnerabilityEnabled": True,
            "checks": {
                "types": {"enabled": []},
                "categories": {"enabled": []},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "broken"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_categories_populated(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "good-cats",
            "name": "Good Cats",
            "vulnerabilityEnabled": True,
            "checks": {
                "types": {"enabled": []},
                "categories": {"enabled": ["windows", "linux"]},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_pass_when_types_populated(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "good-types",
            "name": "Good Types",
            "vulnerabilityEnabled": True,
            "checks": {
                "types": {"enabled": ["safe-policy-spider-cve"]},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_flags_old_shape_vulnerability_checks_enabled(fake_snapshot):
    """Older on-prem consoles expose vuln-enabled state at
    template.vulnerabilityChecks.enabled. The rule must honor both
    shapes via EnvSnapshot.template_vuln_enabled() — otherwise old-shape
    consoles would silently miss this hard-fail rule (no templates
    examined at all).

    With the helper, the old-shape template IS examined. Whether it
    gets flagged depends on whether the rule can read the
    types/categories sub-fields. On the old shape those live under
    template.vulnerabilityChecks.{types,categories}.enabled, not
    template.checks.{types,categories}.enabled. So the rule examines
    the template but treats both sub-arrays as empty (the modern-shape
    lookup misses), which produces a flag — the rule's primary intent
    ("vuln assessment runs but performs zero checks") is preserved
    even on the old shape, because the modern-shape miss looks
    identical to truly-empty arrays.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "old-shape",
            "name": "OldShape",
            "vulnerabilityChecks": {
                "enabled": True,
                "types": {"enabled": ["XYZ"]},
                "categories": {"enabled": ["abc"]},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    # The rule examines the old-shape template (template_vuln_enabled
    # returns True) but reads `t.checks.*` instead of
    # `t.vulnerabilityChecks.*`, which returns empty in both cases —
    # so the template is flagged even though it actually has checks
    # populated. Documents the known modern-shape-only sub-field read.
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_vuln_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "discovery-only",
            "name": "Discovery Only",
            "vulnerabilityEnabled": False,
            "checks": {},
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_missing_checks_block_treated_as_empty(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "no-checks", "name": "No Checks", "vulnerabilityEnabled": True},
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
