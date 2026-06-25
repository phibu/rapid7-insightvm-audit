from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.vuln_enabled_but_no_checks import (
    VulnEnabledButNoChecksRule,
)


def test_issue_29_template_configured_via_disabled_and_individual_passes(fake_snapshot):
    """Issue #29: the built-in 'Denial of service' template enables a huge
    check set via ``categories.disabled`` (454/455 enabled = 1 disabled) and
    ``individual.enabled`` (1.78M checks) -- its ``*.enabled`` category/type
    lists are empty, but it absolutely runs checks. The old rule read only the
    two ``.enabled`` lists and false-flagged it ``fail``. It must NOT flag.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "denial-of-service",
            "name": "Denial of service",
            "vulnerabilityEnabled": True,
            "checks": {
                "categories": {"enabled": [], "disabled": ["policy"]},
                "types": {"enabled": [], "disabled": []},
                "individual": {"enabled": [{"id": "x"}], "disabled": []},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_flags_truly_blank_template_as_warn(fake_snapshot):
    """All five enable/disable lists empty → provably 'no check configuration'.
    Flagged, but at warn (not the old fail) -- the baseline is unknowable.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "blank",
            "name": "Blank Template",
            "vulnerabilityEnabled": True,
            "checks": {
                "categories": {"enabled": [], "disabled": []},
                "types": {"enabled": [], "disabled": []},
                "individual": {"enabled": [], "disabled": []},
            },
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["template_id"] == "blank"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_default_severity_is_warn(fake_snapshot):
    """The rule's default_severity dropped fail -> warn (issue #29)."""
    assert VulnEnabledButNoChecksRule.default_severity == "warn"


def test_categories_disabled_only_passes(fake_snapshot):
    """A non-empty ``categories.disabled`` proves a curated baseline → passes."""
    fake_snapshot.set_templates_full([
        {
            "id": "all-except",
            "name": "All Except Policy",
            "vulnerabilityEnabled": True,
            "checks": {"categories": {"enabled": [], "disabled": ["policy"]}},
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_individual_enabled_only_passes(fake_snapshot):
    """Checks enabled purely via ``individual.enabled`` → passes."""
    fake_snapshot.set_templates_full([
        {
            "id": "individuals",
            "name": "Individual Checks",
            "vulnerabilityEnabled": True,
            "checks": {"individual": {"enabled": [{"id": "abc"}]}},
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_types_disabled_only_passes(fake_snapshot):
    """A non-empty ``types.disabled`` also proves a curated baseline."""
    fake_snapshot.set_templates_full([
        {
            "id": "type-except",
            "name": "Types Except",
            "vulnerabilityEnabled": True,
            "checks": {"types": {"enabled": [], "disabled": ["unsafe"]}},
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_vuln_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "discovery-only",
            "name": "Discovery Only",
            "vulnerabilityEnabled": False,
            "checks": {},
        },
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_missing_checks_block_flags(fake_snapshot):
    """No ``checks`` block at all = no check configuration → flagged (warn)."""
    fake_snapshot.set_templates_full([
        {"id": "no-checks", "name": "No Checks", "vulnerabilityEnabled": True},
    ])
    r = VulnEnabledButNoChecksRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
