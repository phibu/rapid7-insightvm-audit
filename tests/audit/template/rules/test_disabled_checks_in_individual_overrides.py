from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.disabled_checks_in_individual_overrides import (
    DisabledChecksInIndividualOverridesRule,
)


def test_flags_when_above_threshold(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "checks": {"individual": {"disabled": [f"cve-{i}" for i in range(25)]}},
        },
    ])
    r = DisabledChecksInIndividualOverridesRule().run(
        fake_snapshot, "warn", False, 500, {"max_disabled_individual_checks": 20}
    )
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["disabled_check_count"] == 25
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_at_or_below_threshold(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "checks": {"individual": {"disabled": [f"cve-{i}" for i in range(20)]}},
        },
    ])
    r = DisabledChecksInIndividualOverridesRule().run(
        fake_snapshot, "warn", False, 500, {"max_disabled_individual_checks": 20}
    )
    assert r.status == "pass"


def test_default_threshold_is_20(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "checks": {"individual": {"disabled": [f"cve-{i}" for i in range(21)]}},
        },
    ])
    r = DisabledChecksInIndividualOverridesRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1


def test_examined_includes_all_templates(fake_snapshot):
    # Examined denominator is ALL templates (individual overrides apply
    # across vuln/policy/discovery types).
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "vulnerabilityEnabled": True, "checks": {}},
        {"id": "t2", "name": "T2", "vulnerabilityEnabled": False, "checks": {}},
        {"id": "t3", "name": "T3", "policyEnabled": True, "checks": {}},
    ])
    r = DisabledChecksInIndividualOverridesRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.card_summary == {"examined": 3, "passed": 3, "failed": 0}


def test_missing_individual_block_treated_as_empty(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "checks": {}},
    ])
    r = DisabledChecksInIndividualOverridesRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
