from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.potential_checks_disabled import (
    PotentialChecksDisabledRule,
)


def test_flags_when_potential_explicitly_false(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"potential": False},
        },
    ])
    r = PotentialChecksDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_potential_true(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"potential": True},
        },
    ])
    r = PotentialChecksDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_pass_when_potential_key_missing(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "vulnerabilityEnabled": True, "checks": {}},
    ])
    r = PotentialChecksDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_vuln_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": False,
            "checks": {"potential": False},
        },
    ])
    r = PotentialChecksDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
