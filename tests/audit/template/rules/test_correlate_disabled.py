from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.correlate_disabled import (
    CorrelateDisabledRule,
)


def test_flags_when_correlate_explicitly_false(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"correlate": False},
        },
    ])
    r = CorrelateDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_correlate_true(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"correlate": True},
        },
    ])
    r = CorrelateDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_pass_when_correlate_key_missing(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "vulnerabilityEnabled": True, "checks": {}},
    ])
    r = CorrelateDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_vuln_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": False,
            "checks": {"correlate": False},
        },
    ])
    r = CorrelateDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
