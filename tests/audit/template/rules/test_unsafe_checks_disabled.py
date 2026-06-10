from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.unsafe_checks_disabled import (
    UnsafeChecksDisabledRule,
)


def test_emits_info_finding_when_unsafe_false(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"unsafe": False},
        },
    ])
    r = UnsafeChecksDisabledRule().run(fake_snapshot, "info", False, 500, {})
    # Per project convention: info findings don't escalate check status.
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "info"
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_pass_when_unsafe_true(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": True,
            "checks": {"unsafe": True},
        },
    ])
    r = UnsafeChecksDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_pass_when_unsafe_key_missing(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "T1", "vulnerabilityEnabled": True, "checks": {}},
    ])
    r = UnsafeChecksDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_vuln_disabled_template_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {
            "id": "t1",
            "name": "T1",
            "vulnerabilityEnabled": False,
            "checks": {"unsafe": False},
        },
    ])
    r = UnsafeChecksDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
