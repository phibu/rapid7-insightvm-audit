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


def test_old_shape_console_examined_but_correlate_not_evaluated(fake_snapshot):
    """Older on-prem consoles expose vuln-enabled state at
    template.vulnerabilityChecks.enabled (handled by
    EnvSnapshot.template_vuln_enabled()), but the modern `checks.correlate`
    sub-field lives at `vulnerabilityChecks.correlate` on the same console.
    This rule reads modern-shape `checks.correlate` only — on older shapes,
    the template is correctly examined (counts toward `examined`) but never
    flagged because the sub-field lookup misses. Documents the known
    limitation.
    """
    fake_snapshot.set_templates_full([
        {
            "id": "old-shape",
            "name": "OldShape",
            "vulnerabilityChecks": {"enabled": True, "correlate": False},
        },
    ])
    r = CorrelateDisabledRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
    # Examined denominator includes the old-shape template (template_vuln_enabled
    # returns True for it); failed is 0 because we don't probe the legacy field.
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


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
