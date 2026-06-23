from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.discovery_timeout_high import (
    DiscoveryTimeoutHighRule,
)


def _timeout(template, **kw):
    template.setdefault("discovery", {}).setdefault("performance", {}).setdefault(
        "timeout", {}).update(kw)
    return template


def test_flags_ceiling_above_default(fake_snapshot):
    """maximum=PT3S (3000ms) is above the 500ms ceiling default → flag."""
    fake_snapshot.set_templates_full([
        _timeout({"id": "t1", "name": "Slow", "vulnerabilityEnabled": True},
                 initial="PT0.5S", maximum="PT3S"),
    ])
    r = DiscoveryTimeoutHighRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    d = r.findings[0].details
    assert d["timeout_ceiling_ms"] == 3000.0
    assert d["max_timeout_ceiling_ms"] == 500


def test_flags_initial_above_default(fake_snapshot):
    """initial=PT0.5S (500ms) is above the 200ms initial default → flag."""
    fake_snapshot.set_templates_full([
        _timeout({"id": "t2", "name": "SlowInit", "vulnerabilityEnabled": True},
                 initial="PT0.5S", maximum="PT0.5S"),
    ])
    r = DiscoveryTimeoutHighRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["timeout_initial_ms"] == 500.0


def test_tuned_low_not_flagged(fake_snapshot):
    fake_snapshot.set_templates_full([
        _timeout({"id": "t3", "name": "Tuned", "vulnerabilityEnabled": True},
                 initial="PT0.2S", maximum="PT0.5S"),
    ])
    r = DiscoveryTimeoutHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_absent_block_skipped(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "NoTimeout", "vulnerabilityEnabled": True},
    ])
    r = DiscoveryTimeoutHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0


def test_unparseable_value_skips_template(fake_snapshot):
    """A non-ISO-8601 value must never crash or false-flag — the template is
    skipped (not examined)."""
    fake_snapshot.set_templates_full([
        _timeout({"id": "t5", "name": "Weird", "vulnerabilityEnabled": True},
                 initial="3 seconds", maximum="garbage"),
    ])
    r = DiscoveryTimeoutHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0


def test_custom_knobs(fake_snapshot):
    fake_snapshot.set_templates_full([
        _timeout({"id": "t6", "name": "Mid", "vulnerabilityEnabled": True},
                 initial="PT0.3S", maximum="PT1S"),
    ])
    # Raise the ceiling to 2000ms → 1000ms maximum now compliant; initial 300>250 flags
    r = DiscoveryTimeoutHighRule().run(
        fake_snapshot, "info", False, 500,
        {"max_timeout_initial_ms": 250, "max_timeout_ceiling_ms": 2000})
    assert len(r.findings) == 1
    assert r.findings[0].details["timeout_initial_ms"] == 300.0
