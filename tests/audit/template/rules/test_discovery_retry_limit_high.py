from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.discovery_retry_limit_high import (
    DiscoveryRetryLimitHighRule,
)


def _perf(template, **kw):
    template.setdefault("discovery", {}).setdefault("performance", {}).update(kw)
    return template


def test_flags_above_default(fake_snapshot):
    fake_snapshot.set_templates_full([
        _perf({"id": "t1", "name": "Retry3", "vulnerabilityEnabled": True},
              retryLimit=3),
    ])
    r = DiscoveryRetryLimitHighRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["retry_limit"] == 3
    assert r.findings[0].details["max_retry_limit"] == 1


def test_at_threshold_not_flagged(fake_snapshot):
    fake_snapshot.set_templates_full([
        _perf({"id": "t2", "name": "Retry1", "vulnerabilityEnabled": True},
              retryLimit=1),
    ])
    r = DiscoveryRetryLimitHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []


def test_absent_skipped(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t3", "name": "NoPerf", "vulnerabilityEnabled": True},
    ])
    r = DiscoveryRetryLimitHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0


def test_custom_knob(fake_snapshot):
    fake_snapshot.set_templates_full([
        _perf({"id": "t4", "name": "Retry3", "vulnerabilityEnabled": True},
              retryLimit=3),
    ])
    r = DiscoveryRetryLimitHighRule().run(
        fake_snapshot, "info", False, 500, {"max_retry_limit": 3})
    assert r.findings == []


def test_non_int_value_skipped(fake_snapshot):
    fake_snapshot.set_templates_full([
        _perf({"id": "t5", "name": "Bad", "vulnerabilityEnabled": True},
              retryLimit="oops"),
    ])
    r = DiscoveryRetryLimitHighRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0
