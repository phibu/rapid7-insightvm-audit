from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.enhanced_logging_in_prod import (
    EnhancedLoggingInProdRule,
)


def test_flags_enhanced_logging_on_high_importance_site(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "DebugTemplate", "enhancedLogging": True},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "Crown Jewels", "importance": "very_high",
         "scanTemplate": "t1"},
    ])
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    d = r.findings[0].details
    assert d["template_id"] == "t1"
    assert "Crown Jewels" in d["high_importance_sites"]
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_no_finding_when_bound_site_is_normal_importance(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "DebugTemplate", "enhancedLogging": True},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "Normal", "importance": "normal",
         "scanTemplate": "t1"},
    ])
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    # Examined still 1 — the template has enhancedLogging on; it's
    # applicable to the rule even though no high-importance site is bound.
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_no_finding_when_no_bound_sites(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Orphan", "enhancedLogging": True},
    ])
    fake_snapshot.set_sites([])
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_template_without_enhanced_logging_not_examined(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Standard", "enhancedLogging": False},
        {"id": "t2", "name": "Default"},  # field unset
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "X", "importance": "very_high", "scanTemplate": "t1"},
    ])
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    # Neither template has enhancedLogging on — examined = 0
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_high_importance_sites_overflow(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Debug", "enhancedLogging": True},
    ])
    sites = [
        {"id": i, "name": f"site-{i}", "importance": "high",
         "scanTemplate": "t1"}
        for i in range(25)
    ]
    fake_snapshot.set_sites(sites)
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    d = r.findings[0].details
    assert d["high_importance_site_count"] == 25
    assert len(d["high_importance_sites"]) == 20
    assert d["high_importance_sites_overflow"] == 5


def test_nested_scan_template_shape(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Debug", "enhancedLogging": True},
    ])
    fake_snapshot.set_sites([
        {"id": 1, "name": "Old Console", "importance": "high",
         "scanTemplate": {"id": "t1", "name": "Debug"}},
    ])
    r = EnhancedLoggingInProdRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
