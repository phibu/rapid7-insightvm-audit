from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.near_duplicate_templates import (
    NearDuplicateTemplatesRule,
    _similarity,
)


def _tpl(id_, name, **fields):
    return {"id": id_, "name": name, **fields}


def test_similarity_helper_ignores_id_links_name():
    t1 = {"id": "a", "name": "Foo", "links": [1], "vulnerabilityEnabled": True}
    t2 = {"id": "b", "name": "Bar", "links": [2], "vulnerabilityEnabled": True}
    assert _similarity(t1, t2) == 1.0


def test_similarity_partial():
    t1 = {"id": "a", "name": "X", "a": 1, "b": 2, "c": 3, "d": 4}
    t2 = {"id": "b", "name": "Y", "a": 1, "b": 2, "c": 99, "d": 99}
    # 2 of 4 keys match
    assert _similarity(t1, t2) == 0.5


def test_three_near_identical_templates_one_cluster(fake_snapshot):
    """3 templates with the same config differing only in id/name → one
    cluster finding listing all three; failed = 3 (templates in clusters)."""
    base = {"vulnerabilityEnabled": True, "policyEnabled": False,
            "maxParallelAssets": 10, "discoveryOnly": False}
    fake_snapshot.set_templates_full([
        _tpl("t1", "FirstClone", **base),
        _tpl("t2", "SecondClone", **base),
        _tpl("t3", "ThirdClone", **base),
    ])
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    d = r.findings[0].details
    assert d["cluster_size"] == 3
    assert sorted(d["template_ids"]) == ["t1", "t2", "t3"]
    assert d["similarity"] == 1.0
    assert r.card_summary == {"examined": 3, "passed": 0, "failed": 3}


def test_distinct_templates_no_findings(fake_snapshot):
    fake_snapshot.set_templates_full([
        _tpl("t1", "A", vulnerabilityEnabled=True, policyEnabled=False,
             maxParallelAssets=10),
        _tpl("t2", "B", vulnerabilityEnabled=False, policyEnabled=True,
             maxParallelAssets=50),
    ])
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 2, "passed": 2, "failed": 0}


def test_skip_when_over_sample_size(fake_snapshot):
    """When templates > sample_size and not full_scan, emit a skip
    finding and zero-out card_summary."""
    templates = [_tpl(f"t{i}", f"Tpl{i}", vulnerabilityEnabled=True)
                 for i in range(501)]
    fake_snapshot.set_templates_full(templates)
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert "Skipped" in r.findings[0].message
    assert r.findings[0].details["template_count"] == 501
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}
    assert r.summary["skipped"] is True


def test_full_scan_bypasses_cap(fake_snapshot):
    """With full_scan=True, the rule runs even over sample_size."""
    base = {"vulnerabilityEnabled": True}
    templates = [_tpl(f"t{i}", f"Tpl{i}", **base) for i in range(10)]
    fake_snapshot.set_templates_full(templates)
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", True, 5, {})
    # All 10 identical → 1 cluster of size 10
    assert len(r.findings) == 1
    assert r.findings[0].details["cluster_size"] == 10


def test_custom_threshold(fake_snapshot):
    """At threshold 0.5, partially-similar templates cluster together."""
    fake_snapshot.set_templates_full([
        _tpl("t1", "A", a=1, b=2, c=3, d=4),
        _tpl("t2", "B", a=1, b=2, c=99, d=99),  # similarity 0.5
        _tpl("t3", "C", a=99, b=99, c=99, d=99),  # similarity 0.0 to t1
    ])
    # Default 0.95 → no clusters
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    # Lowered to 0.5 → t1 + t2 cluster
    r = NearDuplicateTemplatesRule().run(
        fake_snapshot, "info", False, 500, {"similarity_threshold": 0.5},
    )
    assert len(r.findings) == 1
    assert r.findings[0].details["cluster_size"] == 2


def test_invalid_threshold_falls_back_to_default(fake_snapshot):
    fake_snapshot.set_templates_full([
        _tpl("t1", "A", a=1), _tpl("t2", "B", a=1),
    ])
    r = NearDuplicateTemplatesRule().run(
        fake_snapshot, "info", False, 500, {"similarity_threshold": "nope"},
    )
    # Default 0.95 → identical templates still cluster
    assert len(r.findings) == 1


def test_threshold_clamped_to_range(fake_snapshot):
    fake_snapshot.set_templates_full([
        _tpl("t1", "A", a=1), _tpl("t2", "B", a=1),
    ])
    # > 1.0 clamps to 1.0; identical content still 1.0 sim → cluster
    r = NearDuplicateTemplatesRule().run(
        fake_snapshot, "info", False, 500, {"similarity_threshold": 5.0},
    )
    assert len(r.findings) == 1


def test_zero_or_one_template(fake_snapshot):
    fake_snapshot.set_templates_full([])
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}

    fake_snapshot.set_templates_full([_tpl("t1", "Only", a=1)])
    r = NearDuplicateTemplatesRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}
