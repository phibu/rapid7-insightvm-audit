from __future__ import annotations

from rapid7_healthcheck.audit.rules.dynamic_groups_and_nested_tags import (
    DynamicGroupsAndNestedTagsRule,
)


def _tag(name, references=None):
    """references: list of other tag names this tag's searchCriteria points at."""
    sc = {"filters": [], "match": "all"}
    for ref in references or []:
        sc["filters"].append({"field": "custom-tag", "operator": "is", "value": ref})
    return {"name": name, "id": hash(name) & 0xffff, "type": "custom", "searchCriteria": sc}


def _dyn_group(group_id, name):
    return {"id": group_id, "name": name, "type": "dynamic"}


def _static_group(group_id, name):
    return {"id": group_id, "name": name, "type": "static"}


def test_pass_when_no_groups_and_no_tag_refs(fake_snapshot):
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_tags([_tag("plain")])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_dynamic_group_count_exceeds_threshold(fake_snapshot):
    fake_snapshot.set_asset_groups(
        [_dyn_group(i, f"dyn-{i}") for i in range(5)] + [_static_group(99, "static")]
    )
    fake_snapshot.set_tags([])
    r = DynamicGroupsAndNestedTagsRule().run(
        fake_snapshot, "warn", False, 500, {"dynamic_group_limit": 3},
    )
    assert r.status == "warn"
    assert any("dynamic asset groups" in f.message for f in r.findings)
    assert r.summary["dynamic_group_count"] == 5


def test_warn_when_tag_references_another_tag(fake_snapshot):
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_tags([_tag("base"), _tag("nested", references=["base"])])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    nested_findings = [f for f in r.findings if f.details.get("tag") == "nested"]
    assert len(nested_findings) == 1
    assert nested_findings[0].details["references"] == ["base"]
    assert r.summary["nested_tag_refs"] == 1
    assert r.card_summary == {"examined": 2, "passed": 1, "failed": 1}


def test_warn_with_circular_tag_reference(fake_snapshot):
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_tags([
        _tag("a", references=["b"]),
        _tag("b", references=["a"]),
    ])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    cycle_findings = [f for f in r.findings if "Circular" in f.message]
    assert len(cycle_findings) == 1
    assert r.summary["tag_cycles"] == 1


def test_ignores_references_to_unknown_tag_names(fake_snapshot):
    """Tags whose searchCriteria reference a name we don't have shouldn't fire
    nested-tag findings (might be a tag-by-value compare, not a reference)."""
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_tags([_tag("only-tag", references=["does-not-exist"])])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_dynamic_group_referencing_tag_emits_info_finding(fake_snapshot):
    group_with_tag_ref = {
        "id": 1, "name": "g", "type": "dynamic",
        "searchCriteria": {
            "filters": [{"field": "custom-tag", "operator": "is", "value": "high-risk"}],
            "match": "all",
        },
    }
    fake_snapshot.set_asset_groups([group_with_tag_ref])
    fake_snapshot.set_tags([_tag("high-risk")])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.summary["dynamic_groups_referencing_tags"] == 1
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert info_findings[0].details["groups"][0]["group_id"] == 1
    # Info findings alone shouldn't flip status away from pass.
    assert r.status == "pass"


def test_long_tag_chain_does_not_recurse(fake_snapshot):
    """Chain of 1500 tags each referencing the next -- would blow the
    default Python recursion limit if the cycle walker were recursive."""
    fake_snapshot.set_asset_groups([])
    chain = []
    for i in range(1500):
        refs = [f"t{i+1}"] if i < 1499 else None
        chain.append(_tag(f"t{i}", references=refs))
    fake_snapshot.set_tags(chain)
    # Should not raise RecursionError. No cycle, so tag_cycles == 0.
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.summary["tag_cycles"] == 0


def test_duplicate_filter_values_are_deduped(fake_snapshot):
    """Same tag referenced via both `value` and `values` shouldn't appear twice."""
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_tags([
        _tag("base"),
        {
            "name": "dupe", "id": 99, "type": "custom",
            "searchCriteria": {
                "filters": [
                    {"field": "custom-tag", "operator": "is", "value": "base"},
                    {"field": "custom-tag", "operator": "is", "values": ["base", "base"]},
                ],
                "match": "all",
            },
        },
    ])
    r = DynamicGroupsAndNestedTagsRule().run(fake_snapshot, "warn", False, 500, {})
    nested = [f for f in r.findings if f.details.get("tag") == "dupe"]
    assert len(nested) == 1
    assert nested[0].details["references"] == ["base"]
