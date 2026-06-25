from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.parallel_assets_extreme import (
    ParallelAssetsExtremeRule,
)


def test_flags_above_default_max(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Aggressive", "maxParallelAssets": 100},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["max_parallel_assets"] == 100
    assert r.card_summary == {"examined": 1, "passed": 0, "failed": 1}


def test_in_range_not_flagged(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t2", "name": "Reasonable", "maxParallelAssets": 10},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_at_boundary_min_value_not_flagged(fake_snapshot):
    """Boundary value at min_threshold is INCLUSIVE -- a user setting
    parallel_assets_min=2 means 'values 2 and up are acceptable.' Strictly-
    below values flag; the boundary value itself does not.
    """
    fake_snapshot.set_templates_full([
        {"id": "boundary-min", "name": "Boundary", "maxParallelAssets": 2},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_at_boundary_max_value_not_flagged(fake_snapshot):
    """Boundary value at max_threshold is INCLUSIVE -- a user setting
    parallel_assets_max=50 means 'up to 50 is acceptable.'
    """
    fake_snapshot.set_templates_full([
        {"id": "boundary-max", "name": "Boundary", "maxParallelAssets": 50},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_template_without_field_not_examined(fake_snapshot):
    """Templates without `maxParallelAssets` use the engine default and
    are not applicable to this rule -- they must not inflate `examined`."""
    fake_snapshot.set_templates_full([
        {"id": "t3", "name": "NoValue"},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 0, "passed": 0, "failed": 0}


def test_below_default_min(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "Serialized", "maxParallelAssets": 1},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["max_parallel_assets"] == 1


def test_custom_knob_overrides(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t5", "name": "Tight", "maxParallelAssets": 20},
    ])
    r = ParallelAssetsExtremeRule().run(
        fake_snapshot, "info", False, 500,
        {"parallel_assets_min": 5, "parallel_assets_max": 15},
    )
    assert len(r.findings) == 1
    assert r.findings[0].details["min_threshold"] == 5
    assert r.findings[0].details["max_threshold"] == 15


def test_knob_max_clamped_to_min(fake_snapshot):
    """If a user accidentally configures max < min, max is bumped to min."""
    fake_snapshot.set_templates_full([
        {"id": "t6", "name": "Mid", "maxParallelAssets": 10},
    ])
    r = ParallelAssetsExtremeRule().run(
        fake_snapshot, "info", False, 500,
        {"parallel_assets_min": 20, "parallel_assets_max": 5},
    )
    # max bumped up to 20, so 10 < 20 → flagged
    assert len(r.findings) == 1
    assert r.findings[0].details["min_threshold"] == 20
    assert r.findings[0].details["max_threshold"] == 20


def test_mixed_in_and_out_of_range(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Aggressive", "maxParallelAssets": 100},
        {"id": "t2", "name": "Reasonable", "maxParallelAssets": 10},
        {"id": "t3", "name": "Default"},
        {"id": "t4", "name": "Serialized", "maxParallelAssets": 1},
    ])
    r = ParallelAssetsExtremeRule().run(fake_snapshot, "info", False, 500, {})
    assert r.card_summary == {"examined": 3, "passed": 1, "failed": 2}
