"""The cardinal two-rect mask invariant, asserted across all three figures.

Every styled box rect (`dg-band-*`, `dg-engine*`, `dg-flag`) must be drawn
*on top of* an opaque `dg-mask` rect of identical geometry -- the archify
cardinal rule (ADR-0008) that keeps arrows/segments from bleeding through a
semi-transparent fill. Before the `_masked_rect` primitive this was open-coded
7×; this test locks the invariant so the refactor (and any future builder)
can't silently drop a mask.

Segment rects in the status map (`dg-seg-*`) are deliberately *not* masked --
they tile a track that is itself a masked box -- so they are excluded.
"""

from __future__ import annotations

import re

from rapid7_healthcheck.diagrams import (
    CoverageData,
    EngineNode,
    StatusRow,
    TopologyData,
    build_coverage_svg,
    build_status_map_svg,
    build_topology_svg,
)

# A styled box class that MUST sit on a mask. dg-seg-* (status segments) and
# dg-pool (a non-filled dashed boundary) are intentionally excluded.
_MASKED_BOX_CLS = re.compile(r'class="(dg-band-[a-z]+|dg-engine(?:-[a-z]+)?|dg-flag)"')

_RECT = re.compile(
    r'<rect class="(?P<cls>dg-[a-z-]+)" x="(?P<x>[\d.]+)" y="(?P<y>[\d.]+)" '
    r'width="(?P<w>[\d.]+)" height="(?P<h>[\d.]+)"(?: rx="(?P<rx>\d+)")?/>'
)


def _rects(svg: str) -> list[dict]:
    out = []
    for m in _RECT.finditer(svg):
        out.append({
            "cls": m.group("cls"),
            "geom": (m.group("x"), m.group("y"), m.group("w"), m.group("h"), m.group("rx")),
        })
    return out


def _assert_every_styled_box_is_masked(svg: str) -> None:
    rects = _rects(svg)
    for i, r in enumerate(rects):
        if not _MASKED_BOX_CLS.fullmatch(f'class="{r["cls"]}"'):
            continue
        # The immediately-preceding rect must be a dg-mask of identical geometry.
        assert i > 0, f"styled box {r['cls']} has no preceding rect"
        prev = rects[i - 1]
        assert prev["cls"] == "dg-mask", (
            f"styled box {r['cls']} is not preceded by a dg-mask (got {prev['cls']})"
        )
        assert prev["geom"] == r["geom"], (
            f"mask geometry {prev['geom']} != box geometry {r['geom']} for {r['cls']}"
        )


def _coverage() -> str:
    return build_coverage_svg(CoverageData(
        total_assets=12000, stale=3000, never_scanned=800,
        agent_only=400, ghost=120, stale_days=30, never_scanned_days=90,
    ))


def _topology() -> str:
    return build_topology_svg(TopologyData(
        engines=[
            EngineNode(10, "Engine A", "Pool Prod", 12, 8200, False),
            EngineNode(11, "Engine B", "Pool Prod", 6, 3100, False),
            EngineNode(12, "Engine C", None, 41, 22000, True),
        ],
        orphan_site_count=3,
        unpaired_engines=["Engine D"],
        total_paired_sites=59,
    ))


def _status() -> str:
    return build_status_map_svg([
        StatusRow("Scan Engines", 6, 2, 0, 0, 1),
        StatusRow("Asset Coverage", 3, 0, 5, 0, 0),
    ])


def test_coverage_boxes_are_masked():
    _assert_every_styled_box_is_masked(_coverage())


def test_topology_boxes_are_masked():
    _assert_every_styled_box_is_masked(_topology())


def test_status_map_track_is_masked():
    _assert_every_styled_box_is_masked(_status())


def test_invariant_catches_a_missing_mask():
    # Sanity: the checker actually fails when a mask is absent. A lone styled
    # box with no preceding mask must trip the assertion.
    bad = '<svg><rect class="dg-band-fail" x="0" y="0" width="10" height="10" rx="6"/></svg>'
    import pytest
    with pytest.raises(AssertionError):
        _assert_every_styled_box_is_masked(bad)
