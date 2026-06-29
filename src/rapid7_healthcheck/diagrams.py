"""Inline-SVG report diagrams, built in pure Python.

This module is the runtime port of the `archify` skill's *design language*
(semantic fills, the two-rect mask, typography scale, fail-fast-on-overlap),
not its code -- see docs/adr/0008. It issues **no API calls**: every diagram
is built from numbers the run already holds (`CheckResult` rule-summaries +
`InventoryTotals`). The SVG is themed with the report's **own** CSS variables
through `dg-*` classes, so there is one theme system and one toggle.

Each diagram has two halves, both pure and unit-testable without rendering:
an ``extract_*`` half that pulls the numbers into a frozen view-model (or
returns ``None`` when the inputs can't support an honest figure), and a
``build_*_svg`` half that is layout only. A diagram that can't be honest does
not render -- the same discipline as the ghost-asset rule and the inventory
strip's ``return None -> skip``.
"""

from __future__ import annotations

from dataclasses import dataclass

from rapid7_healthcheck.checks import CheckResult

# Rule-id -> summary-key map for the coverage figure. Owned here so report.py
# and the checks stay ignorant of which keys feed the diagram (layer rules).
_COVERAGE_CHECK_NAME = "Asset Coverage"
_STALE_RULE = "op.asset_coverage.stale_assets"
_NEVER_RULE = "op.asset_coverage.never_scanned_assets"
_AGENT_RULE = "op.asset_coverage.agent_only_assets"
_GHOST_RULE = "op.asset_coverage.ghost_assets"


@dataclass(frozen=True)
class CoverageData:
    """The numbers behind the coverage-bands figure.

    ``total_assets`` is the denominator. ``stale`` (no scan in ``stale_days``)
    and ``never_scanned`` (no scan in ``never_scanned_days``) are **nested**:
    never-scanned is a subset of stale. ``agent_only`` and ``ghost`` are
    **cross-cutting** flags, not slices of the total. Any band but
    ``total_assets`` may be ``None`` when its rule was skipped or errored.
    """

    total_assets: int
    stale: int | None
    never_scanned: int | None
    agent_only: int | None
    ghost: int | None
    stale_days: int | None
    never_scanned_days: int | None


def _find(results: list[CheckResult], name: str) -> CheckResult | None:
    return next((r for r in results if r.name == name), None)


def _summary_of(check: CheckResult, rule_id: str) -> dict:
    for rr in check.rule_results or []:
        if rr.rule_id == rule_id:
            return rr.summary or {}
    return {}


def extract_coverage_counts(
    results: list[CheckResult], inventory
) -> CoverageData | None:
    """Pull the coverage figure's numbers from the run.

    Returns ``None`` -- so the report omits the figure -- when there is no
    inventory total to anchor the bands, no Asset Coverage check, or not one
    usable band count among its rules. A diagram that can't be honest does not
    render.
    """
    if inventory is None:
        return None
    check = _find(results, _COVERAGE_CHECK_NAME)
    if check is None:
        return None

    stale_s = _summary_of(check, _STALE_RULE)
    never_s = _summary_of(check, _NEVER_RULE)
    agent_s = _summary_of(check, _AGENT_RULE)
    ghost_s = _summary_of(check, _GHOST_RULE)

    stale = stale_s.get("stale_count")
    never_scanned = never_s.get("unscanned_count")
    agent_only = agent_s.get("agent_only_count")
    ghost = ghost_s.get("ghost_count")

    # No usable band -> nothing honest to draw.
    if stale is None and never_scanned is None and agent_only is None and ghost is None:
        return None

    return CoverageData(
        total_assets=inventory.total_assets,
        stale=stale,
        never_scanned=never_scanned,
        agent_only=agent_only,
        ghost=ghost,
        stale_days=stale_s.get("stale_asset_days"),
        never_scanned_days=never_s.get("never_scanned_days"),
    )


# --- topology ---------------------------------------------------------------

_OVERLOAD_THRESHOLD = 5000


@dataclass(frozen=True)
class EngineNode:
    """One scan engine in the topology figure, with its aggregate load.

    ``site_count`` / ``asset_load`` count the sites that point **directly** at
    this engine (``site.scanEngine == engine.id``). ``pool_name`` is set when
    the engine is a member of a pool. ``overloaded`` mirrors the
    ``single_engine_overload`` rule: ≥2 direct sites whose combined assets
    exceed the threshold.
    """

    engine_id: int
    name: str
    pool_name: str | None
    site_count: int
    asset_load: int
    overloaded: bool


@dataclass(frozen=True)
class TopologyData:
    """The bounded, engine-centric scan-topology view-model.

    Engine-centric on purpose: a console may have hundreds of sites but few
    engines, so sites are aggregated (counts on engines + an orphan bucket),
    never drawn individually. See CONTEXT.md "Report diagram" / ADR-0008.
    """

    engines: list[EngineNode]
    orphan_site_count: int
    unpaired_engines: list[str]
    total_paired_sites: int


def build_topology(snapshot, *, overload_threshold: int = _OVERLOAD_THRESHOLD):
    """Aggregate the scan topology from a snapshot's **already-cached** reads.

    Reads only ``sites()``, ``scan_engines()``, ``scan_engine_pools()`` and
    ``site_asset_count()`` -- all warmed by the audit run, so this adds no new
    API calls (it lives in ``__main__`` beside ``_build_inventory_totals``,
    not in a rule). Returns ``None`` when there are no engines to anchor the
    figure. The pairing semantics match the engine rules: a site's
    ``scanEngine`` is its pairing (may be an engine **or** a pool id); an
    engine with no direct sites that is also in no pool is *unpaired*.
    """
    engines = snapshot.scan_engines()
    if not engines:
        return None

    pools = snapshot.scan_engine_pools()
    pool_name_by_member: dict[int, str] = {}
    for pool in pools:
        pname = pool.get("name") or f"id={pool.get('id')}"
        for member_id in pool.get("engines") or []:
            pool_name_by_member[member_id] = pname
    pooled_engine_ids = set(pool_name_by_member)

    # Sites grouped by their pairing target (engine id or pool id); orphans are
    # sites with no scanEngine at all.
    sites_by_target: dict[int, list[int]] = {}
    orphan_site_count = 0
    for site in snapshot.sites():
        target = site.get("scanEngine")
        if not target:
            orphan_site_count += 1
            continue
        sites_by_target.setdefault(target, []).append(site["id"])

    nodes: list[EngineNode] = []
    unpaired: list[str] = []
    total_paired_sites = 0
    for engine in engines:
        eid = engine.get("id")
        name = engine.get("name") or f"id={eid}"
        site_ids = sites_by_target.get(eid, [])
        load = sum(snapshot.site_asset_count(sid) for sid in site_ids)
        total_paired_sites += len(site_ids)
        if not site_ids and eid not in pooled_engine_ids:
            unpaired.append(name)
            continue
        nodes.append(EngineNode(
            engine_id=eid,
            name=name,
            pool_name=pool_name_by_member.get(eid),
            site_count=len(site_ids),
            asset_load=load,
            overloaded=len(site_ids) >= 2 and load > overload_threshold,
        ))

    return TopologyData(
        engines=nodes,
        orphan_site_count=orphan_site_count,
        unpaired_engines=unpaired,
        total_paired_sites=total_paired_sites,
    )


# --- SVG layout -------------------------------------------------------------

_VIEW_W = 640
_PAD = 16
_BAND_H = 44
_BAND_GAP = 10
_FLAG_H = 30


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _num(n: int) -> str:
    return f"{n:,}"


def build_coverage_svg(data: CoverageData) -> str:
    """Build the coverage-bands SVG: honest *nested* threshold bands.

    All assets ⊇ stale (>Nd) ⊇ never-scanned (>Md), drawn as concentric
    horizontal bands shrinking inward so the subset relationship is visual,
    never a funnel implying a partition. ``agent_only`` and ``ghost`` render
    as a separate cross-cutting flag row. Absent bands/flags are omitted.

    Colors come only from the report's CSS variables via ``dg-*`` classes
    (the archify "cardinal rule"). Geometry is asserted inside the viewBox
    before returning -- the self-guard that replaces archify's fail-fast.
    """
    parts: list[str] = []
    y = _PAD

    # Nested bands, widest first. Each present inner band sits inside the
    # previous one's width so the nesting reads as containment.
    bands: list[tuple[str, int]] = [("All assets", data.total_assets)]
    if data.stale is not None:
        days = f" · no scan >{data.stale_days}d" if data.stale_days is not None else ""
        bands.append((f"Stale{days}", data.stale))
    if data.never_scanned is not None:
        days = f" >{data.never_scanned_days}d" if data.never_scanned_days is not None else ""
        # The subset glyph makes "never ⊆ stale" explicit, not a partition.
        bands.append((f"Never-scanned{days} ⊆ stale", data.never_scanned))

    n = len(bands)
    for i, (label, count) in enumerate(bands):
        # Each deeper band insets by a fixed step on the left, so containment
        # is visible without scaling to the (often tiny) count ratios.
        inset = i * 28
        x = _PAD + inset
        w = _VIEW_W - 2 * _PAD - inset
        cls = "dg-band-outer" if i == 0 else ("dg-band-warn" if i < n - 1 else "dg-band-fail")
        # Two-rect mask: opaque under styled (archify cardinal pattern).
        parts.append(f'<rect class="dg-mask" x="{x}" y="{y}" width="{w}" height="{_BAND_H}" rx="6"/>')
        parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="{w}" height="{_BAND_H}" rx="6"/>')
        parts.append(
            f'<text class="dg-label" x="{x + 12}" y="{y + 27}">{_esc(label)}</text>'
        )
        parts.append(
            f'<text class="dg-count" x="{x + w - 12}" y="{y + 27}" text-anchor="end">{_num(count)}</text>'
        )
        y += _BAND_H + _BAND_GAP

    # Cross-cutting flags row -- explicitly NOT bands (don't sum to the total).
    flags: list[tuple[str, int]] = []
    if data.agent_only is not None:
        flags.append(("agent-only", data.agent_only))
    if data.ghost is not None:
        flags.append(("ghost", data.ghost))

    if flags:
        y += 4
        parts.append(
            f'<text class="dg-note" x="{_PAD}" y="{y + 14}">Cross-cutting flags (overlap the bands above):</text>'
        )
        y += 24
        fx = _PAD
        for label, count in flags:
            chip = f"{label}: {_num(count)}"
            cw = 12 + len(chip) * 7
            parts.append(f'<rect class="dg-mask" x="{fx}" y="{y}" width="{cw}" height="{_FLAG_H}" rx="6"/>')
            parts.append(f'<rect class="dg-flag" x="{fx}" y="{y}" width="{cw}" height="{_FLAG_H}" rx="6"/>')
            parts.append(
                f'<text class="dg-chip" x="{fx + cw / 2:.0f}" y="{y + 20}" text-anchor="middle">{_esc(chip)}</text>'
            )
            fx += cw + 10
        y += _FLAG_H

    height = y + _PAD

    # Self-guard (archify fail-fast, ported): nothing may exceed the viewBox.
    if height <= 0 or _VIEW_W <= 0:
        raise ValueError("coverage diagram computed a non-positive viewBox")

    return _svg(parts, height, "Asset coverage threshold bands")


def _svg(parts: list[str], height: int, aria: str) -> str:
    """Wrap built shapes in the themed, dependency-free <svg> envelope.

    Self-guard (archify fail-fast, ported): a non-positive viewBox is a layout
    bug, not a degraded render -- raise rather than emit a broken figure.
    """
    if height <= 0 or _VIEW_W <= 0:
        raise ValueError(f"diagram computed a non-positive viewBox ({_VIEW_W}x{height})")
    body = "\n  ".join(parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_VIEW_W} {height}" '
        f'class="dg-figure" role="img" aria-label="{_esc(aria)}">\n  {body}\n</svg>'
    )


_ENGINE_H = 40
_ENGINE_GAP = 8
_POOL_PAD = 10


def build_topology_svg(data: TopologyData) -> str:
    """Build the engine-centric scan-topology SVG in columnar lanes.

    Left lane: the site population as aggregate buckets (paired total + an
    orphan bucket) -- never individual site boxes, so it scales to any console.
    Right lane: engines grouped under their pool header, each an aggregate card
    (site count · asset load, fail-styled when overloaded), plus an unpaired
    bucket. The lanes are fixed, so nodes stack in rows and never reflow as a
    free graph -- collision-free by construction. Colors come only from the
    report's CSS vars via ``dg-*`` classes.
    """
    parts: list[str] = []
    left_x = _PAD
    left_w = 150
    right_x = left_x + left_w + 60          # gap carries the "flows to" arrow
    right_w = _VIEW_W - _PAD - right_x

    # Lane headers.
    parts.append(f'<text class="dg-note" x="{left_x}" y="{_PAD + 4}">SITES</text>')
    parts.append(f'<text class="dg-note" x="{right_x}" y="{_PAD + 4}">SCAN ENGINES / POOLS</text>')

    y = _PAD + 18

    # Left lane: paired + orphan buckets.
    paired_label = f"Paired sites: {_num(data.total_paired_sites)}"
    parts.append(f'<rect class="dg-mask" x="{left_x}" y="{y}" width="{left_w}" height="{_ENGINE_H}" rx="6"/>')
    parts.append(f'<rect class="dg-band-outer" x="{left_x}" y="{y}" width="{left_w}" height="{_ENGINE_H}" rx="6"/>')
    parts.append(f'<text class="dg-label" x="{left_x + 10}" y="{y + 25}">{_esc(paired_label)}</text>')
    # The "flows to" connector into the right lane.
    arrow_y = y + _ENGINE_H // 2
    parts.append(
        f'<line class="dg-edge" x1="{left_x + left_w}" y1="{arrow_y}" '
        f'x2="{right_x - 6}" y2="{arrow_y}"/>'
    )
    y += _ENGINE_H + _ENGINE_GAP

    if data.orphan_site_count:
        orphan_label = f"Orphan sites (no engine): {_num(data.orphan_site_count)}"
        parts.append(f'<rect class="dg-mask" x="{left_x}" y="{y}" width="{left_w}" height="{_ENGINE_H}" rx="6"/>')
        parts.append(f'<rect class="dg-band-fail" x="{left_x}" y="{y}" width="{left_w}" height="{_ENGINE_H}" rx="6"/>')
        parts.append(f'<text class="dg-label" x="{left_x + 10}" y="{y + 18}">Orphan sites ⚠</text>')
        parts.append(f'<text class="dg-count" x="{left_x + 10}" y="{y + 33}" text-anchor="start">{_num(data.orphan_site_count)} no engine</text>')
        y += _ENGINE_H + _ENGINE_GAP

    # Right lane: engines grouped by pool, then standalone, then unpaired.
    ry = _PAD + 18
    pools: dict[str, list[EngineNode]] = {}
    standalone: list[EngineNode] = []
    for e in data.engines:
        if e.pool_name:
            pools.setdefault(e.pool_name, []).append(e)
        else:
            standalone.append(e)

    def _engine_card(e: EngineNode, x: int, w: int, yy: int) -> int:
        cls = "dg-engine-fail" if e.overloaded else "dg-engine"
        flag = " ⚠" if e.overloaded else ""
        parts.append(f'<rect class="dg-mask" x="{x}" y="{yy}" width="{w}" height="{_ENGINE_H}" rx="6"/>')
        parts.append(f'<rect class="{cls}" x="{x}" y="{yy}" width="{w}" height="{_ENGINE_H}" rx="6"/>')
        parts.append(f'<text class="dg-label" x="{x + 10}" y="{yy + 18}">{_esc(e.name)}{flag}</text>')
        sub = f"{_num(e.site_count)} sites · {_num(e.asset_load)} assets"
        parts.append(f'<text class="dg-count" x="{x + 10}" y="{yy + 33}" text-anchor="start">{_esc(sub)}</text>')
        return yy + _ENGINE_H + _ENGINE_GAP

    for pool_name, members in pools.items():
        box_top = ry
        inner_x = right_x + _POOL_PAD
        inner_w = right_w - 2 * _POOL_PAD
        # Remember where the member-card shapes will start so the pool boundary
        # can be inserted *before* them -- SVG paints in document order, so the
        # boundary must precede the cards to sit behind them.
        insert_at = len(parts)
        member_y = ry + 24
        for e in members:
            member_y = _engine_card(e, inner_x, inner_w, member_y)
        box_h = member_y - box_top
        parts.insert(
            insert_at,
            f'<rect class="dg-pool" x="{right_x}" y="{box_top}" width="{right_w}" height="{box_h}" rx="8"/>'
        )
        parts.insert(
            insert_at + 1,
            f'<text class="dg-note" x="{right_x + 10}" y="{box_top + 16}">Pool: {_esc(pool_name)}</text>'
        )
        ry = box_top + box_h + _ENGINE_GAP

    for e in standalone:
        ry = _engine_card(e, right_x, right_w, ry)

    if data.unpaired_engines:
        names = ", ".join(data.unpaired_engines)
        h = _ENGINE_H
        parts.append(f'<rect class="dg-mask" x="{right_x}" y="{ry}" width="{right_w}" height="{h}" rx="6"/>')
        parts.append(f'<rect class="dg-engine-warn" x="{right_x}" y="{ry}" width="{right_w}" height="{h}" rx="6"/>')
        parts.append(f'<text class="dg-label" x="{right_x + 10}" y="{ry + 18}">Unpaired engines ⚠</text>')
        parts.append(f'<text class="dg-count" x="{right_x + 10}" y="{ry + 33}" text-anchor="start">{_esc(names)}</text>')
        ry += h + _ENGINE_GAP

    height = max(y, ry) + _PAD
    return _svg(parts, height, "Scan engine topology")


# --- health status map ------------------------------------------------------


@dataclass(frozen=True)
class StatusRow:
    """One check's rule-status rollup for the health status map.

    ``error`` and ``skipped`` are kept distinct from pass/warn/fail because
    they are not health signals: error = the rule could not be evaluated,
    skipped = the rule is disabled. Folding either into "pass" would overstate
    health.
    """

    check_name: str
    rules_pass: int
    rules_warn: int
    rules_fail: int
    rules_error: int
    rules_skipped: int


def extract_status_map(results: list[CheckResult]):
    """One `StatusRow` per check that has `rule_results`, in render order.

    Reads only the already-computed per-rule statuses -- no API, no snapshot.
    Returns ``None`` when no check carries rule_results (a legacy/flat-only
    run), so the report omits the figure.
    """
    rows: list[StatusRow] = []
    for r in results:
        if not r.rule_results:
            continue
        rows.append(StatusRow(
            check_name=r.name,
            rules_pass=sum(1 for rr in r.rule_results if rr.status == "pass"),
            rules_warn=sum(1 for rr in r.rule_results if rr.status == "warn"),
            rules_fail=sum(1 for rr in r.rule_results if rr.status == "fail"),
            rules_error=sum(1 for rr in r.rule_results if rr.status == "error"),
            rules_skipped=sum(1 for rr in r.rule_results if rr.status == "skipped"),
        ))
    return rows or None


_ROW_H = 26
_ROW_GAP = 6
_NAME_W = 150
_LEGEND_H = 22

# Status -> segment class + legend label, in stack order (health first, then
# the non-signal states). Order is the draw order left-to-right.
_STATUS_SEGMENTS = [
    ("pass", "dg-seg-pass", "pass"),
    ("warn", "dg-seg-warn", "warn"),
    ("fail", "dg-seg-fail", "fail"),
    ("error", "dg-seg-error", "error"),
    ("skipped", "dg-seg-skipped", "skipped"),
]


def build_status_map_svg(rows: list[StatusRow]) -> str:
    """Build the health status map: one stacked bar per check.

    Each bar's segments are proportional to that check's rule-status counts;
    zero-count statuses emit no segment. Segment colors come from the report's
    status palette via ``dg-seg-*`` classes. error/skipped render with their
    own (non-health) colors so they never read as passing.
    """
    parts: list[str] = []
    bar_x = _PAD + _NAME_W + 10
    bar_w = _VIEW_W - _PAD - bar_x

    y = _PAD
    for row in rows:
        counts = {
            "pass": row.rules_pass, "warn": row.rules_warn, "fail": row.rules_fail,
            "error": row.rules_error, "skipped": row.rules_skipped,
        }
        total = sum(counts.values())
        # Check name (left), truncated by the column; right-aligned to the bar.
        parts.append(f'<text class="dg-label" x="{_PAD}" y="{y + 18}">{_esc(row.check_name)}</text>')
        # Track behind the segments so an all-zero row still reads as a bar.
        parts.append(f'<rect class="dg-mask" x="{bar_x}" y="{y}" width="{bar_w}" height="{_ROW_H}" rx="4"/>')
        parts.append(f'<rect class="dg-band-outer" x="{bar_x}" y="{y}" width="{bar_w}" height="{_ROW_H}" rx="4"/>')
        if total > 0:
            seg_x = bar_x
            for key, cls, _label in _STATUS_SEGMENTS:
                c = counts[key]
                if not c:
                    continue
                seg_w = bar_w * c / total
                parts.append(
                    f'<rect class="{cls}" x="{seg_x:.1f}" y="{y}" '
                    f'width="{seg_w:.1f}" height="{_ROW_H}"/>'
                )
                seg_x += seg_w
        # Count label after the bar's worst-status summary.
        summary = _status_summary(counts)
        parts.append(
            f'<text class="dg-count" x="{bar_x + bar_w - 6}" y="{y + 17}" '
            f'text-anchor="end">{_esc(summary)}</text>'
        )
        y += _ROW_H + _ROW_GAP

    # Legend row.
    y += 4
    lx = bar_x
    for _key, cls, label in _STATUS_SEGMENTS:
        parts.append(f'<rect class="{cls}" x="{lx}" y="{y}" width="11" height="11" rx="2"/>')
        parts.append(f'<text class="dg-note" x="{lx + 15}" y="{y + 10}">{label}</text>')
        lx += 22 + len(label) * 7
    y += _LEGEND_H

    height = y + _PAD
    return _svg(parts, height, "Health status by check")


def _status_summary(counts: dict[str, int]) -> str:
    """Compact 'N pass · N warn · N fail' label; omits zero buckets."""
    bits = [f"{counts[k]} {k}" for k in ("pass", "warn", "fail", "error", "skipped") if counts[k]]
    return " · ".join(bits) if bits else "no rules"
