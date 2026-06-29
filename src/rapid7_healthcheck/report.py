from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rapid7_healthcheck import diagrams, state_engine
from rapid7_healthcheck.audit.rule_rollup import rule_summary, worst_status
from rapid7_healthcheck.checks import CheckResult, Finding, findings_of

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _format_duration(ms: int | None) -> str:
    """Render a duration in human-readable form for the report.

    < 1 s -> "123 ms"
    < 1 m -> "4.2 s"
    < 1 h -> "2m 14s"
    >= 1h -> "1h 12m"
    """
    if ms is None:
        return "-"
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins}m"


def _humanize_key(key: str) -> str:
    """Turn a snake_case rule-summary key into a sentence-case label.

    `stale_assets_count` → "Stale assets count"
    `coverage_percent`   → "Coverage percent"
    `duplicate_ip_groups` → "Duplicate ip groups"
    """
    if not isinstance(key, str):
        return str(key)
    return key.replace("_", " ").strip().capitalize()


def _humanize_value(value) -> str:
    """Render a rule-summary value for the info-box, formatting numbers and
    booleans in a way that reads well in the UI. Strings are passed through
    so callers (e.g. the duplicate-detection skip reason) can supply a
    pre-formatted user-visible message."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return str(value)


def _metrics(results: list[CheckResult]) -> dict:
    """Roll up metric grid numbers from the list of CheckResults.

    Counts every rule across every check that has rule_results, and every
    finding from both rule_results-bearing checks and operational checks.
    """
    rules_total = rules_fail = rules_warn = rules_pass = rules_skipped = rules_error = rules_sampled = 0
    findings_total = findings_fail = findings_warn = 0
    total_duration_ms = 0

    # Rule-level counts come from `rule_summary` (the same rollup the runners
    # use to build each CheckResult.summary), summed across checks. Only
    # `rules_sampled` is added here -- `rule_summary` doesn't carry it.
    # Finding-level counts iterate `findings_of`, the single owner of the
    # rule_results-xor-top-level-findings walk; no xor branch re-typed here.
    for r in results:
        if r.duration_ms:
            total_duration_ms += r.duration_ms
        if r.rule_results:
            summary = rule_summary(r.rule_results)
            rules_total += summary["rules_total"]
            rules_fail += summary["rules_fail"]
            rules_warn += summary["rules_warn"]
            rules_pass += summary["rules_pass"]
            rules_skipped += summary["rules_skipped"]
            rules_error += summary["rules_error"]
            rules_sampled += sum(1 for rr in r.rule_results if rr.sampled)
        for _rule_id, f in findings_of(r):
            findings_total += 1
            if f.severity == "fail":
                findings_fail += 1
            elif f.severity == "warn":
                findings_warn += 1
    return {
        "rules_total": rules_total,
        "rules_fail": rules_fail,
        "rules_warn": rules_warn,
        "rules_pass": rules_pass,
        "rules_skipped": rules_skipped,
        "rules_error": rules_error,
        "rules_sampled": rules_sampled,
        "findings_total": findings_total,
        "findings_fail": findings_fail,
        "findings_warn": findings_warn,
        "total_duration_ms": total_duration_ms,
    }


_FINDING_BADGE_CSS = {"fail": "fail", "warn": "warn"}


def _severity_css(severity: str) -> str:
    """Map a finding's severity to its badge css class.

    `fail`/`warn` map to themselves; everything else (notably `info`) maps to
    the `pass`-styled badge. This is the template ternary that used to be spelled
    twice (the flat-fallback table and the per-rule findings table)."""
    return _FINDING_BADGE_CSS.get(severity, "pass")


@dataclass(frozen=True)
class RuleCardView:
    """The per-rule-card view-model -- the decisions the report template used to
    make inline, computed once in pure Python. See CONTEXT.md "RuleCardView"."""
    rule_id: str
    search_text: str
    changed: bool


def build_card_views(
    results: list[CheckResult], *, delta: dict | None
) -> dict[str, RuleCardView]:
    """Build one `RuleCardView` per rule card, keyed by `rule_id`.

    Pure: reads the live results plus the delta the render already holds. The
    `changed` set is resolved from `delta` (every delta finding carries its
    `rule_id`, attached by `state_engine.compute.index`), so the template stamps
    `data-changed` server-side and the JS need not re-walk the state blob.
    """
    changed_rule_ids: set[str] = set()
    if delta is not None:
        for key in ("resolved", "new_fails", "severity_changed"):
            for f in delta.get(key, []) or []:
                rid = f.get("rule_id")
                if rid is not None:
                    changed_rule_ids.add(rid)

    views: dict[str, RuleCardView] = {}
    for r in results:
        for rr in r.rule_results or []:
            messages = " ".join(f.message or "" for f in rr.findings)
            search_text = f"{rr.rule_name} {messages}".strip().lower()[:200]
            views[rr.rule_id] = RuleCardView(
                rule_id=rr.rule_id,
                search_text=search_text,
                changed=rr.rule_id in changed_rule_ids,
            )
    return views


def build_rail_counts(results: list[CheckResult]) -> list[dict[str, int]]:
    """Per-check ``{"fail": n, "warn": n}`` for the section rail, one entry per
    check in render order.

    Counts come from `findings_of` -- the canonical rule_results-xor-top-level
    walk -- not the `r.findings` flat mirror the rail template used to read via
    `selectattr`. The two usually agree, but the mirror can drift; reading the
    canonical population keeps the rail honest. See CONTEXT.md "Section rail"."""
    counts: list[dict[str, int]] = []
    for r in results:
        fail = warn = 0
        for _rule_id, f in findings_of(r):
            if f.severity == "fail":
                fail += 1
            elif f.severity == "warn":
                warn += 1
        counts.append({"fail": fail, "warn": warn})
    return counts


_SCAN_ENGINES_CHECK_NAME = "Scan Engines"


def build_section_diagrams(
    results: list[CheckResult],
    *,
    inventory_totals: "InventoryTotals | None",
    topology: "diagrams.TopologyData | None" = None,
) -> dict[str, str]:
    """Build per-check inline-SVG diagrams, keyed by check name.

    Pure: delegates to `diagrams.py` (which reads only numbers the run already
    holds -- no API). A check appears in the dict only when its diagram has
    honest inputs; the template emits `section_diagrams[r.name]` when present
    and omits it otherwise. See CONTEXT.md "Report diagram".
    """
    out: dict[str, str] = {}
    coverage = diagrams.extract_coverage_counts(results, inventory_totals)
    if coverage is not None:
        out[diagrams._COVERAGE_CHECK_NAME] = diagrams.build_coverage_svg(coverage)
    if topology is not None and topology.engines:
        out[_SCAN_ENGINES_CHECK_NAME] = diagrams.build_topology_svg(topology)
    return out


@dataclass(frozen=True)
class InventoryTotals:
    """At-a-glance inventory counters rendered at the top of the report."""
    total_assets: int
    total_sites: int
    total_scan_engines: int
    total_asset_groups_static: int
    total_asset_groups_dynamic: int
    total_scans: int


@dataclass(frozen=True)
class ReportContext:
    """The inputs a render needs. Inputs only -- the derived cross-run state
    (delta, state blob, content hash, metrics) is computed by
    `build_render_state` and returned as a `RenderState`, never mutated back
    onto the context. See CONTEXT.md "RenderState"."""
    title: str
    generated_at: datetime
    base_url_host: str
    tool_version: str
    config_path: str
    results: list[CheckResult]
    thresholds_table: list[tuple[str, str]] = field(default_factory=list)
    inventory_totals: "InventoryTotals | None" = None
    topology: "diagrams.TopologyData | None" = None


# The hero verdict for each worst-status outcome: (css-class, label). The
# status precedence itself lives once, in `worst_status` -- this is only the
# status->presentation mapping. `skipped`/`error` never reach here as a key:
# `worst_status` collapses the run to one of fail/warn/pass.
_VERDICT_BY_STATUS: dict[str, tuple[str, str]] = {
    "fail": ("fail", "Action required"),
    "warn": ("warn", "Warnings"),
    "pass": ("pass", "Healthy"),
}


def _verdict(results: list[CheckResult]) -> tuple[str, str]:
    return _VERDICT_BY_STATUS[worst_status(results)]


def _annotate_findings(results: list[CheckResult]) -> None:
    """Attach a pre-serialized JSON string for each finding's details.

    `Finding` is `frozen=True`, so attribute assignment is normally blocked.
    `object.__setattr__` bypasses that to attach a `details_json` slot used by
    the Jinja template. We pre-serialize here (rather than in the template) so
    autoescape treats the JSON as plain text -- `<` characters in details would
    otherwise break the HTML. The mutation is intentional and confined to the
    render path; downstream code does not rely on `Finding` immutability.
    """
    def annotate_one(f: Finding) -> None:
        if f.details is not None:
            object.__setattr__(f, "details_json", json.dumps(f.details, indent=2, default=str))
        else:
            object.__setattr__(f, "details_json", "")

    for r in results:
        for _rule_id, f in findings_of(r):
            annotate_one(f)


@dataclass(frozen=True)
class RenderState:
    """The cross-run state a render needs, computed once from a run's results.

    Bundles the four values the template reads that are derived (not given) --
    the trimmed state blob's serialized JSON, its content hash, the cross-run
    delta, and the metric rollup. Previously these were mutated onto
    `ReportContext` in a fixed-but-implicit order inside `render_report`; here
    the order lives in `build_render_state` and the result is immutable. See
    CONTEXT.md "RenderState".
    """
    blob_json: str | None
    content_hash: str | None
    delta: dict | None
    metrics: dict


def build_render_state(
    *,
    results: list[CheckResult],
    tool_version: str,
    generated_at: datetime,
    base_url_host: str,
    prior_state: dict | None,
) -> RenderState:
    """Compute the cross-run `RenderState` for a run.

    The single owner of the project -> serialize -> compute -> metrics
    sequence. `project` builds the trimmed state blob (None if oversized);
    serialization + the content hash follow only when the blob exists; the
    delta is computed only with both a blob and a `prior_state`; metrics are
    always computed. Pure -- no I/O, no HTML -- so it is testable without
    rendering. See CONTEXT.md "RenderState".
    """
    blob = state_engine.project(
        results=results,
        tool_version=tool_version,
        generated_at=generated_at,
        base_url_host=base_url_host,
    )
    if blob is not None:
        blob_json = json.dumps(blob, separators=(",", ":"), default=str)
        content_hash = hashlib.sha256(blob_json.encode("utf-8")).hexdigest()[:16]
    else:
        blob_json = None
        content_hash = None

    if blob is not None and prior_state is not None:
        delta = state_engine.compute(prior=prior_state, current=blob)
    else:
        delta = None

    return RenderState(
        blob_json=blob_json,
        content_hash=content_hash,
        delta=delta,
        metrics=_metrics(results),
    )


def render_report(ctx: ReportContext, *, prior_state: dict | None = None) -> str:
    """Render the report. If `prior_state` is supplied, compute a delta and
    embed both the delta strip and the trimmed state blob in the output."""
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    env.filters["duration"] = _format_duration
    env.filters["humanize_key"] = _humanize_key
    env.filters["humanize_value"] = _humanize_value
    env.filters["severity_css"] = _severity_css
    template = env.get_template("report.html.j2")
    _annotate_findings(ctx.results)
    verdict_class, verdict_label = _verdict(ctx.results)
    generated_at_local_str = ctx.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    generated_at_utc_str = ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")

    state = build_render_state(
        results=ctx.results,
        tool_version=ctx.tool_version,
        generated_at=ctx.generated_at,
        base_url_host=ctx.base_url_host,
        prior_state=prior_state,
    )
    card_views = build_card_views(ctx.results, delta=state.delta)
    rail_counts = build_rail_counts(ctx.results)
    section_diagrams = build_section_diagrams(
        ctx.results, inventory_totals=ctx.inventory_totals, topology=ctx.topology
    )

    return template.render(
        title=ctx.title,
        generated_at_utc=generated_at_utc_str,
        generated_at_local=generated_at_local_str,
        base_url_host=ctx.base_url_host,
        tool_version=ctx.tool_version,
        config_path=ctx.config_path,
        results=ctx.results,
        thresholds_table=ctx.thresholds_table,
        verdict_class=verdict_class,
        verdict_label=verdict_label,
        delta=state.delta,
        state_blob_json=state.blob_json,
        metrics=state.metrics,
        content_hash=state.content_hash,
        inventory_totals=ctx.inventory_totals,
        card_views=card_views,
        rail_counts=rail_counts,
        section_diagrams=section_diagrams,
    )


def write_report(
    ctx: ReportContext,
    *,
    output_dir: Path | None = None,
    filename_pattern: str | None = None,
    explicit_path: Path | None = None,
    delta_max_age_days: int | None = 30,
) -> Path:
    if explicit_path is not None:
        # Explicit-path mode: no delta (we have no convention for finding a prior).
        html = render_report(ctx)
        explicit_path.parent.mkdir(parents=True, exist_ok=True)
        explicit_path.write_text(html, encoding="utf-8")
        return explicit_path

    if output_dir is None or filename_pattern is None:
        raise ValueError(
            "write_report requires either explicit_path, or both output_dir and filename_pattern"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = filename_pattern.replace("{timestamp}", timestamp)
    out = output_dir / filename

    # Load prior state (if any) before rendering so the delta strip can render.
    prior = state_engine.load_prior(
        output_dir=output_dir,
        filename_pattern=filename_pattern,
        exclude=out,
        max_age_days=delta_max_age_days,
    )
    html = render_report(ctx, prior_state=prior)
    out.write_text(html, encoding="utf-8")
    return out
