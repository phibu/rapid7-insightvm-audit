from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rapid7_healthcheck import state_engine
from rapid7_healthcheck.audit.rule_rollup import rule_summary
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
    # `rules_sampled` is added here — `rule_summary` doesn't carry it.
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


@dataclass(frozen=True)
class InventoryTotals:
    """At-a-glance inventory counters rendered at the top of the report."""
    total_assets: int
    total_sites: int
    total_scan_engines: int
    total_asset_groups_static: int
    total_asset_groups_dynamic: int
    total_scans: int


@dataclass
class ReportContext:
    title: str
    generated_at: datetime
    base_url_host: str
    tool_version: str
    config_path: str
    results: list[CheckResult]
    thresholds_table: list[tuple[str, str]] = field(default_factory=list)
    delta: dict | None = None              # computed delta or None
    state_blob_json: str | None = None     # pre-serialized JSON for embedding, or None if dropped
    metrics: dict | None = None            # populated by render_report
    content_hash: str | None = None        # SHA-256 prefix of state_blob_json
    inventory_totals: "InventoryTotals | None" = None


def _verdict(results: list[CheckResult]) -> tuple[str, str]:
    if any(r.status in ("fail", "error") for r in results):
        return ("fail", "Action required")
    if any(r.status == "warn" for r in results):
        return ("warn", "Warnings")
    return ("pass", "Healthy")


def _annotate_findings(results: list[CheckResult]) -> None:
    """Attach a pre-serialized JSON string for each finding's details.

    `Finding` is `frozen=True`, so attribute assignment is normally blocked.
    `object.__setattr__` bypasses that to attach a `details_json` slot used by
    the Jinja template. We pre-serialize here (rather than in the template) so
    autoescape treats the JSON as plain text — `<` characters in details would
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
    template = env.get_template("report.html.j2")
    _annotate_findings(ctx.results)
    verdict_class, verdict_label = _verdict(ctx.results)
    generated_at_local_str = ctx.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    generated_at_utc_str = ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")

    # Build the trimmed state blob (may be None if oversized).
    blob = state_engine.project(
        results=ctx.results,
        tool_version=ctx.tool_version,
        generated_at=ctx.generated_at,
        base_url_host=ctx.base_url_host,
    )
    if blob is not None:
        ctx.state_blob_json = json.dumps(blob, separators=(",", ":"), default=str)
        ctx.content_hash = hashlib.sha256(ctx.state_blob_json.encode("utf-8")).hexdigest()[:16]
    else:
        ctx.state_blob_json = None
        ctx.content_hash = None

    # Compute delta (None if no prior, host mismatch, or blob is None).
    if blob is not None and prior_state is not None:
        ctx.delta = state_engine.compute(prior=prior_state, current=blob)
    else:
        ctx.delta = None

    ctx.metrics = _metrics(ctx.results)

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
        delta=ctx.delta,
        state_blob_json=ctx.state_blob_json,
        metrics=ctx.metrics,
        content_hash=ctx.content_hash,
        inventory_totals=ctx.inventory_totals,
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
