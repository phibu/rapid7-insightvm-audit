from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rapid7_healthcheck.checks import CheckResult, Finding


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


def _finding_signature(rule_id: str, finding: Finding) -> str:
    """Stable 16-char hex hash of (rule_id, message, details).

    Used to match the same finding across two runs of the report. Severity is
    intentionally excluded so a finding that flips warn->fail (or back) gets
    counted in the "severity changed" delta, not as one resolved + one new.
    Details are normalized via JSON with sorted keys so dict ordering doesn't
    affect the signature.
    """
    details_norm = json.dumps(finding.details or {}, sort_keys=True, default=str)
    payload = f"{rule_id}\x00{finding.message}\x00{details_norm}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class ReportContext:
    title: str
    generated_at: datetime
    base_url_host: str
    tool_version: str
    config_path: str
    results: list[CheckResult]
    thresholds_table: list[tuple[str, str]] = field(default_factory=list)


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
        for f in r.findings:
            annotate_one(f)
        if r.rule_results:
            for rr in r.rule_results:
                for f in rr.findings:
                    annotate_one(f)


def render_report(ctx: ReportContext) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    env.filters["duration"] = _format_duration
    template = env.get_template("report.html.j2")
    _annotate_findings(ctx.results)
    verdict_class, verdict_label = _verdict(ctx.results)
    generated_at_local_str = ctx.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    generated_at_utc_str = ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")
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
    )


def write_report(
    ctx: ReportContext,
    *,
    output_dir: Path | None = None,
    filename_pattern: str | None = None,
    explicit_path: Path | None = None,
) -> Path:
    html = render_report(ctx)
    if explicit_path is not None:
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
    out.write_text(html, encoding="utf-8")
    return out
