from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rapid7_healthcheck.checks import CheckResult, Finding


_TEMPLATE_DIR = Path(__file__).parent / "templates"


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
    for r in results:
        for f in r.findings:
            if f.details is not None:
                # Pre-serialize so the template stays simple and safe (autoescape escapes the string).
                object.__setattr__(f, "details_json", json.dumps(f.details, indent=2, default=str))
            else:
                object.__setattr__(f, "details_json", "")


def render_report(ctx: ReportContext) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=False,
        lstrip_blocks=False,
    )
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
