from __future__ import annotations

import hashlib
import json
import re
import time
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


def _state_blob_projection(
    *,
    results: list[CheckResult],
    tool_version: str,
    generated_at: datetime,
    base_url_host: str,
    size_cap_bytes: int = 1_000_000,
) -> dict | None:
    """Build the trimmed JSON state blob embedded in the report.

    Used by:
      - the next run's delta computation (parsed via regex from the prior file),
      - the SHA-256 content hash shown in the footer.

    Drops the largest fields (`details`, `description`, `sources`) since those
    already exist in the rendered DOM. Returns None if the projection exceeds
    `size_cap_bytes` — the report still renders without it; delta will simply
    not compute next run.
    """
    def project_finding(rule_id: str, idx: int, f: Finding) -> dict:
        return {
            "id": f"{rule_id}#{idx}",
            "signature": _finding_signature(rule_id, f),
            "severity": f.severity,
            "message_short": (f.message or "")[:200],
        }

    projected_results = []
    for r in results:
        rr_list = []
        if r.rule_results:
            for rr in r.rule_results:
                rr_list.append({
                    "rule_id": rr.rule_id,
                    "rule_name": rr.rule_name,
                    "status": rr.status,
                    "severity": rr.severity,
                    "duration_ms": rr.duration_ms,
                    "finding_count": len(rr.findings),
                    "findings": [
                        project_finding(rr.rule_id, i, f) for i, f in enumerate(rr.findings)
                    ],
                    "error": rr.error,
                    "error_path": rr.error_path,
                    "error_status_code": rr.error_status_code,
                })
        check_findings = [
            project_finding(r.name, i, f) for i, f in enumerate(r.findings)
        ]
        projected_results.append({
            "name": r.name,
            "status": r.status,
            "duration_ms": r.duration_ms,
            "findings": check_findings,
            "rule_results": rr_list,
        })

    blob = {
        "tool_version": tool_version,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_url_host": base_url_host,
        "results": projected_results,
    }
    serialized = json.dumps(blob, separators=(",", ":"), default=str)
    if len(serialized.encode("utf-8")) > size_cap_bytes:
        return None
    return blob


def _compute_delta(*, prior: dict | None, current: dict) -> dict | None:
    """Diff two state blobs. Returns None when no comparable prior exists.

    Skips silently on host mismatch (filename collision protection).
    Tolerates version skew: unknown rule_ids in current count as new findings,
    not as resolutions. Conservative — never claims something was resolved
    when we can't verify the prior actually checked for it.

    Returns:
        {
          "prior_generated_at": str,
          "resolved":          list[finding_projection],
          "new_fails":         list[finding_projection],
          "severity_changed":  list[finding_projection],
        }
    """
    if prior is None:
        return None
    if prior.get("base_url_host") != current.get("base_url_host"):
        return None

    def index(state: dict) -> dict[str, dict]:
        """Map signature -> finding-projection (with rule_id attached)."""
        out: dict[str, dict] = {}
        for r in state.get("results", []):
            check_name = r.get("name")
            # Audit-rule findings.
            for rr in r.get("rule_results", []) or []:
                rule_id = rr.get("rule_id")
                for f in rr.get("findings", []):
                    sig = f.get("signature")
                    if sig:
                        out[sig] = {**f, "rule_id": rule_id}
            # Operational-check top-level findings (use check_name as namespace).
            for f in r.get("findings", []) or []:
                sig = f.get("signature")
                if sig:
                    out[sig] = {**f, "rule_id": check_name}
        return out

    prior_idx = index(prior)
    cur_idx = index(current)

    resolved = [v for sig, v in prior_idx.items() if sig not in cur_idx]
    new_fails = [
        v for sig, v in cur_idx.items()
        if sig not in prior_idx and v.get("severity") == "fail"
    ]
    severity_changed = [
        cur_idx[sig] for sig in cur_idx
        if sig in prior_idx and cur_idx[sig].get("severity") != prior_idx[sig].get("severity")
    ]
    return {
        "prior_generated_at": prior.get("generated_at"),
        "resolved": resolved,
        "new_fails": new_fails,
        "severity_changed": severity_changed,
    }


_STATE_BLOB_RE = re.compile(
    r'<script id="report-state" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def _load_prior_state(
    *,
    output_dir: Path,
    filename_pattern: str,
    exclude: Path,
    max_age_days: int | None,
) -> dict | None:
    """Find the most recent report file in `output_dir` (excluding `exclude`),
    parse its embedded JSON state blob, and return the dict.

    Returns None on any failure: no candidates, all stale, parse error, or
    missing script tag. All failure modes are silent — the caller should treat
    None as "no comparable prior, don't render the delta strip."

    `max_age_days=None` disables the age filter (still excludes `exclude`).
    """
    if not output_dir.exists():
        return None

    # Discover candidate files: same extension, same prefix as filename_pattern.
    # We don't try to fully parse the pattern; we use the suffix after the last
    # "{timestamp}" placeholder as the extension and the prefix before it as
    # the name root. If the pattern has no placeholder, glob the whole pattern.
    if "{timestamp}" in filename_pattern:
        prefix, _, suffix = filename_pattern.partition("{timestamp}")
        glob = f"{prefix}*{suffix}"
    else:
        glob = filename_pattern

    candidates = [p for p in output_dir.glob(glob) if p.resolve() != exclude.resolve()]
    if not candidates:
        return None

    if max_age_days is not None:
        now = time.time()
        max_age_seconds = max_age_days * 86400
        candidates = [p for p in candidates if (now - p.stat().st_mtime) <= max_age_seconds]
        if not candidates:
            return None

    # Most recent by mtime.
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    most_recent = candidates[0]

    try:
        text = most_recent.read_text(encoding="utf-8")
    except OSError:
        return None

    m = _STATE_BLOB_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return None


def _metrics(results: list[CheckResult]) -> dict:
    """Roll up metric grid numbers from the list of CheckResults.

    Counts every rule across every check that has rule_results, and every
    finding from both rule_results-bearing checks and operational checks.
    """
    rules_total = rules_fail = rules_warn = rules_pass = rules_skipped = rules_error = rules_sampled = 0
    findings_total = findings_fail = findings_warn = 0
    total_duration_ms = 0

    for r in results:
        if r.duration_ms:
            total_duration_ms += r.duration_ms
        # Top-level findings (operational checks).
        for f in r.findings:
            findings_total += 1
            if f.severity == "fail":
                findings_fail += 1
            elif f.severity == "warn":
                findings_warn += 1
        if r.rule_results:
            for rr in r.rule_results:
                rules_total += 1
                if rr.status == "fail":
                    rules_fail += 1
                elif rr.status == "warn":
                    rules_warn += 1
                elif rr.status == "pass":
                    rules_pass += 1
                elif rr.status == "skipped":
                    rules_skipped += 1
                elif rr.status == "error":
                    rules_error += 1
                if rr.sampled:
                    rules_sampled += 1
                for f in rr.findings:
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
    template = env.get_template("report.html.j2")
    _annotate_findings(ctx.results)
    verdict_class, verdict_label = _verdict(ctx.results)
    generated_at_local_str = ctx.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    generated_at_utc_str = ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")

    # Build the trimmed state blob (may be None if oversized).
    blob = _state_blob_projection(
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
        ctx.delta = _compute_delta(prior=prior_state, current=blob)
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
    prior = _load_prior_state(
        output_dir=output_dir,
        filename_pattern=filename_pattern,
        exclude=out,
        max_age_days=delta_max_age_days,
    )
    html = render_report(ctx, prior_state=prior)
    out.write_text(html, encoding="utf-8")
    return out
