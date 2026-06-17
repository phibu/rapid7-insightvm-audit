"""Cross-run delta engine — lifted out of report.py so deltas are testable
without rendering HTML.

The report embeds a *trimmed projection* of each run (signatures + severity +
short message — never the full `details`) in a
`<script id="report-state" type="application/json">` blob, capped at 1 MB. The
next run extracts that prior blob, diffs it against the current projection, and
renders a "what changed" strip. This module owns that whole machinery; report.py
owns only rendering.

Interface (the small public surface other modules / tests use):

  - ``finding_signature(rule_id, finding)`` — stable hash matching a finding
    across runs.
  - ``project(results, *, ...)`` — build the trimmed state blob (or None if it
    exceeds the size cap).
  - ``compute(prior, current)`` — diff two state blobs into a delta (or None).
  - ``load_prior(output_dir, *, ...)`` — discover the most recent prior report
    file and return its embedded blob (or None).
  - ``extract_blob_from_html(text)`` — the single HTML adapter at the seam:
    pull the embedded JSON blob back out of a rendered report.

``compute`` and ``project`` take/return plain dicts, so prior→delta is unit
-testable by passing an in-memory prior dict directly — no render-to-disk-then
-regex-parse round trip. ``load_prior`` is the file-I/O adapter (the
local-substitutable dependency); ``extract_blob_from_html`` is the lone
HTML-coupling point.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

from rapid7_healthcheck.checks import CheckResult, Finding


def finding_signature(rule_id: str, finding: Finding) -> str:
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


def project(
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
            "signature": finding_signature(rule_id, f),
            "severity": f.severity,
            "message_short": (f.message or "")[:200],
        }

    # This keeps its own rule_results loop because it needs the per-rule
    # enumeration index for each finding's `id` (`{rule_id}#{idx}`), which the
    # flat `checks.findings_of` iterator does not carry. The finding xor-walk
    # invariant it encodes lives canonically in `checks.findings_of`.
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
        # Project top-level findings only when there are no rule_results.
        # Every modern check has rule_results; r.findings is a flattened mirror
        # of those rules' findings, so projecting it again would double-count.
        if r.rule_results:
            check_findings: list[dict] = []
        else:
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


def compute(*, prior: dict | None, current: dict) -> dict | None:
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
        """Map signature -> finding-projection (with rule_id attached).

        Walks the *deserialized* prior/current blob (plain dicts), so it cannot
        use `checks.findings_of` (which takes a live CheckResult). It re-encodes
        the same xor-walk invariant — see `checks.findings_of` for the canonical
        statement of why the top-level mirror must not be indexed too.

        Every check now produces rule_results, so we index findings out of
        rule_results only. The top-level `r.findings` is a flattened mirror —
        indexing it would double-count each finding under check_name.

        Pre-0.2.6 reports stored op-check findings only at the top level; for
        backwards compatibility, we fall back to top-level findings when a
        check has no rule_results.
        """
        out: dict[str, dict] = {}
        for r in state.get("results", []):
            check_name = r.get("name")
            rule_results = r.get("rule_results") or []
            if rule_results:
                for rr in rule_results:
                    rule_id = rr.get("rule_id")
                    for f in rr.get("findings", []):
                        sig = f.get("signature")
                        if sig:
                            out[sig] = {**f, "rule_id": rule_id}
            else:
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


STATE_BLOB_RE = re.compile(
    r'<script id="report-state" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def extract_blob_from_html(text: str) -> dict | None:
    """Pull the embedded state blob back out of a rendered report's HTML.

    This is the single HTML-coupling adapter at the prior-state seam: file
    discovery and staleness live in ``load_prior``; the *format* of the embed
    is known only here. Returns None when no blob is present or the JSON is
    unparseable (both silent — caller treats None as "no comparable prior").
    """
    m = STATE_BLOB_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return None


def load_prior(
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

    File discovery + staleness live here; the HTML→blob step is delegated to
    ``extract_blob_from_html`` so the only format-coupling lives in one place.
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

    return extract_blob_from_html(text)
