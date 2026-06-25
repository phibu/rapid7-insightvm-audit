# Report UI/UX Rework -- Phase 1 Implementation Plan (0.1.9)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current single-block HTML report with a hybrid editorial + dashboard layout (hero verdict, conditional delta strip, metric grid, restyled per-category sections), light + dark mode via system preference, and an embedded trimmed JSON state blob that the next run uses to compute deltas. No JS interactivity layer in this phase -- that ships in 0.2.0.

**Architecture:** All changes confined to `report.py`, `templates/report.html.j2`, `config.py`, and tests. Add three pure helpers in `report.py` (`_finding_signature`, `_state_blob_projection`, `_compute_delta`) plus one I/O helper (`_load_prior_state`). Wire them through `render_report` so the template gets new context fields (`delta`, `state_blob_json`, `metrics`). Replace the template wholesale; preserve every existing tested behavior (verdicts, sampling notes, durations, error messages, source links, threshold table, no external resources). Add a `_build_report_config` validator to `config.py` so the new `delta_max_age_days` field is optional in YAML and existing configs keep loading.

**Tech Stack:** Python 3.11+, Jinja2 (already in use), `hashlib` and `json` from stdlib, pytest. No new dependencies.

---

## File Structure

| Path | Responsibility |
|---|---|
| `src/rapid7_healthcheck/report.py` | Add: signature/projection/delta/prior-load helpers, content-hash, metrics rollup, expanded `ReportContext` fields. Modify: `render_report` to populate new context. |
| `src/rapid7_healthcheck/templates/report.html.j2` | Full rewrite -- new IA, light+dark CSS, embedded state blob, print CSS. Native `<details>` for rule expansion (no JS yet). |
| `src/rapid7_healthcheck/config.py` | Add `delta_max_age_days: int \| None` to `ReportConfig`. Add `_build_report_config` so the field is optional in YAML. |
| `docs/examples/config.yaml` | Add `delta_max_age_days: 30` under `report:` with a comment. |
| `tests/test_report.py` | Update `test_no_external_resources` to allow inline JSON `<script>` while still forbidding external `src=`. Update `test_renders_pass_verdict_when_all_pass` to match new verdict text if needed. |
| `tests/test_report_state_blob.py` *(new)* | Tests for `_finding_signature`, `_state_blob_projection`, size cap. |
| `tests/test_report_delta.py` *(new)* | 7 tests: no-prior, all-resolved, new-fail, severity-changed, stale-prior, version-skew, host-mismatch. |
| `tests/test_config.py` | Add tests: `delta_max_age_days` defaults to 30 when absent; rejects unknown keys under `report:`; accepts `null` to disable delta. |
| `CHANGELOG.md` | Add 0.1.9 entry. |
| `pyproject.toml` | Bump version to `0.1.9`. |

---

## Task 1: Add `delta_max_age_days` field with backward-compatible YAML loader

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:27-31` (ReportConfig dataclass)
- Modify: `src/rapid7_healthcheck/config.py:358` (replace `_from_dict(ReportConfig, ...)` call with `_build_report_config(...)`)
- Modify: `tests/test_config.py` (add 3 tests)

- [ ] **Step 1.1: Write failing test for default value when key absent**

Append to `tests/test_config.py`:

```python
def test_report_delta_max_age_days_defaults_to_30(tmp_path):
    """Existing configs without delta_max_age_days still load, defaulting to 30."""
    cfg_text = """
rapid7:
  base_url: https://us.api.insight.rapid7.com
  request_timeout_seconds: 30
  max_retries: 3
  retry_backoff_seconds: 2.0
  page_size: 500
report:
  output_dir: ./reports
  filename_pattern: "report-{timestamp}.html"
  title: "Test"
thresholds:
  scan_engines:
    last_contact_warn_hours: 2
    last_contact_fail_hours: 24
  scan_activity:
    stuck_warn_hours: 4
    stuck_fail_hours: 24
    backlog_warn_count: 50
    backlog_fail_count: 200
  asset_coverage:
    stale_warn_days: 14
    stale_fail_days: 30
  data_quality:
    untagged_warn_pct: 10
    missing_os_warn_pct: 5
    duplicate_pairs_warn: 50
checks:
  scan_engines: true
  scan_activity: true
  asset_coverage: true
  data_quality: true
"""
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    from rapid7_healthcheck.config import load_config
    cfg = load_config(p)
    assert cfg.report.delta_max_age_days == 30
```

If `tests/test_config.py` already imports `load_config`, skip the inline import. Match the file's existing helper style if it has one.

- [ ] **Step 1.2: Run test, verify it fails**

```bash
pytest tests/test_config.py::test_report_delta_max_age_days_defaults_to_30 -v
```

Expected: FAIL with `AttributeError: 'ReportConfig' object has no attribute 'delta_max_age_days'` or `unknown key(s): ['delta_max_age_days']` depending on order.

- [ ] **Step 1.3: Add the field to `ReportConfig`**

Edit `src/rapid7_healthcheck/config.py` lines 27-31:

```python
@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str
    delta_max_age_days: int | None = 30
```

- [ ] **Step 1.4: Add `_build_report_config` so the new field is optional in YAML**

Insert this function in `src/rapid7_healthcheck/config.py` directly above `_build_app_config` (around line 340):

```python
def _build_report_config(data: Any) -> ReportConfig:
    """Validate the `report:` block, allowing `delta_max_age_days` to be absent.

    Accepts:
      - missing key  -> default 30
      - integer >= 0 -> use as-is
      - null/None    -> delta disabled
    Rejects unknown keys (consistent with `_from_dict`).
    """
    if not isinstance(data, dict):
        raise ConfigError(f"report: expected mapping, got {type(data).__name__}")
    expected = {"output_dir", "filename_pattern", "title", "delta_max_age_days"}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"report: unknown key(s): {sorted(unknown)}")
    required = {"output_dir", "filename_pattern", "title"}
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"report: missing required key(s): {sorted(missing)}")
    for k in ("output_dir", "filename_pattern", "title"):
        if not isinstance(data[k], str):
            raise ConfigError(f"report.{k}: expected str")
    delta = data.get("delta_max_age_days", 30)
    if delta is not None and (not isinstance(delta, int) or isinstance(delta, bool) or delta < 0):
        raise ConfigError("report.delta_max_age_days: expected non-negative int or null")
    return ReportConfig(
        output_dir=data["output_dir"],
        filename_pattern=data["filename_pattern"],
        title=data["title"],
        delta_max_age_days=delta,
    )
```

- [ ] **Step 1.5: Replace the `_from_dict` call site for ReportConfig**

In `src/rapid7_healthcheck/config.py` line 358, change:

```python
report = _from_dict(ReportConfig, data["report"], "report")
```

to:

```python
report = _build_report_config(data["report"])
```

- [ ] **Step 1.6: Run the new test, verify it passes**

```bash
pytest tests/test_config.py::test_report_delta_max_age_days_defaults_to_30 -v
```

Expected: PASS.

- [ ] **Step 1.7: Add tests for explicit values and rejection of unknown keys**

Append to `tests/test_config.py`:

```python
def test_report_delta_max_age_days_can_be_disabled(tmp_path):
    """delta_max_age_days: null disables delta (loads as None)."""
    from rapid7_healthcheck.config import load_config
    cfg_text = _MINIMAL_CONFIG_TEXT + "  delta_max_age_days: null\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.report.delta_max_age_days is None


def test_report_rejects_unknown_key(tmp_path):
    """Unknown keys under report: raise ConfigError."""
    from rapid7_healthcheck.config import load_config, ConfigError
    cfg_text = _MINIMAL_CONFIG_TEXT + "  bogus: 1\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    import pytest
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(p)


def test_report_rejects_negative_delta(tmp_path):
    """delta_max_age_days must be non-negative or null."""
    from rapid7_healthcheck.config import load_config, ConfigError
    cfg_text = _MINIMAL_CONFIG_TEXT + "  delta_max_age_days: -1\n"
    p = tmp_path / "c.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    import pytest
    with pytest.raises(ConfigError, match="non-negative"):
        load_config(p)
```

If `_MINIMAL_CONFIG_TEXT` doesn't already exist in the test file, extract it from the test in step 1.1 -- pull everything up through the `report:` block (so the appended line lands inside it) into a module-level constant.

- [ ] **Step 1.8: Run the new tests + the full config suite**

```bash
pytest tests/test_config.py -v
```

Expected: all PASS, no regressions.

- [ ] **Step 1.9: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "feat(config): add report.delta_max_age_days (default 30, optional in YAML)"
```

---

## Task 2: Update `docs/examples/config.yaml` with the new field

**Files:**
- Modify: `docs/examples/config.yaml` (under the `report:` block)

- [ ] **Step 2.1: Add the field with a comment**

Read the file first to find the `report:` block. Insert the new line at the end of that block (preserving indentation, typically 2 spaces):

```yaml
  # How many days back to compare against a prior report when computing the
  # "since last run" delta strip. null disables the feature.
  delta_max_age_days: 30
```

- [ ] **Step 2.2: Sanity-check the file still loads**

```bash
python -c "from rapid7_healthcheck.config import load_config; load_config('docs/examples/config.yaml'); print('ok')"
```

Expected: `ok`. (The example config may use a placeholder API URL -- that's fine, this test only validates schema loading, not network calls.)

- [ ] **Step 2.3: Commit**

```bash
git add docs/examples/config.yaml
git commit -m "docs(config): document report.delta_max_age_days"
```

---

## Task 3: Implement `_finding_signature` (pure function)

**Files:**
- Modify: `src/rapid7_healthcheck/report.py` (add helper near top, after `_format_duration`)
- Test: `tests/test_report_state_blob.py` (new)

A finding's signature is a stable hash of `(rule_id, message, sorted-details-tuple)`. Same finding across runs → same signature. New asset triggering same rule → different signature (because details differ). Used to key the diff sets in Task 5.

- [ ] **Step 3.1: Write failing tests**

Create `tests/test_report_state_blob.py`:

```python
from __future__ import annotations

from rapid7_healthcheck.checks import Finding


def test_finding_signature_stable_across_calls():
    from rapid7_healthcheck.report import _finding_signature
    f = Finding(severity="fail", message="port 22 exposed", details={"asset": "web-1", "port": 22})
    assert _finding_signature("ssh_open", f) == _finding_signature("ssh_open", f)


def test_finding_signature_changes_with_rule_id():
    from rapid7_healthcheck.report import _finding_signature
    f = Finding(severity="fail", message="m", details={"k": 1})
    assert _finding_signature("rule_a", f) != _finding_signature("rule_b", f)


def test_finding_signature_changes_with_message():
    from rapid7_healthcheck.report import _finding_signature
    f1 = Finding(severity="fail", message="m1", details={"k": 1})
    f2 = Finding(severity="fail", message="m2", details={"k": 1})
    assert _finding_signature("r", f1) != _finding_signature("r", f2)


def test_finding_signature_changes_with_details():
    from rapid7_healthcheck.report import _finding_signature
    f1 = Finding(severity="fail", message="m", details={"asset": "host-a"})
    f2 = Finding(severity="fail", message="m", details={"asset": "host-b"})
    assert _finding_signature("r", f1) != _finding_signature("r", f2)


def test_finding_signature_independent_of_details_key_order():
    from rapid7_healthcheck.report import _finding_signature
    f1 = Finding(severity="fail", message="m", details={"a": 1, "b": 2})
    f2 = Finding(severity="fail", message="m", details={"b": 2, "a": 1})
    assert _finding_signature("r", f1) == _finding_signature("r", f2)


def test_finding_signature_handles_none_details():
    from rapid7_healthcheck.report import _finding_signature
    f = Finding(severity="warn", message="m")
    sig = _finding_signature("r", f)
    assert isinstance(sig, str) and len(sig) >= 8


def test_finding_signature_independent_of_severity():
    """Same finding promoted from warn to fail keeps its signature -- this is what
    lets us detect a 'severity changed' delta rather than counting it as a new
    finding plus a resolved one."""
    from rapid7_healthcheck.report import _finding_signature
    f1 = Finding(severity="warn", message="m", details={"k": 1})
    f2 = Finding(severity="fail", message="m", details={"k": 1})
    assert _finding_signature("r", f1) == _finding_signature("r", f2)
```

- [ ] **Step 3.2: Run tests, verify they fail**

```bash
pytest tests/test_report_state_blob.py -v
```

Expected: 7 FAIL with `ImportError: cannot import name '_finding_signature'`.

- [ ] **Step 3.3: Implement `_finding_signature`**

Add to `src/rapid7_healthcheck/report.py` after `_format_duration` (after line 35):

```python
def _finding_signature(rule_id: str, finding: Finding) -> str:
    """Stable 16-char hex hash of (rule_id, message, details).

    Used to match the same finding across two runs of the report. Severity is
    intentionally excluded so a finding that flips warn->fail (or back) gets
    counted in the "severity changed" delta, not as one resolved + one new.
    Details are normalized via JSON with sorted keys so dict ordering doesn't
    affect the signature.
    """
    import hashlib
    details_norm = json.dumps(finding.details or {}, sort_keys=True, default=str)
    payload = f"{rule_id}\x00{finding.message}\x00{details_norm}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
```

- [ ] **Step 3.4: Run tests, verify they pass**

```bash
pytest tests/test_report_state_blob.py -v
```

Expected: 7 PASS.

- [ ] **Step 3.5: Commit**

```bash
git add src/rapid7_healthcheck/report.py tests/test_report_state_blob.py
git commit -m "feat(report): add _finding_signature for cross-run delta keying"
```

---

## Task 4: Implement `_state_blob_projection` with size cap

**Files:**
- Modify: `src/rapid7_healthcheck/report.py` (add helper near other private helpers)
- Modify: `tests/test_report_state_blob.py` (extend)

The trimmed projection that goes into `<script id="report-state">`. Drops `details` from findings (already in DOM), drops `description`/`sources` from rules (already in DOM). 1 MB hard cap drops the blob entirely if exceeded.

- [ ] **Step 4.1: Write failing tests**

Append to `tests/test_report_state_blob.py`:

```python
import json as _json
from datetime import datetime, timezone
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.audit import RuleResult


def test_state_blob_projection_shape():
    from rapid7_healthcheck.report import _state_blob_projection
    rr = RuleResult(
        rule_id="r1", rule_name="Rule One", description="desc",
        severity="warn", status="warn", duration_ms=120,
        findings=[
            Finding(severity="warn", message="hello", details={"k": "v" * 500}),
        ],
        sources=["https://example.com/doc"],
    )
    cr = CheckResult(
        name="Audit", description="d", status="warn",
        rule_results=[rr],
        findings=[],
    )
    blob = _state_blob_projection(
        results=[cr],
        tool_version="0.1.9",
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=timezone.utc),
        base_url_host="example",
    )
    assert blob["tool_version"] == "0.1.9"
    assert blob["generated_at"].startswith("2026-04-29")
    assert blob["base_url_host"] == "example"
    assert len(blob["results"]) == 1
    rb = blob["results"][0]["rule_results"][0]
    # Trimmed: no description, no sources on rules.
    assert "description" not in rb
    assert "sources" not in rb
    # Per-finding projection: signature + severity + short message + id.
    assert "details" not in rb["findings"][0]
    assert "signature" in rb["findings"][0]
    assert "severity" in rb["findings"][0]
    assert "message_short" in rb["findings"][0]
    assert "id" in rb["findings"][0]


def test_state_blob_projection_truncates_long_messages():
    from rapid7_healthcheck.report import _state_blob_projection
    long = "x" * 500
    cr = CheckResult(
        name="X", description="d", status="warn",
        findings=[Finding(severity="warn", message=long)],
    )
    blob = _state_blob_projection(
        results=[cr],
        tool_version="t", generated_at=datetime.now(timezone.utc), base_url_host="h",
    )
    assert len(blob["results"][0]["findings"][0]["message_short"]) == 200


def test_state_blob_projection_size_cap_drops_blob():
    """Projected blob > 1 MB returns None instead of the dict."""
    from rapid7_healthcheck.report import _state_blob_projection
    # Build something huge: 5000 findings with ~250 char messages.
    findings = [Finding(severity="fail", message="m" * 250) for _ in range(5000)]
    cr = CheckResult(
        name="X", description="d", status="fail",
        rule_results=[
            RuleResult(
                rule_id="r1", rule_name="r", description="d",
                severity="fail", status="fail",
                findings=findings,
            )
        ],
        findings=[],
    )
    blob = _state_blob_projection(
        results=[cr],
        tool_version="t", generated_at=datetime.now(timezone.utc), base_url_host="h",
        size_cap_bytes=1_000_000,
    )
    assert blob is None
```

- [ ] **Step 4.2: Run tests, verify they fail**

```bash
pytest tests/test_report_state_blob.py -v -k "projection"
```

Expected: 3 FAIL with `ImportError: cannot import name '_state_blob_projection'`.

- [ ] **Step 4.3: Implement `_state_blob_projection`**

Add to `src/rapid7_healthcheck/report.py` after `_finding_signature`:

```python
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
    `size_cap_bytes` -- the report still renders without it; delta will simply
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
```

- [ ] **Step 4.4: Run tests, verify they pass**

```bash
pytest tests/test_report_state_blob.py -v
```

Expected: all PASS (10 total in this file now).

- [ ] **Step 4.5: Commit**

```bash
git add src/rapid7_healthcheck/report.py tests/test_report_state_blob.py
git commit -m "feat(report): add trimmed state-blob projection with 1 MB size cap"
```

---

## Task 5: Implement `_compute_delta` (pure function)

**Files:**
- Modify: `src/rapid7_healthcheck/report.py`
- Test: `tests/test_report_delta.py` (new)

Compares two state blobs and returns three sets: resolved, new_fails, severity_changed. Pure function over already-loaded dicts; no I/O.

- [ ] **Step 5.1: Write failing tests**

Create `tests/test_report_delta.py`:

```python
from __future__ import annotations


def _state(results, tool_version="0.1.9", host="us.api.insight.rapid7.com"):
    """Tiny constructor for a state-blob fixture."""
    return {
        "tool_version": tool_version,
        "generated_at": "2026-04-29T12:00:00Z",
        "base_url_host": host,
        "results": results,
    }


def _rule(rule_id, status, findings):
    return {
        "rule_id": rule_id,
        "rule_name": rule_id.replace("_", " ").title(),
        "status": status,
        "severity": "fail" if status == "fail" else "warn",
        "duration_ms": 100,
        "finding_count": len(findings),
        "findings": findings,
    }


def _check(name, rule_results):
    return {
        "name": name, "status": "warn", "duration_ms": 1000,
        "findings": [], "rule_results": rule_results,
    }


def _f(sig, severity="fail", short="msg"):
    return {"id": f"r#{sig}", "signature": sig, "severity": severity, "message_short": short}


def test_compute_delta_no_prior_returns_none():
    from rapid7_healthcheck.report import _compute_delta
    cur = _state([_check("Audit", [_rule("r1", "fail", [_f("a")])])])
    assert _compute_delta(prior=None, current=cur) is None


def test_compute_delta_all_resolved():
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "fail", [_f("a"), _f("b")])])])
    cur = _state([_check("Audit", [_rule("r1", "pass", [])])])
    delta = _compute_delta(prior=prior, current=cur)
    assert delta is not None
    assert len(delta["resolved"]) == 2
    assert len(delta["new_fails"]) == 0
    assert len(delta["severity_changed"]) == 0


def test_compute_delta_new_fail():
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "fail", [_f("a")])])])
    cur = _state([_check("Audit", [_rule("r1", "fail", [_f("a"), _f("b")])])])
    delta = _compute_delta(prior=prior, current=cur)
    assert len(delta["new_fails"]) == 1
    assert delta["new_fails"][0]["signature"] == "b"


def test_compute_delta_severity_changed():
    """Same signature, severity warn -> fail."""
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "warn", [_f("a", severity="warn")])])])
    cur = _state([_check("Audit", [_rule("r1", "fail", [_f("a", severity="fail")])])])
    delta = _compute_delta(prior=prior, current=cur)
    assert len(delta["severity_changed"]) == 1
    assert delta["severity_changed"][0]["signature"] == "a"


def test_compute_delta_host_mismatch_returns_none():
    """Filename collision protection -- different consoles should not produce a delta."""
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "fail", [_f("a")])])], host="us.api")
    cur = _state([_check("Audit", [_rule("r1", "fail", [_f("a")])])], host="eu.api")
    assert _compute_delta(prior=prior, current=cur) is None


def test_compute_delta_version_skew_unknown_rule_treated_as_new():
    """Rules added in current that didn't exist in prior count as new findings,
    not as resolutions. Conservative."""
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "fail", [_f("a")])])], tool_version="0.1.8")
    cur = _state([
        _check("Audit", [
            _rule("r1", "fail", [_f("a")]),
            _rule("r2_new", "fail", [_f("z")]),
        ])
    ], tool_version="0.1.9")
    delta = _compute_delta(prior=prior, current=cur)
    assert len(delta["new_fails"]) == 1
    assert delta["new_fails"][0]["signature"] == "z"
    assert len(delta["resolved"]) == 0


def test_compute_delta_only_fail_severity_counts_as_new_fail():
    """A new warn finding is not a new_fail (only severity == fail counts)."""
    from rapid7_healthcheck.report import _compute_delta
    prior = _state([_check("Audit", [_rule("r1", "warn", [])])])
    cur = _state([_check("Audit", [_rule("r1", "warn", [_f("a", severity="warn")])])])
    delta = _compute_delta(prior=prior, current=cur)
    assert len(delta["new_fails"]) == 0
    # But it should still show up in 'new_findings' if we expose that -- for
    # Phase 1 we expose only resolved/new_fails/severity_changed, and the
    # new warn is correctly absent from all three.
    assert len(delta["resolved"]) == 0
    assert len(delta["severity_changed"]) == 0
```

- [ ] **Step 5.2: Run tests, verify they fail**

```bash
pytest tests/test_report_delta.py -v
```

Expected: 7 FAIL with `ImportError`.

- [ ] **Step 5.3: Implement `_compute_delta`**

Add to `src/rapid7_healthcheck/report.py` after `_state_blob_projection`:

```python
def _compute_delta(*, prior: dict | None, current: dict) -> dict | None:
    """Diff two state blobs. Returns None when no comparable prior exists.

    Skips silently on host mismatch (filename collision protection).
    Tolerates version skew: unknown rule_ids in current count as new findings,
    not as resolutions. Conservative -- never claims something was resolved
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
            for rr in r.get("rule_results", []) or []:
                rule_id = rr.get("rule_id")
                for f in rr.get("findings", []):
                    sig = f.get("signature")
                    if sig:
                        out[sig] = {**f, "rule_id": rule_id}
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
```

- [ ] **Step 5.4: Run tests, verify they pass**

```bash
pytest tests/test_report_delta.py -v
```

Expected: 7 PASS.

- [ ] **Step 5.5: Commit**

```bash
git add src/rapid7_healthcheck/report.py tests/test_report_delta.py
git commit -m "feat(report): add _compute_delta for cross-run finding diff"
```

---

## Task 6: Implement `_load_prior_state` (I/O -- find + parse the most recent prior report)

**Files:**
- Modify: `src/rapid7_healthcheck/report.py`
- Modify: `tests/test_report_delta.py` (extend with I/O cases)

This is the only I/O helper in this stack. It scans `output_dir` for the most recent `.html` file matching `filename_pattern`, parses its embedded `<script id="report-state">` JSON via regex, and returns the parsed dict (or `None` on any failure: no match, stale, parse error).

- [ ] **Step 6.1: Write failing tests**

Append to `tests/test_report_delta.py`:

```python
import json as _json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _write_report_with_blob(path: Path, blob: dict, *, mtime: datetime | None = None) -> None:
    """Write a tiny HTML file with a state-blob script tag."""
    payload = _json.dumps(blob)
    html = (
        '<!doctype html><html><body>'
        f'<script id="report-state" type="application/json">{payload}</script>'
        '</body></html>'
    )
    path.write_text(html, encoding="utf-8")
    if mtime is not None:
        ts = mtime.timestamp()
        import os
        os.utime(path, (ts, ts))


def test_load_prior_state_no_match_returns_none(tmp_path):
    from rapid7_healthcheck.report import _load_prior_state
    assert _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "r-2026-04-29_1200.html",
        max_age_days=30,
    ) is None


def test_load_prior_state_picks_most_recent(tmp_path):
    from rapid7_healthcheck.report import _load_prior_state
    older = tmp_path / "r-2026-04-20_1000.html"
    newer = tmp_path / "r-2026-04-28_1000.html"
    _write_report_with_blob(older, _state([_check("A", [])], host="h"),
                            mtime=datetime(2026, 4, 20, tzinfo=timezone.utc))
    _write_report_with_blob(newer, _state([_check("B", [])], host="h"),
                            mtime=datetime(2026, 4, 28, tzinfo=timezone.utc))
    blob = _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "r-2026-04-29_1200.html",
        max_age_days=30,
    )
    assert blob is not None
    assert blob["results"][0]["name"] == "B"


def test_load_prior_state_excludes_self(tmp_path):
    """The current run's path must be excluded so we don't compare to ourselves
    (relevant if same minute write -- defensive)."""
    from rapid7_healthcheck.report import _load_prior_state
    self_path = tmp_path / "r-2026-04-29_1200.html"
    _write_report_with_blob(self_path, _state([], host="h"))
    assert _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=self_path,
        max_age_days=30,
    ) is None


def test_load_prior_state_skips_stale_files(tmp_path):
    from rapid7_healthcheck.report import _load_prior_state
    old = tmp_path / "r-2026-01-01_1000.html"
    _write_report_with_blob(old, _state([], host="h"),
                            mtime=datetime.now(timezone.utc) - timedelta(days=120))
    assert _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "x.html",
        max_age_days=30,
    ) is None


def test_load_prior_state_handles_parse_failure(tmp_path):
    from rapid7_healthcheck.report import _load_prior_state
    bad = tmp_path / "r-2026-04-28_1000.html"
    bad.write_text(
        '<!doctype html><script id="report-state" type="application/json">{not json</script>',
        encoding="utf-8",
    )
    assert _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "x.html",
        max_age_days=30,
    ) is None


def test_load_prior_state_handles_missing_script_tag(tmp_path):
    from rapid7_healthcheck.report import _load_prior_state
    no_blob = tmp_path / "r-2026-04-28_1000.html"
    no_blob.write_text("<!doctype html><html><body>nothing here</body></html>", encoding="utf-8")
    assert _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "x.html",
        max_age_days=30,
    ) is None


def test_load_prior_state_max_age_none_disables_check(tmp_path):
    """max_age_days=None means don't filter by age."""
    from rapid7_healthcheck.report import _load_prior_state
    ancient = tmp_path / "r-2020-01-01_1000.html"
    _write_report_with_blob(ancient, _state([_check("Old", [])], host="h"),
                            mtime=datetime.now(timezone.utc) - timedelta(days=2000))
    blob = _load_prior_state(
        output_dir=tmp_path,
        filename_pattern="r-{timestamp}.html",
        exclude=tmp_path / "x.html",
        max_age_days=None,
    )
    # max_age_days=None disables the staleness filter; the file is loaded.
    assert blob is not None
```

- [ ] **Step 6.2: Run tests, verify they fail**

```bash
pytest tests/test_report_delta.py -v -k "load_prior"
```

Expected: 7 FAIL with `ImportError`.

- [ ] **Step 6.3: Implement `_load_prior_state`**

Add to `src/rapid7_healthcheck/report.py` after `_compute_delta`:

```python
import re as _re
import time as _time

_STATE_BLOB_RE = _re.compile(
    r'<script id="report-state" type="application/json">(.*?)</script>',
    _re.DOTALL,
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
    missing script tag. All failure modes are silent -- the caller should treat
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
        now = _time.time()
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
```

- [ ] **Step 6.4: Run tests, verify they pass**

```bash
pytest tests/test_report_delta.py -v
```

Expected: all PASS (14 total in this file).

- [ ] **Step 6.5: Commit**

```bash
git add src/rapid7_healthcheck/report.py tests/test_report_delta.py
git commit -m "feat(report): add _load_prior_state for prior-file discovery + parse"
```

---

## Task 7: Build the metrics rollup helper

**Files:**
- Modify: `src/rapid7_healthcheck/report.py`
- Modify: `tests/test_report.py` (add tests)

A small helper that computes the metric grid numbers (total rules, fail count, warn count, sampled count, total duration, skipped count) from a `list[CheckResult]`. Used by the template's editorial band.

- [ ] **Step 7.1: Write failing tests**

Append to `tests/test_report.py`:

```python
def test_metrics_rollup_counts():
    from rapid7_healthcheck.report import _metrics
    from rapid7_healthcheck.audit import RuleResult
    cr = CheckResult(
        name="Audit", description="d", status="warn", duration_ms=2500,
        findings=[],
        rule_results=[
            RuleResult(rule_id="a", rule_name="A", description="d",
                       severity="fail", status="fail",
                       findings=[Finding(severity="fail", message="m")]),
            RuleResult(rule_id="b", rule_name="B", description="d",
                       severity="warn", status="warn",
                       findings=[Finding(severity="warn", message="m")],
                       sampled=True, sample_info="500/4200"),
            RuleResult(rule_id="c", rule_name="C", description="d",
                       severity="info", status="pass"),
            RuleResult(rule_id="d", rule_name="D", description="d",
                       severity="warn", status="skipped"),
        ],
    )
    m = _metrics([cr])
    assert m["rules_total"] == 4
    assert m["rules_fail"] == 1
    assert m["rules_warn"] == 1
    assert m["rules_pass"] == 1
    assert m["rules_skipped"] == 1
    assert m["rules_sampled"] == 1
    assert m["total_duration_ms"] == 2500
    assert m["findings_total"] == 2
    assert m["findings_fail"] == 1
    assert m["findings_warn"] == 1


def test_metrics_rollup_handles_check_without_rule_results():
    """Operational checks (scan_engines etc.) have no rule_results -- they
    contribute findings but not rule counts."""
    from rapid7_healthcheck.report import _metrics
    cr = CheckResult(
        name="Scan Engines", description="d", status="warn", duration_ms=300,
        findings=[Finding(severity="warn", message="m")],
    )
    m = _metrics([cr])
    assert m["rules_total"] == 0
    assert m["findings_total"] == 1
    assert m["findings_warn"] == 1
    assert m["total_duration_ms"] == 300
```

- [ ] **Step 7.2: Run tests, verify they fail**

```bash
pytest tests/test_report.py::test_metrics_rollup_counts tests/test_report.py::test_metrics_rollup_handles_check_without_rule_results -v
```

Expected: 2 FAIL with `ImportError`.

- [ ] **Step 7.3: Implement `_metrics`**

Add to `src/rapid7_healthcheck/report.py` after `_load_prior_state`:

```python
def _metrics(results: list[CheckResult]) -> dict:
    """Roll up metric grid numbers from the list of CheckResults.

    Counts every rule across every check that has rule_results, and every
    finding from both rule_results-bearing checks and operational checks.
    """
    rules_total = rules_fail = rules_warn = rules_pass = rules_skipped = rules_sampled = 0
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
        "rules_sampled": rules_sampled,
        "findings_total": findings_total,
        "findings_fail": findings_fail,
        "findings_warn": findings_warn,
        "total_duration_ms": total_duration_ms,
    }
```

- [ ] **Step 7.4: Run tests, verify they pass**

```bash
pytest tests/test_report.py::test_metrics_rollup_counts tests/test_report.py::test_metrics_rollup_handles_check_without_rule_results -v
```

Expected: 2 PASS.

- [ ] **Step 7.5: Commit**

```bash
git add src/rapid7_healthcheck/report.py tests/test_report.py
git commit -m "feat(report): add _metrics rollup for the editorial-band tile grid"
```

---

## Task 8: Wire delta + state-blob + metrics through `render_report` and `write_report`

**Files:**
- Modify: `src/rapid7_healthcheck/report.py` (`ReportContext`, `render_report`, `write_report`)
- Modify: `src/rapid7_healthcheck/__main__.py` (pass `delta_max_age_days` from config)
- Modify: `tests/test_report.py` (add wiring tests)

Now connect the helpers. `render_report` gains optional `prior_state` (parsed) and computes both the delta and the state blob. `write_report` is the natural place to call `_load_prior_state` because it knows `output_dir` + `filename_pattern`.

- [ ] **Step 8.1: Extend `ReportContext` with optional fields**

Edit `src/rapid7_healthcheck/report.py` lines 38-46:

```python
@dataclass
class ReportContext:
    title: str
    generated_at: datetime
    base_url_host: str
    tool_version: str
    config_path: str
    results: list[CheckResult]
    thresholds_table: list[tuple[str, str]] = field(default_factory=list)
    delta: dict | None = None              # new -- computed delta or None
    state_blob_json: str | None = None     # new -- pre-serialized JSON for embedding, or None if dropped
    metrics: dict | None = None            # new -- populated by render_report
    content_hash: str | None = None        # new -- SHA-256 prefix of state_blob_json
```

- [ ] **Step 8.2: Update `render_report` to populate the new context fields**

Replace `render_report` in `src/rapid7_healthcheck/report.py` (lines 82-106):

```python
def render_report(ctx: ReportContext, *, prior_state: dict | None = None) -> str:
    """Render the report. If `prior_state` is supplied, compute a delta and
    embed both the delta strip and the trimmed state blob in the output."""
    import hashlib

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
```

- [ ] **Step 8.3: Update `write_report` to load prior state from `output_dir` before rendering**

Replace `write_report` in `src/rapid7_healthcheck/report.py` (lines 109-131):

```python
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
```

- [ ] **Step 8.4: Plumb `delta_max_age_days` from config in `__main__.py`**

Find the existing `write_report(...)` call site in `src/rapid7_healthcheck/__main__.py`. (Use Grep with pattern `write_report\(` against `__main__.py` if needed.) Add `delta_max_age_days=cfg.report.delta_max_age_days` to the kwargs. If the call already has explicit_path it will be ignored -- fine.

- [ ] **Step 8.5: Add wiring tests**

Append to `tests/test_report.py`:

```python
def test_render_report_embeds_state_blob():
    """The rendered HTML must contain the state blob script tag."""
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert '<script id="report-state" type="application/json">' in html


def test_render_report_no_delta_when_no_prior():
    r = CheckResult(name="X", description="x", status="warn",
                    findings=[Finding(severity="warn", message="m")])
    html = render_report(_ctx([r]))
    # Delta strip section should not render when no prior state was passed.
    assert "since" not in html.lower() or "Generated" in html  # generated_at uses "since" too -- be specific
    # Positive assertion: no "resolved" / "new fails" pill text.
    assert "resolved" not in html.lower()
    assert "new fails" not in html.lower()


def test_render_report_renders_delta_strip_when_prior_passed(tmp_path):
    """End-to-end: write a report, write a second one, second one must show delta."""
    r1 = CheckResult(
        name="Audit", description="d", status="fail",
        rule_results=[
            __import__("rapid7_healthcheck.audit", fromlist=["RuleResult"]).RuleResult(
                rule_id="r1", rule_name="R", description="d",
                severity="fail", status="fail",
                findings=[Finding(severity="fail", message="bad", details={"asset": "a"})],
            ),
        ],
    )
    ctx1 = _ctx([r1])
    p1 = tmp_path / "report-1.html"
    write_report(ctx1, explicit_path=p1)

    # Now run a second one in the same dir but using output_dir mode so it sees p1.
    # Move/copy p1 to look like a pattern match.
    import shutil
    pattern_p1 = tmp_path / "rapid7-{timestamp}.html".replace("{timestamp}", "2026-04-28_1000")
    shutil.move(str(p1), str(pattern_p1))

    r2 = CheckResult(name="Audit", description="d", status="pass",
                     rule_results=[], findings=[])  # all resolved
    ctx2 = _ctx([r2])
    out2 = write_report(
        ctx2, output_dir=tmp_path,
        filename_pattern="rapid7-{timestamp}.html",
        delta_max_age_days=30,
    )
    html = out2.read_text(encoding="utf-8")
    # Should mention the delta strip's "resolved" pill.
    assert "resolved" in html.lower()
```

- [ ] **Step 8.6: Run wiring tests**

These will partially fail until the template renders the delta strip and state blob (Task 9). For now run only the state-blob assertion:

```bash
pytest tests/test_report.py::test_render_report_embeds_state_blob -v
```

Expected: this test will FAIL because the template doesn't render the script tag yet. That's the bridge to Task 9. The other two wiring tests will also FAIL -- leave them failing for Task 9 to satisfy.

- [ ] **Step 8.7: Commit (red)**

```bash
git add src/rapid7_healthcheck/report.py src/rapid7_healthcheck/__main__.py tests/test_report.py
git commit -m "feat(report): wire delta + state-blob + metrics through render_report"
```

(Yes, committing red -- the tests fail because the template hasn't been updated yet. Task 9's commit is what turns them green. This keeps the diff reviewable as logical units.)

---

## Task 9: Replace `templates/report.html.j2` with the new layout

**Files:**
- Modify: `src/rapid7_healthcheck/templates/report.html.j2` (full rewrite)
- Modify: `tests/test_report.py` (update `test_no_external_resources`)

This is the biggest single step. The template is fully rewritten -- but it must preserve every assertion in the existing `tests/test_report.py` file (verdict text, rule names, descriptions, source URLs, sampling info, error messages, durations rendered with the duration filter). Take it slow and verify after.

- [ ] **Step 9.1: Update `test_no_external_resources` to allow inline JSON script**

Edit `tests/test_report.py` lines 60-65:

```python
def test_no_external_resources():
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    # Inline JSON state blob is allowed. External script src is not.
    assert "<script src=" not in html
    assert "https://cdn" not in html
    assert "//cdn" not in html
    # No external stylesheets, fonts, images, iframes.
    assert "<link rel=\"stylesheet\"" not in html
    assert "@import url" not in html
    assert "<iframe" not in html
    # Source URLs are allowed in <a href>; no other http(s):// references.
```

Also update line 133 in `test_audit_section_renders_per_rule_table`:

```python
    assert "<script src=" not in html  # was: assert "<script" not in html
```

- [ ] **Step 9.2: Replace `templates/report.html.j2`**

Overwrite the entire file with the new template below. Treat this as a "write the file fresh" operation -- there is no incremental diff that's safer than the full rewrite.

```jinja
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
  :root {
    --font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

    --neutral-fg: #1a1a1a;
    --neutral-muted: #5a5a5a;
    --border: #e3e3e3;
    --surface: #fafafa;
    --bg: #ffffff;

    --pass-fg: #0f6b3a;
    --pass-bg: #e6f5ec;
    --warn-fg: #8a4b00;
    --warn-bg: #fdf2dc;
    --fail-fg: #9a2417;
    --fail-bg: #fbe7e3;
    --info-fg: #1f4e8c;
    --info-bg: #e6eef9;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --neutral-fg: #e8e8ea;
      --neutral-muted: #9a9aa3;
      --border: #2a2e38;
      --surface: #161922;
      --bg: #0f1115;
      --pass-fg: #4dbe7a;
      --pass-bg: rgba(77,190,122,0.12);
      --warn-fg: #e0a04b;
      --warn-bg: rgba(224,160,75,0.14);
      --fail-fg: #e6786b;
      --fail-bg: rgba(230,120,107,0.14);
      --info-fg: #6aa6ee;
      --info-bg: rgba(106,166,238,0.14);
    }
  }
  *, *::before, *::after { box-sizing: border-box; }
  html { background: var(--bg); }
  body {
    font-family: var(--font-sans);
    color: var(--neutral-fg);
    background: var(--bg);
    margin: 2rem auto;
    max-width: 1100px;
    padding: 0 1.5rem;
    font-size: 15px;
    line-height: 1.55;
  }
  code, pre, .mono { font-family: var(--font-mono); font-size: 0.92em; }
  table { font-variant-numeric: tabular-nums; }

  h1 { margin: 0 0 0.25rem 0; font-size: 28px; letter-spacing: -0.01em; }
  h2 { margin: 2rem 0 0.5rem 0; font-size: 22px; }
  h3 { margin: 1rem 0 0.5rem 0; font-size: 18px; }

  a { color: var(--info-fg); text-underline-offset: 2px; }
  a:focus-visible, button:focus-visible, summary:focus-visible {
    outline: 2px solid var(--info-fg);
    outline-offset: 2px;
  }

  .meta {
    color: var(--neutral-muted);
    font-size: 13px;
    margin: 0 0 1.5rem 0;
    display: flex; flex-wrap: wrap; gap: 0.25rem 1.25rem;
  }
  .meta b { color: var(--neutral-fg); font-weight: 600; }

  .hero {
    margin: 1rem 0 1rem;
    padding: 1.25rem 1.5rem;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    flex-wrap: wrap;
    border: 1px solid var(--border);
  }
  .hero.pass { background: var(--pass-bg); }
  .hero.warn { background: var(--warn-bg); }
  .hero.fail { background: var(--fail-bg); }
  .hero .verdict-word {
    font-size: 36px; font-weight: 700; letter-spacing: -0.02em;
    color: var(--neutral-fg);
  }
  .hero.pass .verdict-word { color: var(--pass-fg); }
  .hero.warn .verdict-word { color: var(--warn-fg); }
  .hero.fail .verdict-word { color: var(--fail-fg); }
  .hero .verdict-summary {
    font-size: 15px; color: var(--neutral-muted); text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .delta-strip {
    margin: 0 0 1.5rem 0;
    padding: 0.5rem 1rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem;
    font-size: 13px;
    color: var(--neutral-muted);
  }
  .delta-pill {
    padding: 0.15rem 0.6rem; border-radius: 999px; font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .delta-pill.resolved { background: var(--pass-bg); color: var(--pass-fg); }
  .delta-pill.new-fail { background: var(--fail-bg); color: var(--fail-fg); }
  .delta-pill.changed  { background: var(--warn-bg); color: var(--warn-fg); }
  .delta-strip .since { margin-left: auto; }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 0.75rem;
    margin: 0 0 2rem 0;
  }
  .metric {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    background: var(--surface);
  }
  .metric-label {
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--neutral-muted); margin: 0 0 0.25rem 0;
  }
  .metric-value {
    font-size: 28px; font-weight: 600; line-height: 1.1;
    font-variant-numeric: tabular-nums;
  }
  .metric-sub { font-size: 13px; color: var(--neutral-muted); margin-top: 0.25rem; }

  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; }
  th, td {
    text-align: left; padding: 0.55rem 0.7rem;
    border-bottom: 1px solid var(--border); vertical-align: top;
  }
  tbody tr:nth-child(even) { background: var(--surface); }

  .badge {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px;
    font-size: 12px; font-weight: 600;
  }
  .badge.pass    { background: var(--pass-bg); color: var(--pass-fg); }
  .badge.warn    { background: var(--warn-bg); color: var(--warn-fg); }
  .badge.fail,
  .badge.error   { background: var(--fail-bg); color: var(--fail-fg); }
  .badge.skipped { background: var(--info-bg); color: var(--info-fg); }
  .badge.info    { background: var(--info-bg); color: var(--info-fg); }

  section.check { margin: 2.5rem 0; }
  section.check h2 { margin: 0 0 0.25rem 0; }
  .check-desc { color: var(--neutral-muted); margin: 0 0 0.75rem 0; }

  .tiles { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.75rem 0 1rem; }
  .tile {
    background: var(--surface); border: 1px solid var(--border);
    padding: 0.4rem 0.7rem; border-radius: 6px; font-size: 13px;
    font-variant-numeric: tabular-nums;
  }
  .tile b { display: block; font-size: 16px; }

  .error-box {
    background: var(--fail-bg); color: var(--fail-fg);
    border: 1px solid var(--fail-fg);
    padding: 0.75rem 1rem; border-radius: 6px;
  }
  .skipped-box {
    background: var(--info-bg); color: var(--info-fg);
    border: 1px solid var(--border);
    padding: 0.75rem 1rem; border-radius: 6px;
  }

  details { margin: 0.5rem 0; }
  details summary {
    cursor: pointer; padding: 0.4rem 0; font-weight: 600;
  }
  pre {
    background: var(--surface); padding: 0.5rem 0.75rem; border-radius: 4px;
    overflow-x: auto; font-size: 12px; max-height: 240px; overflow-y: auto;
    border: 1px solid var(--border);
  }

  footer {
    color: var(--neutral-muted); font-size: 13px; margin-top: 3rem;
    border-top: 1px solid var(--border); padding-top: 1rem;
  }
  footer code { color: var(--neutral-fg); }

  @media print {
    body { max-width: none; margin: 0; padding: 1cm; color: #000; background: #fff; }
    :root {
      --bg: #fff; --neutral-fg: #000; --neutral-muted: #444; --surface: #f6f6f6;
    }
    .delta-strip, .metric-grid { page-break-inside: avoid; }
    section.check { page-break-before: always; page-break-inside: auto; }
    section.check:first-of-type { page-break-before: avoid; }
    details { page-break-inside: avoid; }
    details[open] summary { page-break-after: avoid; }
    a[href]::after { content: " (" attr(href) ")"; font-size: 0.85em; color: #555; }
    a[href^="#"]::after { content: ""; }
  }
</style>
</head>
<body>

<h1>{{ title }}</h1>
<div class="meta">
  <span><b>Generated:</b> {{ generated_at_local }} ({{ generated_at_utc }} UTC)</span>
  <span><b>Console:</b> <span class="mono">{{ base_url_host }}</span></span>
  <span><b>Version:</b> <span class="mono">{{ tool_version }}</span></span>
  {% if content_hash %}<span><b>Run hash:</b> <span class="mono">{{ content_hash }}</span></span>{% endif %}
</div>

<div class="hero {{ verdict_class }}" role="status">
  <div class="verdict-word">{{ verdict_label }}</div>
  {% if metrics %}
  <div class="verdict-summary">
    {{ metrics.findings_fail }} fail · {{ metrics.findings_warn }} warn
    {% if metrics.rules_total %}across {{ metrics.rules_total }} rule{{ "" if metrics.rules_total == 1 else "s" }} in {{ results|length }} check{{ "" if results|length == 1 else "s" }}{% endif %}
  </div>
  {% endif %}
</div>

{% if delta %}
<div class="delta-strip" aria-label="Changes since last run">
  <span class="delta-pill resolved">↓ {{ delta.resolved|length }} resolved</span>
  <span class="delta-pill new-fail">↑ {{ delta.new_fails|length }} new fails</span>
  <span class="delta-pill changed">↻ {{ delta.severity_changed|length }} changed severity</span>
  <span class="since">since <span class="mono">{{ delta.prior_generated_at }}</span></span>
</div>
{% endif %}

{% if metrics %}
<div class="metric-grid" aria-label="At a glance">
  <div class="metric">
    <div class="metric-label">Rules run</div>
    <div class="metric-value">{{ metrics.rules_total }}</div>
    {% if metrics.rules_sampled %}<div class="metric-sub">{{ metrics.rules_sampled }} sampled</div>{% endif %}
  </div>
  <div class="metric">
    <div class="metric-label">Findings · fail</div>
    <div class="metric-value">{{ metrics.findings_fail }}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Findings · warn</div>
    <div class="metric-value">{{ metrics.findings_warn }}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Rules pass</div>
    <div class="metric-value">{{ metrics.rules_pass }}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Skipped</div>
    <div class="metric-value">{{ metrics.rules_skipped }}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Total duration</div>
    <div class="metric-value">{{ metrics.total_duration_ms | duration }}</div>
  </div>
</div>
{% endif %}

<h2>Summary</h2>
<table>
  <thead>
    <tr><th>Check</th><th>Status</th><th>Findings</th><th style="text-align:right">Duration</th></tr>
  </thead>
  <tbody>
  {% for r in results %}
    <tr>
      <td><a href="#check-{{ loop.index }}">{{ r.name }}</a></td>
      <td><span class="badge {{ r.status }}">{{ r.status|upper }}</span></td>
      <td>{{ r.findings|length }} ({{ r.findings|selectattr('severity','equalto','fail')|list|length }} fail / {{ r.findings|selectattr('severity','equalto','warn')|list|length }} warn)</td>
      <td style="text-align:right">{{ r.duration_ms | duration }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

{% for r in results %}
<section class="check" id="check-{{ loop.index }}">
  <h2>{{ r.name }} <span class="badge {{ r.status }}">{{ r.status|upper }}</span></h2>
  <p class="check-desc">{{ r.description }}</p>

  {% if r.status == "error" %}
    <div class="error-box"><b>Check failed to run:</b> {{ r.error }}</div>
  {% elif r.status == "skipped" %}
    <div class="skipped-box">This check is disabled in <code>config.yaml</code>.</div>
  {% else %}
    {% if r.rule_results %}
      <div class="tiles">
        <div class="tile"><b>{{ r.summary.rules_total }}</b> rules</div>
        <div class="tile"><b>{{ r.summary.rules_pass }}</b> pass</div>
        <div class="tile"><b>{{ r.summary.rules_warn }}</b> warn</div>
        <div class="tile"><b>{{ r.summary.rules_fail }}</b> fail</div>
        <div class="tile"><b>{{ r.summary.rules_error }}</b> error</div>
        <div class="tile"><b>{{ r.summary.rules_skipped }}</b> skipped</div>
      </div>

      <table>
        <thead><tr><th>Rule</th><th>Status</th><th>Findings</th><th>Notes</th><th style="text-align:right">Duration</th></tr></thead>
        <tbody>
        {% for rr in r.rule_results %}
          <tr>
            <td><a href="#rule-{{ rr.rule_id }}">{{ rr.rule_name }}</a></td>
            <td><span class="badge {{ rr.status }}">{{ rr.status|upper }}</span></td>
            <td>{{ rr.findings|length }}</td>
            <td>{% if rr.sampled %}sampled{% endif %}</td>
            <td style="text-align:right">{{ rr.duration_ms | duration }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>

      {% for rr in r.rule_results %}
      <details id="rule-{{ rr.rule_id }}">
        <summary><b>{{ rr.rule_name }}</b> <span class="badge {{ rr.status }}">{{ rr.status|upper }}</span></summary>
        <p class="check-desc">{{ rr.description }}</p>

        {% if rr.status == "error" %}
          <div class="error-box"><b>Rule failed to run:</b> {{ rr.error }}</div>
        {% elif rr.status == "skipped" %}
          <div class="skipped-box">This rule is disabled in <code>config.yaml</code> (audit.rules.{{ rr.rule_id }}.enabled: false).</div>
        {% else %}
          {% if rr.sampled %}
            <p class="check-desc"><i>Note: {{ rr.sample_info }}</i></p>
          {% endif %}
          {% if rr.findings %}
          <table>
            <thead><tr><th>Severity</th><th>Message</th></tr></thead>
            <tbody>
            {% for f in rr.findings %}
              <tr>
                <td><span class="badge {{ 'fail' if f.severity == 'fail' else 'warn' if f.severity == 'warn' else 'pass' }}">{{ f.severity|upper }}</span></td>
                <td>
                  {{ f.message }}
                  {% if f.details %}
                    <details><summary>details</summary><pre>{{ f.details_json }}</pre></details>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% else %}
          <p>No findings.</p>
          {% endif %}
        {% endif %}

        {% if rr.sources %}
        <p class="check-desc"><b>Sources:</b></p>
        <ul>
          {% for src in rr.sources %}
            <li><a href="{{ src }}" target="_blank" rel="noopener noreferrer">{{ src }}</a></li>
          {% endfor %}
        </ul>
        {% endif %}
      </details>
      {% endfor %}

    {% elif r.summary %}
    <div class="tiles">
      {% for k, v in r.summary.items() %}
        <div class="tile"><b>{{ v }}</b> {{ k }}</div>
      {% endfor %}
    </div>
    {% endif %}

    {% if not r.rule_results %}
    {% if r.findings %}
    <table>
      <thead><tr><th>Severity</th><th>Message</th></tr></thead>
      <tbody>
      {% for f in r.findings %}
        <tr>
          <td><span class="badge {{ 'fail' if f.severity == 'fail' else 'warn' if f.severity == 'warn' else 'pass' }}">{{ f.severity|upper }}</span></td>
          <td>
            {{ f.message }}
            {% if f.details %}
              <details><summary>details</summary><pre>{{ f.details_json }}</pre></details>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
      <p>No issues found.</p>
    {% endif %}
    {% endif %}
  {% endif %}
</section>
{% endfor %}

<footer>
  <p>Config: <code>{{ config_path }}</code></p>
  {% if thresholds_table %}
  <p>Thresholds applied:</p>
  <table>
    <thead><tr><th>Setting</th><th>Value</th></tr></thead>
    <tbody>
    {% for key, value in thresholds_table %}
      <tr><td><code>{{ key }}</code></td><td>{{ value }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
</footer>

{% if state_blob_json %}
<script id="report-state" type="application/json">{{ state_blob_json | safe }}</script>
{% endif %}

</body>
</html>
```

- [ ] **Step 9.3: Run the full test suite**

```bash
pytest -v
```

Expected: every test from the original `test_report.py` still passes (verdict, sampling, error rendering, durations, source links, audit section), plus all new tests (state-blob, delta, metrics, wiring).

If any existing test fails, the most likely cause is a missing string the new template renamed. Look at the assertion, find the equivalent in the new template, and either:
- adjust the template to preserve the original wording (preferred), or
- update the test if the new wording is genuinely the intended one.

Either change must be justified -- don't silently weaken assertions.

- [ ] **Step 9.4: Manual smoke check (browser)**

Generate a sample report against test fixtures, open in a browser, eyeball:

```bash
python -c "
from datetime import datetime, timezone
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.report import ReportContext, write_report
import tempfile, pathlib, webbrowser

results = [
    CheckResult(
        name='Configuration Audit', description='Audit checks',
        status='warn', duration_ms=4200,
        rule_results=[
            RuleResult(rule_id='r1', rule_name='Rule One', description='First rule',
                       severity='fail', status='fail', duration_ms=120,
                       findings=[Finding(severity='fail', message='port 22 exposed', details={'asset':'web-1'})],
                       sources=['https://docs.rapid7.com/insightvm/foo']),
            RuleResult(rule_id='r2', rule_name='Rule Two', description='Second rule',
                       severity='warn', status='warn', duration_ms=80,
                       findings=[Finding(severity='warn', message='outdated agent')],
                       sampled=True, sample_info='checked 500 of 4200 assets'),
        ],
        summary={'rules_total':2,'rules_pass':0,'rules_warn':1,'rules_fail':1,'rules_error':0,'rules_skipped':0},
    ),
    CheckResult(name='Scan Engines', description='Scan engine health', status='pass', duration_ms=300),
]

ctx = ReportContext(
    title='Rapid7 HealthCheck -- sample',
    generated_at=datetime.now(timezone.utc),
    base_url_host='us.api.insight.rapid7.com',
    tool_version='0.1.9',
    config_path='config.yaml',
    results=results,
    thresholds_table=[('scan_engines.last_contact_warn_hours', '2')],
)

p = pathlib.Path(tempfile.gettempdir()) / 'r7-sample.html'
write_report(ctx, explicit_path=p)
print(f'wrote {p}')
webbrowser.open(p.as_uri())
"
```

Visual checklist:
- Hero verdict shows "Warnings" with amber tint.
- Metric grid renders with 6 tiles, numbers tabular-aligned.
- Per-check section renders with rules table + collapsible rule details.
- Sources link is clickable, opens in new tab.
- Toggle the OS to dark mode, refresh -- colors invert sensibly.
- Print preview (Ctrl+P) -- rule cards expand, no chrome lost.

- [ ] **Step 9.5: Commit**

```bash
git add src/rapid7_healthcheck/templates/report.html.j2 tests/test_report.py
git commit -m "feat(report): new editorial+dashboard template with delta strip + metrics"
```

---

## Task 10: Bump version, update CHANGELOG, update README

**Files:**
- Modify: `pyproject.toml` (version bump)
- Modify: `CHANGELOG.md`
- Modify: `README.md` (one paragraph for the new report)

- [ ] **Step 10.1: Bump version in `pyproject.toml`**

Find the line `version = "0.1.8"` (or wherever the version lives) and change to `0.1.9`. The version-drift test will catch any inconsistency.

- [ ] **Step 10.2: Add CHANGELOG entry**

Add a new section at the top of `CHANGELOG.md` (after the format header):

```markdown
## 0.1.9 -- 2026-04-29

### Changed
- Report HTML restyled with a hybrid editorial + dashboard layout: hero verdict
  band, metric grid, restyled per-category sections, light + dark mode via
  `prefers-color-scheme`, and print-friendly CSS.
- System-font typography stack throughout; tabular numerals on all metrics.

### Added
- "Since last run" delta strip: when a prior report exists in the same output
  directory and is younger than `report.delta_max_age_days` (default 30),
  shows resolved / new-fails / severity-changed counts. Silent on parse
  failures, host mismatch, or version skew.
- Embedded `<script id="report-state" type="application/json">` blob with a
  trimmed projection of the run (signatures + severity + short message). Used
  by the next run to compute deltas and by the new "Run hash" footer field
  (16-char SHA-256 prefix). Drops automatically if projected size > 1 MB.
- New `report.delta_max_age_days` config option (int or null). Optional in
  YAML; existing configs continue to load unchanged.

### Notes
- This is the first half of a two-part rework. Filtering, theme toggle,
  rule-card JS toggle, and the a11y test sweep land in 0.2.0.
```

- [ ] **Step 10.3: Update `README.md` with a "What's new" note**

Find a sensible spot near the top of `README.md` (just under the project description, above "Common commands" or equivalent). Insert:

```markdown
### What's new in 0.1.9

The HTML report has been restyled into a hybrid editorial + dashboard layout
with light/dark mode, a metric grid, and a "since last run" delta strip that
appears automatically when a prior report exists in the output directory.
The report remains a single self-contained HTML file with no external
resources.
```

- [ ] **Step 10.4: Run the full test suite one last time**

```bash
pytest -v
```

Expected: all green, including `test_version` regression test.

- [ ] **Step 10.5: Commit**

```bash
git add pyproject.toml CHANGELOG.md README.md
git commit -m "release: 0.1.9"
```

---

## Self-Review

Done after the plan was written, before handing off to execution.

**Spec coverage:**
- Hero verdict, delta strip, metric grid → Tasks 7, 8, 9. ✓
- Embedded JSON state blob with trimmed projection + 1 MB cap → Tasks 4, 8, 9. ✓
- Delta computation against prior file → Tasks 5, 6, 8. ✓
- `delta_max_age_days` config + backward-compatible YAML loader → Tasks 1, 2. ✓
- New visual language (typography, color tokens, dark mode, spacing) → Task 9. ✓
- Print CSS → Task 9 (inside template). ✓
- 4-case delta tests + stale + version-skew + host-mismatch → Task 5 (logic) + Task 6 (I/O). ✓
- Strengthened `test_no_external_resources` → Task 9. ✓
- Acceptance criteria (file size, smoke test, green pytest) → Task 9 step 9.4 + Task 10 step 10.4. ✓

**Placeholder scan:** None found. Every code step shows the actual code; every test step shows the actual test.

**Type consistency:**
- `_finding_signature(rule_id: str, finding: Finding) -> str` -- used the same way in Tasks 4 (projection), 5 (delta input is signature-keyed). ✓
- `_state_blob_projection(...) -> dict | None` -- `None` return on size cap is what Task 8's `render_report` checks via `if blob is not None`. ✓
- `_compute_delta(*, prior, current) -> dict | None` -- keyword-only args; `None` handled in Task 8 wiring. ✓
- `_load_prior_state(*, output_dir, filename_pattern, exclude, max_age_days) -> dict | None` -- same kwargs in tests (Task 6) and call site (Task 8). ✓
- `delta` dict shape: `prior_generated_at`, `resolved`, `new_fails`, `severity_changed` -- consistent across compute (Task 5), wiring (Task 8), template (Task 9). ✓
- `metrics` dict keys: `rules_total/rules_fail/rules_warn/rules_pass/rules_skipped/rules_sampled/findings_total/findings_fail/findings_warn/total_duration_ms` -- defined Task 7, used in template Task 9 (only `findings_fail`, `findings_warn`, `rules_total`, `rules_sampled`, `rules_pass`, `rules_skipped`, `total_duration_ms` are read; the rest are unused but harmless). ✓
- `ReportContext` new fields default to `None` so existing call sites in tests don't break. ✓

**One known red commit (Task 8 step 8.7).** This is intentional: the helpers and wiring land separately from the template rewrite to keep each commit reviewable. Task 9's commit is the one that turns the suite green. If you prefer fully-green commits, fold step 8.7 into Task 9's commit instead.
