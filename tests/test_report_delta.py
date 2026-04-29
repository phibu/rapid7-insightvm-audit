from __future__ import annotations

import json as _json
from datetime import datetime, timedelta, timezone
from pathlib import Path


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
    """Filename collision protection — different consoles should not produce a delta."""
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
    # But it should still show up in 'new_findings' if we expose that — for
    # Phase 1 we expose only resolved/new_fails/severity_changed, and the
    # new warn is correctly absent from all three.
    assert len(delta["resolved"]) == 0
    assert len(delta["severity_changed"]) == 0


# ---------------------------------------------------------------------------
# _load_prior_state — I/O tests
# ---------------------------------------------------------------------------


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
    (relevant if same minute write — defensive)."""
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
