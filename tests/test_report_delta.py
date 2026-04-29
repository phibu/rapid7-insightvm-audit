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
