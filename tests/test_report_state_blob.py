from __future__ import annotations

import json as _json
from datetime import datetime, timezone

from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.audit import RuleResult


def test_finding_signature_stable_across_calls():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f = Finding(severity="fail", message="port 22 exposed", details={"asset": "web-1", "port": 22})
    assert _finding_signature("ssh_open", f) == _finding_signature("ssh_open", f)


def test_finding_signature_changes_with_rule_id():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f = Finding(severity="fail", message="m", details={"k": 1})
    assert _finding_signature("rule_a", f) != _finding_signature("rule_b", f)


def test_finding_signature_changes_with_message():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f1 = Finding(severity="fail", message="m1", details={"k": 1})
    f2 = Finding(severity="fail", message="m2", details={"k": 1})
    assert _finding_signature("r", f1) != _finding_signature("r", f2)


def test_finding_signature_changes_with_details():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f1 = Finding(severity="fail", message="m", details={"asset": "host-a"})
    f2 = Finding(severity="fail", message="m", details={"asset": "host-b"})
    assert _finding_signature("r", f1) != _finding_signature("r", f2)


def test_finding_signature_independent_of_details_key_order():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f1 = Finding(severity="fail", message="m", details={"a": 1, "b": 2})
    f2 = Finding(severity="fail", message="m", details={"b": 2, "a": 1})
    assert _finding_signature("r", f1) == _finding_signature("r", f2)


def test_finding_signature_handles_none_details():
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f = Finding(severity="warn", message="m")
    sig = _finding_signature("r", f)
    assert isinstance(sig, str) and len(sig) >= 8


def test_finding_signature_independent_of_severity():
    """Same finding promoted from warn to fail keeps its signature -- this is what
    lets us detect a 'severity changed' delta rather than counting it as a new
    finding plus a resolved one."""
    from rapid7_healthcheck.state_engine import finding_signature as _finding_signature
    f1 = Finding(severity="warn", message="m", details={"k": 1})
    f2 = Finding(severity="fail", message="m", details={"k": 1})
    assert _finding_signature("r", f1) == _finding_signature("r", f2)


def test_state_blob_projection_shape():
    from rapid7_healthcheck.state_engine import project as _state_blob_projection
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
    from rapid7_healthcheck.state_engine import project as _state_blob_projection
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
    from rapid7_healthcheck.state_engine import project as _state_blob_projection
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
