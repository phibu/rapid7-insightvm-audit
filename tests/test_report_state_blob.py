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
    """Same finding promoted from warn to fail keeps its signature — this is what
    lets us detect a 'severity changed' delta rather than counting it as a new
    finding plus a resolved one."""
    from rapid7_healthcheck.report import _finding_signature
    f1 = Finding(severity="warn", message="m", details={"k": 1})
    f2 = Finding(severity="fail", message="m", details={"k": 1})
    assert _finding_signature("r", f1) == _finding_signature("r", f2)
