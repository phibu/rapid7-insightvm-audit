from __future__ import annotations

from rapid7_healthcheck.audit.template.rules.windows_services_disabled import (
    WindowsServicesDisabledRule,
)


def test_flags_explicit_false(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t1", "name": "Vuln", "vulnerabilityEnabled": True,
         "enableWindowsServices": False},
    ])
    r = WindowsServicesDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["enable_windows_services"] is False


def test_flags_absent_default_false(fake_snapshot):
    """API/UI default is unchecked (false), so absent = non-compliant for any
    template that scans Windows. Flag-absent (verify-if-Windows wording)."""
    fake_snapshot.set_templates_full([
        {"id": "t2", "name": "Untouched", "vulnerabilityEnabled": True},
    ])
    r = WindowsServicesDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1
    assert r.findings[0].details["enable_windows_services"] == "absent (defaults to false)"


def test_explicit_true_compliant(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t3", "name": "Good", "vulnerabilityEnabled": True,
         "enableWindowsServices": True},
    ])
    r = WindowsServicesDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary == {"examined": 1, "passed": 1, "failed": 0}


def test_scoped_to_vuln_enabled_only(fake_snapshot):
    """enableWindowsServices enables remote-registry checks DURING vuln
    assessment -- a discovery-only template has no vuln checks to bypass-registry
    for, so it is NOT examined (gate = vuln_enabled only, not discoveryOnly)."""
    fake_snapshot.set_templates_full([
        {"id": "t4", "name": "DiscoOnly", "discoveryOnly": True,
         "vulnerabilityEnabled": False},
    ])
    r = WindowsServicesDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.findings == []
    assert r.card_summary["examined"] == 0


def test_severity_is_info_no_escalation(fake_snapshot):
    fake_snapshot.set_templates_full([
        {"id": "t5", "name": "Vuln", "vulnerabilityEnabled": True},
    ])
    r = WindowsServicesDisabledRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"  # info findings never escalate check status
