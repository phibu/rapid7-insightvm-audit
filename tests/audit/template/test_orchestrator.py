"""Tests for TemplateAuditCheck orchestrator (F1 scaffold).

Pins the orchestrator's contract:
- Returns a CheckResult with rule_results=[] when registry is empty.
- Accepts a snapshot via kwarg.
- Decorator registers a rule with the registry.
- Per-rule exceptions are isolated; failing rule produces an error rule_result.
- template_audit.enabled=false makes the orchestrator self-skip.

F2-F4 will add per-rule coverage as they land rule implementations.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import (
    TemplateAuditCheck,
    _TEMPLATE_RULE_REGISTRY,
    register_template_rule,
)
from rapid7_healthcheck.config import (
    AppConfig,
    AssetCoverageThresholds,
    DataQualityThresholds,
    Rapid7Config,
    ReportConfig,
    RuleConfig,
    ScanActivityThresholds,
    ScanEngineThresholds,
    TemplateAuditConfig,
    Thresholds,
)


def _minimal_config(
    *,
    template_audit_enabled: bool = True,
    rules: dict | None = None,
) -> AppConfig:
    return AppConfig(
        rapid7=Rapid7Config(
            base_url="https://example.com",
            verify_tls=True,
            request_timeout_seconds=30,
            max_retries=3,
        ),
        report=ReportConfig(output_dir="reports", filename_pattern="report-{timestamp}.html", title="Test"),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(last_contact_warn_hours=24, last_contact_fail_hours=72),
            scan_activity=ScanActivityThresholds(recent_window_days=7, stuck_scan_hours=12, site_no_scan_days=30),
            asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=True, never_scanned_days=90),
            data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=True),
        ),
        checks={
            "scan_engines": False,
            "scan_activity": False,
            "asset_coverage": False,
            "data_quality": False,
            "configuration_audit": False,
            "user_permission_audit": False,
            "cloud_drift_audit": False,
            "template_audit": True,
        },
        template_audit=TemplateAuditConfig(
            enabled=template_audit_enabled,
            full_scan=False,
            sample_size=500,
            rules=rules or {},
        ),
    )


@pytest.fixture
def empty_registry():
    """Snapshot the template registry, clear it for the test, restore after."""
    saved = dict(_TEMPLATE_RULE_REGISTRY)
    _TEMPLATE_RULE_REGISTRY.clear()
    try:
        yield
    finally:
        _TEMPLATE_RULE_REGISTRY.clear()
        _TEMPLATE_RULE_REGISTRY.update(saved)


def test_template_audit_check_returns_check_result(empty_registry):
    """Empty registry => valid CheckResult with status='pass' and rule_results=[]."""
    client = MagicMock()
    cfg = _minimal_config(template_audit_enabled=True)

    result = TemplateAuditCheck().run(client, cfg)

    assert result.name == "Template Configuration Audit"
    assert result.status == "pass"
    assert result.rule_results == []
    assert result.findings == []
    assert result.summary["rules_total"] == 0
    assert result.duration_ms is not None


def test_template_audit_check_uses_provided_snapshot(empty_registry):
    """When a snapshot is passed via kwarg, the check uses it (does not build new)."""
    client = MagicMock()
    cfg = _minimal_config(template_audit_enabled=True)
    sentinel_snapshot = EnvSnapshot(client, full_scan=False, sample_size=500)

    captured: dict[str, object] = {}

    class _CaptureRule:
        rule_id = "tpl.capture_test"
        rule_name = "Capture snapshot identity"
        description = "Test rule"
        default_severity = "warn"
        expensive = False
        sources: list[str] = []

        def run(self, snapshot, severity, full_scan, sample_size, knobs):
            captured["snapshot"] = snapshot
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="pass",
                sources=list(self.sources),
            )

    _TEMPLATE_RULE_REGISTRY[_CaptureRule.rule_id] = _CaptureRule
    cfg_with_rule = _minimal_config(
        template_audit_enabled=True,
        rules={"tpl.capture_test": RuleConfig(enabled=True, severity="warn", knobs={})},
    )

    TemplateAuditCheck().run(client, cfg_with_rule, snapshot=sentinel_snapshot)

    assert captured["snapshot"] is sentinel_snapshot, (
        "orchestrator must reuse the passed snapshot rather than constructing a new one"
    )


def test_template_audit_check_registry_decorator_registers_rule(empty_registry):
    """@register_template_rule places the rule in _TEMPLATE_RULE_REGISTRY by rule_id."""

    @register_template_rule
    class _Demo:
        rule_id = "tpl.demo_register"
        rule_name = "Demo registration"
        description = "Test rule"
        default_severity = "warn"
        expensive = False
        sources: list[str] = []

        def run(self, snapshot, severity, full_scan, sample_size, knobs):
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="pass",
                sources=list(self.sources),
            )

    assert "tpl.demo_register" in _TEMPLATE_RULE_REGISTRY
    assert _TEMPLATE_RULE_REGISTRY["tpl.demo_register"] is _Demo


def test_template_audit_check_isolates_rule_errors(empty_registry):
    """A rule that raises produces a status='error' rule_result; other rules still run."""

    class _Boom:
        rule_id = "tpl.boom"
        rule_name = "Boom"
        description = "Always raises"
        default_severity = "warn"
        expensive = False
        sources: list[str] = []

        def run(self, snapshot, severity, full_scan, sample_size, knobs):
            raise RuntimeError("boom")

    class _Ok:
        rule_id = "tpl.ok"
        rule_name = "Ok"
        description = "Always passes"
        default_severity = "warn"
        expensive = False
        sources: list[str] = []

        def run(self, snapshot, severity, full_scan, sample_size, knobs):
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="pass",
                sources=list(self.sources),
            )

    _TEMPLATE_RULE_REGISTRY["tpl.boom"] = _Boom
    _TEMPLATE_RULE_REGISTRY["tpl.ok"] = _Ok

    cfg = _minimal_config(
        template_audit_enabled=True,
        rules={
            "tpl.boom": RuleConfig(enabled=True, severity="warn", knobs={}),
            "tpl.ok": RuleConfig(enabled=True, severity="warn", knobs={}),
        },
    )

    result = TemplateAuditCheck().run(MagicMock(), cfg)

    by_id = {r.rule_id: r for r in result.rule_results}
    assert by_id["tpl.boom"].status == "error"
    assert "boom" in (by_id["tpl.boom"].error or "")
    assert by_id["tpl.ok"].status == "pass"
    # Error roll-up: any error => check-level status fail
    assert result.status == "fail"


def test_template_audit_labels_builtin_findings_end_to_end(empty_registry):
    """Wiring check: a finding raised against a built-in template id is labelled
    (details['builtin']=True + clone guidance) by the time it leaves
    TemplateAuditCheck.run; a user-template finding is untouched.
    """
    from rapid7_healthcheck.checks import Finding

    class _TwoFindings:
        rule_id = "tpl.two"
        rule_name = "Two findings"
        description = "Emits one built-in and one user finding"
        default_severity = "warn"
        expensive = False
        sources: list[str] = []

        def run(self, snapshot, severity, full_scan, sample_size, knobs):
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="warn",
                findings=[
                    Finding(severity="warn", message="Built-in problem.",
                            details={"template_id": "exhaustive-audit"}),
                    Finding(severity="warn", message="User problem.",
                            details={"template_id": "acme-weekly"}),
                ],
                sources=list(self.sources),
            )

    _TEMPLATE_RULE_REGISTRY["tpl.two"] = _TwoFindings
    cfg = _minimal_config(
        template_audit_enabled=True,
        rules={"tpl.two": RuleConfig(enabled=True, severity="warn", knobs={})},
    )

    result = TemplateAuditCheck().run(MagicMock(), cfg)

    findings = result.rule_results[0].findings
    by_tid = {f.details["template_id"]: f for f in findings}
    assert by_tid["exhaustive-audit"].details["builtin"] is True
    assert "cloning" in by_tid["exhaustive-audit"].details["builtin_remediation"].lower()
    assert "builtin" not in by_tid["acme-weekly"].details
    # The flattened CheckResult.findings mirror carries the labelled copy too.
    flat = {f.details["template_id"]: f for f in result.findings}
    assert flat["exhaustive-audit"].details["builtin"] is True


def test_template_audit_skipped_when_check_disabled():
    """template_audit.enabled=False makes the orchestrator return status='skipped'
    without iterating the registry.

    Mirrors how UserPermissionAuditCheck.run handles disabled state.
    """
    cfg = _minimal_config(template_audit_enabled=False)
    result = TemplateAuditCheck().run(MagicMock(), cfg)
    assert result.status == "skipped"
    assert result.rule_results == []
    assert "template_audit.enabled" in result.summary.get("reason", "")
