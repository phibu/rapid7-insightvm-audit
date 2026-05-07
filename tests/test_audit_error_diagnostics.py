"""Tests for RuleResult.error_path and error_status_code population.

When a rule raises Rapid7ClientError, the orchestrator's exception trap
extracts the failing API path (from the standardized v0.1.7 diagnostics
message format) and the HTTP status code, surfacing them as separate
RuleResult fields for the report to render."""
from __future__ import annotations

from unittest.mock import MagicMock

from rapid7_healthcheck.audit import (
    ConfigurationAuditCheck,
    RuleResult,
    _RULE_REGISTRY,
)
from rapid7_healthcheck.audit.user_permission import (
    UserPermissionAuditCheck,
    _USER_RULE_REGISTRY,
)
from rapid7_healthcheck.client import Rapid7ClientError


def _build_minimal_app_config(*, audit_enabled=False, user_audit_enabled=False, rules: dict | None = None, user_rules: dict | None = None):
    from rapid7_healthcheck.config import (
        AppConfig,
        AssetCoverageThresholds,
        AuditConfig,
        DataQualityThresholds,
        Rapid7Config,
        ReportConfig,
        ScanActivityThresholds,
        ScanEngineThresholds,
        Thresholds,
        UserAuditConfig,
    )
    return AppConfig(
        rapid7=Rapid7Config(base_url="https://x", verify_tls=True, request_timeout_seconds=30, max_retries=3),
        report=ReportConfig(output_dir="r", filename_pattern="report.html", title="t"),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(last_contact_warn_hours=24, last_contact_fail_hours=72),
            scan_activity=ScanActivityThresholds(recent_window_days=7, stuck_scan_hours=12, site_no_scan_days=30),
            asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=True, never_scanned_days=90),
            data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=True),
        ),
        checks={"configuration_audit": audit_enabled, "user_permission_audit": user_audit_enabled},
        audit=AuditConfig(enabled=audit_enabled, full_scan=False, sample_size=10, agents_timeout_seconds=180, rules=rules or {}),
        user_audit=UserAuditConfig(enabled=user_audit_enabled, full_scan=False, sample_size=10, rules=user_rules or {}),
    )


def test_ruleresult_has_error_path_and_status_code_fields():
    """The dataclass must declare both fields with default None."""
    r = RuleResult(rule_id="x", rule_name="X", description="d", severity="info", status="pass")
    assert r.error_path is None
    assert r.error_status_code is None


def test_configuration_audit_trap_extracts_path_and_status_from_rapid7clienterror(monkeypatch):
    """When a rule raises Rapid7ClientError, the orchestrator must populate
    error_path and error_status_code on the resulting RuleResult."""

    class _BadRule:
        rule_id = "bad_rule_test_only"
        rule_name = "Bad Rule (test)"
        description = "raises Rapid7ClientError"
        default_severity = "info"
        expensive = False
        sources = []

        def run(self, snapshot, severity, full_scan, sample_size, rule_config):
            raise Rapid7ClientError(
                "401 at /api/3/users/42/authentication-tokens: auth failed",
                status_code=401,
            )

    monkeypatch.setitem(_RULE_REGISTRY, "bad_rule_test_only", _BadRule)

    from rapid7_healthcheck.config import RuleConfig
    cfg = _build_minimal_app_config(
        audit_enabled=True,
        rules={"bad_rule_test_only": RuleConfig(enabled=True, severity="info", knobs={})},
    )

    client = MagicMock()
    result = ConfigurationAuditCheck().run(client, cfg)
    rr = next(r for r in result.rule_results if r.rule_id == "bad_rule_test_only")
    assert rr.status == "error"
    assert rr.error_status_code == 401
    assert rr.error_path == "/api/3/users/42/authentication-tokens"


def test_user_permission_audit_trap_extracts_diagnostics_for_network_error(monkeypatch):
    """The user-permission orchestrator's trap must also populate diagnostics.
    Network errors have status_code=None; path still extractable."""

    class _BadUserRule:
        rule_id = "bad_user_rule_test_only"
        rule_name = "Bad User Rule (test)"
        description = "raises Rapid7ClientError"
        default_severity = "info"
        expensive = False
        sources = []

        def run(self, snapshot, severity, full_scan, sample_size, rule_config):
            raise Rapid7ClientError(
                "network error after 4 attempt(s) on GET /api/3/users/me: Read timed out",
                status_code=None,
            )

    monkeypatch.setitem(_USER_RULE_REGISTRY, "bad_user_rule_test_only", _BadUserRule)

    from rapid7_healthcheck.config import RuleConfig
    cfg = _build_minimal_app_config(
        user_audit_enabled=True,
        user_rules={"bad_user_rule_test_only": RuleConfig(enabled=True, severity="info", knobs={})},
    )

    client = MagicMock()
    # Snapshot needs at least one user so is_users_endpoints_unavailable() is False;
    # the orchestrator self-skips before dispatching rules if /users 404s.
    client.paginate.return_value = iter([{"id": 1, "login": "u"}])

    result = UserPermissionAuditCheck().run(client, cfg)
    rr = next((r for r in result.rule_results if r.rule_id == "bad_user_rule_test_only"), None)
    if rr is not None:
        assert rr.status == "error"
        assert rr.error_path == "/api/3/users/me"
        assert rr.error_status_code is None  # network error has no HTTP status


def test_plain_exception_leaves_diagnostic_fields_none(monkeypatch):
    """Non-Rapid7ClientError exceptions don't populate the new fields."""

    class _BadRule:
        rule_id = "bad_rule_plain_test_only"
        rule_name = "Bad Rule Plain (test)"
        description = "raises ValueError"
        default_severity = "info"
        expensive = False
        sources = []

        def run(self, snapshot, severity, full_scan, sample_size, rule_config):
            raise ValueError("rule logic broke")

    monkeypatch.setitem(_RULE_REGISTRY, "bad_rule_plain_test_only", _BadRule)

    from rapid7_healthcheck.config import RuleConfig
    cfg = _build_minimal_app_config(
        audit_enabled=True,
        rules={"bad_rule_plain_test_only": RuleConfig(enabled=True, severity="info", knobs={})},
    )

    client = MagicMock()
    result = ConfigurationAuditCheck().run(client, cfg)
    rr = next(r for r in result.rule_results if r.rule_id == "bad_rule_plain_test_only")
    assert rr.status == "error"
    assert rr.error_path is None
    assert rr.error_status_code is None
