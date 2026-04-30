"""Tests for UserPermissionAuditCheck orchestrator self-skip behavior.

Pins the explicit short-circuit in UserPermissionAuditCheck.run() that turns a
missing /api/3/users endpoint into a clean status='skipped' with one info
finding, rather than 7 rule-level errors with the same root cause.

Note: additional orchestrator coverage (disabled check, all-7-rules, disabled
rule) lives in tests/audit/user_permission/test_user_audit_check.py.  This
file focuses on the MagicMock-based 404 path to exercise the mock-based
pattern documented in CLAUDE.md.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from rapid7_healthcheck.audit.user_permission import UserPermissionAuditCheck
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.config import (
    AppConfig,
    AssetCoverageThresholds,
    DataQualityThresholds,
    Rapid7Config,
    ReportConfig,
    ScanActivityThresholds,
    ScanEngineThresholds,
    Thresholds,
    UserAuditConfig,
)


def _minimal_config(*, user_audit_enabled: bool = True) -> AppConfig:
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
            asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=True),
            data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=True),
        ),
        checks={
            "scan_engines": False,
            "scan_activity": False,
            "asset_coverage": False,
            "data_quality": False,
            "configuration_audit": False,
            "user_permission_audit": True,
        },
        user_audit=UserAuditConfig(
            enabled=user_audit_enabled,
            full_scan=False,
            sample_size=500,
            rules={},
        ),
    )


def test_self_skips_cleanly_when_users_endpoint_returns_404():
    """When /api/3/users returns 404 (on-prem or non-admin key), the orchestrator
    must short-circuit to status='skipped' rather than firing 7 rules that all
    error out with the same root cause.

    Uses MagicMock so we exercise the exact client.paginate call path that
    EnvSnapshot.users() uses, confirming no other mocking glue is needed.
    """
    client = MagicMock()
    # EnvSnapshot.users() calls self._client.paginate("/api/3/users").
    # Raising here triggers the 404 self-skip path in the orchestrator.
    client.paginate.side_effect = Rapid7ClientError(
        "HTTP 404 from GET /api/3/users: not found",
        status_code=404,
    )

    cfg = _minimal_config(user_audit_enabled=True)
    result = UserPermissionAuditCheck().run(client, cfg)

    assert result.status == "skipped", f"expected skipped, got {result.status!r}"
    assert "users endpoint" in result.summary.get("reason", "").lower(), (
        f"expected reason to mention users endpoint, got {result.summary!r}"
    )
    assert result.rule_results == [], (
        f"expected empty rule_results on self-skip, got {result.rule_results!r}"
    )
    assert len(result.findings) == 1, (
        f"expected exactly 1 info finding, got {len(result.findings)}"
    )
    assert result.findings[0].severity == "info", (
        f"expected info severity, got {result.findings[0].severity!r}"
    )
