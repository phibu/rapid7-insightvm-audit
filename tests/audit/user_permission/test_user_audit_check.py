"""Orchestrator-level tests for UserPermissionAuditCheck.

These tests build a real AppConfig and exercise the orchestrator end-to-end
against a mock client, verifying the disabled / unavailable / error-isolation
paths.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from rapid7_healthcheck.audit.user_permission import UserPermissionAuditCheck
from rapid7_healthcheck.config import (
    AppConfig, AssetCoverageThresholds, DataQualityThresholds, Rapid7Config,
    ReportConfig, RuleConfig, ScanActivityThresholds, ScanEngineThresholds,
    Thresholds, UserAuditConfig,
)


def _base_config(*, user_audit_enabled: bool = True, rules: dict | None = None) -> AppConfig:
    if rules is None:
        rules = {
            "privileged_user_without_mfa": RuleConfig(enabled=True, severity="fail", knobs={}),
            "local_account_when_sso_configured": RuleConfig(enabled=True, severity="warn", knobs={}),
            "multiple_global_administrators": RuleConfig(enabled=True, severity="warn", knobs={}),
            "locked_user_account": RuleConfig(enabled=True, severity="warn", knobs={}),
            "disabled_user_with_role_bindings": RuleConfig(enabled=True, severity="info", knobs={}),
            "user_with_role_but_no_access": RuleConfig(enabled=True, severity="info", knobs={}),
            "superuser_flag_outside_global_admin": RuleConfig(enabled=True, severity="fail", knobs={}),
        }
    return AppConfig(
        rapid7=Rapid7Config(base_url="https://x", verify_tls=True, request_timeout_seconds=30, max_retries=3),
        report=ReportConfig(output_dir=".", filename_pattern="x", title="t"),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(2, 24),
            scan_activity=ScanActivityThresholds(7, 24, 14),
            asset_coverage=AssetCoverageThresholds(30, True),
            data_quality=DataQualityThresholds(True, True),
        ),
        checks={"scan_engines": False, "scan_activity": False, "asset_coverage": False, "data_quality": False, "configuration_audit": False, "user_permission_audit": True},
        user_audit=UserAuditConfig(enabled=user_audit_enabled, full_scan=False, sample_size=500, rules=rules),
    )


class _StubClient:
    """Minimal stub: serves a small users list, no SSO sources, no 2FA, no locks."""
    def __init__(self, *, users_404: bool = False):
        self._users_404 = users_404

    def get(self, path, params=None):
        if path == "/api/3/authentication_sources":
            return {"resources": []}
        if path.startswith("/api/3/users/") and path.endswith("/2FA"):
            return {"key": "ABC"}
        return {"resources": []}

    def paginate(self, path, params=None, page_size=500):
        if path == "/api/3/users":
            if self._users_404:
                from rapid7_healthcheck.client import Rapid7ClientError
                raise Rapid7ClientError("HTTP 404 from GET /api/3/users: not found", status_code=404)
            yield from [
                {"id": 1, "login": "alice", "enabled": True, "locked": False,
                 "authentication": {"type": "saml"},
                 "role": {"id": "global-admin", "name": "GA", "superuser": True, "allSites": True, "allAssetGroups": True}},
                {"id": 2, "login": "bob", "enabled": True, "locked": False,
                 "authentication": {"type": "saml"},
                 "role": {"id": "global-admin", "name": "GA", "superuser": True, "allSites": True, "allAssetGroups": True}},
            ]
            return
        yield from []


def test_skipped_when_user_audit_disabled():
    cfg = _base_config(user_audit_enabled=False)
    r = UserPermissionAuditCheck().run(_StubClient(), cfg)
    assert r.status == "skipped"
    assert r.summary["reason"] == "user_audit.enabled is false"


def test_self_skip_when_users_endpoint_unavailable():
    cfg = _base_config()
    r = UserPermissionAuditCheck().run(_StubClient(users_404=True), cfg)
    assert r.status == "skipped"
    assert "users endpoint" in r.summary["reason"].lower()
    # And the info finding tells the operator why.
    assert any("404" in f.message for f in r.findings)


def test_runs_all_seven_rules_when_enabled():
    cfg = _base_config()
    r = UserPermissionAuditCheck().run(_StubClient(), cfg)
    rule_ids = {rr.rule_id for rr in r.rule_results}
    assert rule_ids == {
        "privileged_user_without_mfa",
        "local_account_when_sso_configured",
        "multiple_global_administrators",
        "locked_user_account",
        "disabled_user_with_role_bindings",
        "user_with_role_but_no_access",
        "superuser_flag_outside_global_admin",
    }
    assert r.summary["rules_total"] == 7


def test_disabled_rule_appears_as_skipped():
    cfg = _base_config(rules={
        "privileged_user_without_mfa": RuleConfig(enabled=False, severity="fail", knobs={}),
    })
    r = UserPermissionAuditCheck().run(_StubClient(), cfg)
    skipped = [rr for rr in r.rule_results if rr.status == "skipped"]
    # Six rules NOT in the config dict will also be marked skipped.
    assert len(skipped) == 7
