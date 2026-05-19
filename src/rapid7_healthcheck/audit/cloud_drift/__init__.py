"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default — the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``,
or when the cloud client could not be constructed (e.g. missing key).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.audit import (
    Rule,
    RuleResult,
    _extract_diagnostics,
    _flatten_findings,
    _rollup_audit_status,
)
from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


_CLOUD_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_cloud_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a cloud-drift rule. Mirror of
    ``audit.register`` and ``audit.user_permission.register_user_rule``
    but for the third audit category.
    """
    _CLOUD_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


class CloudDriftAuditCheck:
    name = "Cloud Drift Audit"
    description = (
        "Reconciles the on-prem Security Console with the InsightVM "
        "Cloud Integrations API (v4). Requires Insight Platform "
        "credentials in addition to the console API key; the entire "
        "category self-skips when cloud_integration is not configured."
    )

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        progress=None,
        cloud_client: Any = None,
    ) -> CheckResult:
        start = time.monotonic()

        if not config.cloud_integration.enabled or cloud_client is None:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "Cloud Drift audit skipped: cloud_integration is "
                        "disabled or the Insight Platform API key is not "
                        "configured. Set cloud_integration.enabled=true and "
                        "populate the env var named in cloud_integration."
                        "api_key_env to enable."
                    ),
                    details={"reason": "cloud_integration disabled or cloud_client unavailable"},
                )],
                summary={"reason": "cloud_integration disabled or cloud_client unavailable"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        # Footgun: user enables cloud_integration but forgets to add a
        # cloud_drift.rules block. Every rule falls into the rule_cfg-is-None
        # branch and is silently skipped, producing a deceptively green
        # report. Emit one INFO line so the operator sees what happened.
        if not config.cloud_drift.rules:
            logger.info(
                "cloud_integration is enabled but no cloud_drift rules are "
                "configured; every cloud-drift rule will be skipped. Add a "
                "`cloud_drift.rules:` block to config.yaml to enable rules."
            )

        snapshot = CloudSnapshot(v3_client=client, cloud_client=cloud_client)

        rule_results: list[RuleResult] = []
        total_rules = len(_CLOUD_RULE_REGISTRY)
        for rule_idx, (rule_id, rule_cls) in enumerate(_CLOUD_RULE_REGISTRY.items(), start=1):
            rule_cfg = config.cloud_drift.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                if progress is not None:
                    skipped_label = f"cloud-drift: {rule_id} (skipped)"
                    progress.step(rule_idx, total_rules, skipped_label)
                    progress.done(rule_idx, total_rules, skipped_label, duration_ms=0)
                continue
            label = f"cloud-drift: {rule_id}"
            if progress is not None:
                progress.step(rule_idx, total_rules, label)
            rule_start = time.monotonic()
            try:
                try:
                    # full_scan + sample_size are part of the Rule.run protocol
                    # but cloud-drift rules read aggregate counts (never sample),
                    # so we pass the protocol defaults: full_scan=False, sample_size=500.
                    result = rule_cls().run(
                        snapshot,
                        rule_cfg.severity,
                        False,
                        500,
                        rule_cfg.knobs,
                    )
                    result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                    rule_results.append(result)
                except Exception as e:
                    logger.exception("cloud-drift rule %s raised", rule_id)
                    error_path, error_status_code = _extract_diagnostics(e)
                    rule_results.append(RuleResult(
                        rule_id=rule_id,
                        rule_name=rule_cls.rule_name,
                        description=rule_cls.description,
                        severity=rule_cfg.severity,
                        status="error",
                        sources=list(rule_cls.sources),
                        error=str(e),
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                        error_path=error_path,
                        error_status_code=error_status_code,
                    ))
            finally:
                if progress is not None:
                    progress.done(
                        rule_idx, total_rules, label,
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                    )

        return CheckResult(
            name=self.name,
            description=self.description,
            status=_rollup_audit_status(rule_results),
            findings=_flatten_findings(rule_results),
            summary={
                "rules_total": len(rule_results),
                "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
                "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
                "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
                "rules_error": sum(1 for r in rule_results if r.status == "error"),
                "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )


# Side-effect imports: register all 3 cloud-drift rules at package-import time.
# Adding a new rule = one new file under `audit/cloud_drift/rules/` + one line here.
from rapid7_healthcheck.audit.cloud_drift.rules import (  # noqa: E402,F401
    console_asset_count_drift,
    scan_engine_cloud_registration,
    stale_assessment_cohort,
)
