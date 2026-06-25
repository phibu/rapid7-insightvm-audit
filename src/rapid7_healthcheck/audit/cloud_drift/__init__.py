"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default -- the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``,
or when the cloud client could not be constructed (e.g. missing key).
"""

from __future__ import annotations

import logging
from typing import Any

from rapid7_healthcheck.audit import Rule
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
        **_kwargs: Any,
    ) -> CheckResult:
        # Accepts the uniform check-dispatch kwarg superset (see CONTEXT.md
        # "Check dispatch"); uses progress and cloud_client.
        from rapid7_healthcheck.audit._runner import AuditCategory, AuditRunner, GateDecision

        def gate(client, config, cloud_client) -> GateDecision:
            if not config.cloud_integration.enabled or cloud_client is None:
                return GateDecision(
                    enabled=False,
                    skip_reason="cloud_integration disabled or cloud_client unavailable",
                    skip_finding=Finding(
                        severity="info",
                        message=(
                            "Cloud Drift audit skipped: cloud_integration is "
                            "disabled or the Insight Platform API key is not "
                            "configured. Set cloud_integration.enabled=true and "
                            "populate the env var named in cloud_integration."
                            "api_key_env to enable."
                        ),
                        details={"reason": "cloud_integration disabled or cloud_client unavailable"},
                    ),
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
            return GateDecision(enabled=True)

        category = AuditCategory(
            name=self.name,
            description=self.description,
            progress_prefix="cloud-drift",
            registry=_CLOUD_RULE_REGISTRY,
            rules_config=lambda c: c.cloud_drift.rules,
            # full_scan + sample_size are part of the Rule.run protocol but
            # cloud-drift rules read aggregate counts (never sample), so we
            # pass the protocol defaults: full_scan=False, sample_size=500.
            full_scan=False,
            sample_size=500,
            gate=gate,
            build_snapshot=lambda client, config, cloud_client: CloudSnapshot(
                v3_client=client, cloud_client=cloud_client
            ),
        )
        return AuditRunner().run(
            category, client=client, config=config, progress=progress, cloud_client=cloud_client
        )


# Register every cloud-drift rule at package-import time. The directory is the
# single source of truth -- see CONTEXT.md "Rule registration".
from rapid7_healthcheck._rule_loader import load_rules  # noqa: E402

load_rules("rapid7_healthcheck.audit.cloud_drift.rules")
