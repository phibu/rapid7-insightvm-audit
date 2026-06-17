"""Template Configuration audit category.

Fourth audit vertical, sibling to ``rapid7_healthcheck.audit`` (Configuration
Audit), ``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit),
and ``rapid7_healthcheck.audit.cloud_drift`` (Cloud Drift Audit).

Operates on scan-template configuration exposed by ``/api/3/scan_templates``
(via ``EnvSnapshot.templates_full()``). Rule files live under
``audit/template/rules/`` and self-register via ``@register_template_rule``
at import time. Rule modules are imported as a side effect of importing this
package, so the registry is populated whenever
``rapid7_healthcheck.audit.template`` is loaded (typically by ``__main__.py``).
"""

from __future__ import annotations

import logging
from typing import Any

from rapid7_healthcheck.audit import Rule
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


_TEMPLATE_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_template_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a template-audit rule. Mirror of ``audit.register``,
    ``audit.user_permission.register_user_rule``, and
    ``audit.cloud_drift.register_cloud_rule`` but for the fourth audit category.
    """
    _TEMPLATE_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


class TemplateAuditCheck:
    name = "Template Configuration Audit"
    description = (
        "Best-practice audits over the Security Console's scan templates. "
        "Reviews the ~50 tunable settings on each template (checks, "
        "discovery, web, policy, database, telnet) to catch silent "
        "misconfigurations that produce wrong scan results."
    )

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: EnvSnapshot | None = None,
        progress=None,
        **_kwargs: Any,
    ) -> CheckResult:
        from rapid7_healthcheck.audit._runner import AuditCategory, AuditRunner, GateDecision

        def gate(client, config, _cloud) -> GateDecision:
            return GateDecision(
                enabled=config.template_audit.enabled,
                skip_reason="template_audit.enabled is false",
            )

        def build_snapshot(client, config, _cloud) -> EnvSnapshot:
            # Accept an outer-owned snapshot when the caller provides one (future
            # cleanup path — see __main__._run_checks). Otherwise build our own,
            # which keeps sampling settings scoped to this audit's config block.
            if snapshot is not None:
                return snapshot
            return EnvSnapshot(
                client,
                full_scan=config.template_audit.full_scan,
                sample_size=config.template_audit.sample_size,
                agents_timeout_seconds=180,
            )

        category = AuditCategory(
            name=self.name,
            description=self.description,
            progress_prefix="template-audit",
            registry=_TEMPLATE_RULE_REGISTRY,
            rules_config=lambda c: c.template_audit.rules,
            full_scan=config.template_audit.full_scan,
            sample_size=config.template_audit.sample_size,
            gate=gate,
            build_snapshot=build_snapshot,
        )
        return AuditRunner().run(category, client=client, config=config, progress=progress)


# Side-effect imports: importing the rules subpackage executes its own
# side-effect block, which registers every rule module with the
# Template Configuration Audit registry. F1 lands with an empty registry;
# F2-F4 will append imports to ``audit/template/rules/__init__.py``.
from rapid7_healthcheck.audit.template import rules  # noqa: E402,F401
