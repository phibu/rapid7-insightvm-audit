"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default — the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``.
"""

from __future__ import annotations

from rapid7_healthcheck.audit import Rule

_CLOUD_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_cloud_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a cloud-drift rule. Mirror of
    ``audit.register`` and ``audit.user_permission.register_user_rule``
    but for the third audit category.
    """
    _CLOUD_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls
