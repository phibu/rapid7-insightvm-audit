"""User & Permission audit category.

Sibling to the configuration audit (see ``rapid7_healthcheck.audit``).
Operates on user / RBAC data exposed by ``/api/3/users`` and friends.

Rule files live under ``audit/user_permission/rules/`` and self-register
via ``@register_user_rule`` at import time. The package's
``__main__.py`` imports each rule module so the registry is populated
before any audit runs.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.audit import RuleResult, Rule, _flatten_findings, _rollup_audit_status
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


_USER_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_user_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a user-audit rule. Mirror of ``audit.register``
    but for the separate user-audit category."""
    _USER_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


class UserPermissionAuditCheck:
    name = "User & Permission Audit"
    description = (
        "Best-practice audits over the Security Console's user accounts, "
        "roles, and authentication settings. Requires the API key to "
        "belong to a Global Administrator."
    )

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()

        if not config.user_audit.enabled:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[],
                summary={"reason": "user_audit.enabled is false"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        from rapid7_healthcheck.audit.snapshot import EnvSnapshot
        snapshot = EnvSnapshot(
            client,
            full_scan=config.user_audit.full_scan,
            sample_size=config.user_audit.sample_size,
        )

        # Prime the users endpoint once; if it 404s the entire category
        # self-skips honestly rather than firing 7 rules that all fail.
        snapshot.users()
        if snapshot.is_users_endpoints_unavailable():
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "User & Permission audit skipped: /api/3/users is "
                        "not available on this console (404). The API key "
                        "may not have Global Administrator privileges, or "
                        "this hosted console doesn't expose the users "
                        "endpoint."
                    ),
                    details={"reason": "users endpoint returned 404"},
                )],
                summary={"reason": "users endpoint unavailable"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        rule_results: list[RuleResult] = []
        for rule_id, rule_cls in _USER_RULE_REGISTRY.items():
            rule_cfg = config.user_audit.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                continue
            rule_start = time.monotonic()
            try:
                result = rule_cls().run(
                    snapshot,
                    rule_cfg.severity,
                    config.user_audit.full_scan,
                    config.user_audit.sample_size,
                    rule_cfg.knobs,
                )
                result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                rule_results.append(result)
            except Exception as e:
                logger.exception("user audit rule %s raised", rule_id)
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity=rule_cfg.severity,
                    status="error",
                    sources=list(rule_cls.sources),
                    error=str(e),
                    duration_ms=int((time.monotonic() - rule_start) * 1000),
                ))

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
