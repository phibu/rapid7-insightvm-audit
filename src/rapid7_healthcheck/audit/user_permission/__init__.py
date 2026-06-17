"""User & Permission audit category.

Sibling to the configuration audit (see ``rapid7_healthcheck.audit``).
Operates on user / RBAC data exposed by ``/api/3/users`` and friends.

Rule files live under ``audit/user_permission/rules/`` and self-register
via ``@register_user_rule`` at import time. Rule modules are imported as
a side effect of importing this package, so the registry is populated
whenever ``rapid7_healthcheck.audit.user_permission`` is loaded
(typically by ``__main__.py``).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.audit import Rule
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
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

    def run(self, client: Any, config: AppConfig, *, progress=None) -> CheckResult:
        from rapid7_healthcheck.audit._runner import AuditCategory, AuditRunner, GateDecision

        def gate(client, config, _cloud) -> GateDecision:
            return GateDecision(
                enabled=config.user_audit.enabled,
                skip_reason="user_audit.enabled is false",
            )

        def build_snapshot(client, config, _cloud) -> EnvSnapshot:
            return EnvSnapshot(
                client,
                full_scan=config.user_audit.full_scan,
                sample_size=config.user_audit.sample_size,
                agents_timeout_seconds=180,
            )

        def prime(snapshot, category, start) -> CheckResult | None:
            # Prime the users endpoint once; if it 404s the entire category
            # self-skips honestly rather than firing 7 rules that all fail.
            snapshot.users()
            if not snapshot.is_users_endpoints_unavailable():
                return None
            return CheckResult(
                name=category.name,
                description=category.description,
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

        category = AuditCategory(
            name=self.name,
            description=self.description,
            progress_prefix="user-audit",
            registry=_USER_RULE_REGISTRY,
            rules_config=lambda c: c.user_audit.rules,
            full_scan=config.user_audit.full_scan,
            sample_size=config.user_audit.sample_size,
            gate=gate,
            build_snapshot=build_snapshot,
            prime=prime,
        )
        return AuditRunner().run(category, client=client, config=config, progress=progress)


# Side-effect imports: register all 7 user-permission audit rules at
# package-import time. Adding a new rule = one new file under
# `audit/user_permission/rules/` + one line here.
from rapid7_healthcheck.audit.user_permission.rules import (  # noqa: E402,F401
    privileged_user_without_mfa,
    local_account_when_sso_configured,
    multiple_global_administrators,
    locked_user_account,
    disabled_user_with_role_bindings,
    user_with_role_but_no_access,
    superuser_flag_outside_global_admin,
)
