from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


def _has_bindings(user: dict) -> bool:
    role = user.get("role") or {}
    # role["id"] is the role-name string ("global-admin", "user", etc.) on
    # this endpoint, not a numeric identifier — truthy means the user is
    # bound to a role.
    return bool(
        role.get("id")
        or role.get("allSites")
        or role.get("allAssetGroups")
        or role.get("privileges")
    )


@register_user_rule
class DisabledUserWithRoleBindingsRule(AuditRule):
    rule_id = "disabled_user_with_role_bindings"
    rule_name = "Disabled User With Active Role Bindings"
    description = (
        "Disabled accounts that still hold role assignments are a hygiene "
        "concern: re-enabling the account silently restores all prior "
        "privileges. Cleanup signal — not a security risk in itself."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#disabling-a-user-account",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        users = snapshot.users()

        findings: list[Finding] = []
        flagged = 0
        for u in users:
            if u.get("enabled"):
                continue
            if not _has_bindings(u):
                continue
            flagged += 1
            role = u.get("role") or {}
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Disabled user '{u.get('login')}' still has role "
                    f"'{role.get('name', role.get('id', '?'))}' assigned."
                ),
                details={
                    "user_id": u.get("id"),
                    "login": u.get("login"),
                    "role_id": role.get("id"),
                    "role_name": role.get("name"),
                },
            ))

        return self.result(
            findings,
            severity=severity,
            summary={"users_examined": len(users), "users_flagged": flagged},
            examined=len(users),
            failed=flagged,
        )
