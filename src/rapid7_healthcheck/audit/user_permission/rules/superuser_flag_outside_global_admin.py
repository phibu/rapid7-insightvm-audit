from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


@register_user_rule
class SuperuserFlagOutsideGlobalAdminRule(AuditRule):
    rule_id = "superuser_flag_outside_global_admin"
    rule_name = "Superuser Flag Outside Global Administrator"
    description = (
        "The `role.superuser` flag bypasses the standard RBAC checks "
        "regardless of the named role. On a properly configured console "
        "this flag should only ever appear on Global Administrator "
        "accounts. A non-GA user with the superuser flag is either a "
        "misconfiguration or an intentional privilege-escalation backdoor."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#assigning-roles-to-users",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        users = snapshot.users()

        findings: list[Finding] = []
        for u in users:
            role = u.get("role") or {}
            if not role.get("superuser"):
                continue
            if role.get("id") == "global-admin":
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"User '{u.get('login')}' has role.superuser=true but role "
                    f"is '{role.get('id', '?')}' (not global-admin)."
                ),
                details={
                    "user_id": u.get("id"),
                    "login": u.get("login"),
                    "role_id": role.get("id"),
                    "role_name": role.get("name"),
                    "enabled": bool(u.get("enabled")),
                },
            ))

        return self.result(
            findings,
            severity=severity,
            summary={"users_examined": len(users), "users_flagged": len(findings)},
            examined=len(users),
            failed=len(findings),
        )
