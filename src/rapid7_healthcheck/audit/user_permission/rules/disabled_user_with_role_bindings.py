from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


def _has_bindings(user: dict) -> bool:
    role = user.get("role") or {}
    return bool(
        role.get("id")
        or role.get("allSites")
        or role.get("allAssetGroups")
        or role.get("privileges")
    )


@register_user_rule
class DisabledUserWithRoleBindingsRule:
    rule_id = "disabled_user_with_role_bindings"
    rule_name = "Disabled User With Active Role Bindings"
    description = (
        "Disabled accounts that still hold role assignments are a hygiene "
        "concern: re-enabling the account silently restores all prior "
        "privileges. Cleanup signal — not a security risk in itself."
    )
    default_severity = "info"
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

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"users_examined": len(users), "users_flagged": flagged},
            sources=list(self.sources),
        )
