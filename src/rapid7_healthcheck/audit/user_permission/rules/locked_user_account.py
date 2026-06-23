from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


@register_user_rule
class LockedUserAccountRule(AuditRule):
    rule_id = "locked_user_account"
    rule_name = "Locked User Account"
    description = (
        "User accounts in the locked state. A lockout is either a stuck "
        "account that needs cleanup, or an active brute-force indicator "
        "worth investigating. Either way it deserves operator attention."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#unlocking-a-user-account",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        users = snapshot.users()

        findings: list[Finding] = []
        locked_count = 0
        for u in users:
            if not u.get("locked"):
                continue
            locked_count += 1
            findings.append(Finding(
                severity=severity,
                message=f"User '{u.get('login')}' is locked.",
                details={
                    "user_id": u.get("id"),
                    "login": u.get("login"),
                    "name": u.get("name"),
                    "enabled": bool(u.get("enabled")),
                },
            ))

        return self.result(
            findings,
            severity=severity,
            summary={"users_examined": len(users), "locked_count": locked_count},
            examined=len(users),
            failed=locked_count,
        )
