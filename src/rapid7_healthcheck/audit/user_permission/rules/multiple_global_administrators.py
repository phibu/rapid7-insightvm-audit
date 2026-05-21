from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_MAX_GA = 2


@register_user_rule
class MultipleGlobalAdministratorsRule:
    rule_id = "multiple_global_administrators"
    rule_name = "Multiple Global Administrators"
    description = (
        "Privilege creep is one of the slowest-burn risks in Security "
        "Console operation: every long-lived account with Global "
        "Administrator can change scan scope, exfiltrate vulnerability "
        "data, or disable the audit trail. Two GAs is the minimum for "
        "redundancy; more should be the result of an explicit decision. "
        "Configurable via `max_global_administrators`."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#assigning-roles-to-users",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_ga = int(rule_config.get("max_global_administrators", _DEFAULT_MAX_GA))

        users = snapshot.users()
        gas = [
            u for u in users
            if u.get("enabled") and ((u.get("role") or {}).get("id") == "global-admin")
        ]

        findings: list[Finding] = []
        if len(gas) == 0:
            # No enabled Global Administrator at all — a console no one can
            # administer. Hard-coded "fail" regardless of configured
            # severity: this is unambiguously broken, not a tuning matter.
            findings.append(Finding(
                severity="fail",
                message=(
                    "No enabled Global Administrator accounts found. The "
                    "Security Console has no account that can manage users, "
                    "scan scope, or the audit trail. Restore or create a "
                    "Global Administrator immediately."
                ),
                details={"ga_count": 0},
            ))
        elif len(gas) > max_ga:
            findings.append(Finding(
                severity=severity,
                message=(
                    f"{len(gas)} enabled Global Administrators found "
                    f"(recommended maximum {max_ga}). Demote unnecessary admins "
                    f"to a least-privilege role."
                ),
                details={
                    "ga_count": len(gas),
                    "threshold": max_ga,
                    "ga_logins": [u.get("login") for u in gas],
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
            summary={"ga_count": len(gas), "threshold": max_ga},
            sources=list(self.sources),
        )
