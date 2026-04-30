from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


def _is_privileged(user: dict) -> bool:
    role = user.get("role") or {}
    return bool(role.get("superuser")) or role.get("id") == "global-admin"


@register_user_rule
class PrivilegedUserWithoutMfaRule:
    rule_id = "privileged_user_without_mfa"
    rule_name = "Privileged User Without MFA"
    description = (
        "Flags Global Administrator or superuser accounts that do not have "
        "two-factor authentication configured. Service accounts that need "
        "to authenticate via HTTP Basic Auth necessarily can't use MFA "
        "(the protocol bypasses it); list those in the rule's "
        "mfa_exempt_logins knob to suppress findings on them. The rule is "
        "scoped to privileged accounts only — non-privileged accounts "
        "without MFA are a separate, lower-priority concern."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#enabling-two-factor-authentication",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        exempt = {
            login.strip().lower()
            for login in rule_config.get("mfa_exempt_logins") or []
            if isinstance(login, str)
        }

        users = snapshot.users()
        privileged = [u for u in users if u.get("enabled") and _is_privileged(u)]

        sampled = False
        sample_info: str | None = None
        examined = privileged
        if not full_scan and len(privileged) > sample_size:
            examined = privileged[:sample_size]
            sampled = True
            sample_info = f"checked {len(examined)} of {len(privileged)} privileged users"

        findings: list[Finding] = []
        endpoint_unavailable = False
        users_without_mfa = 0
        users_exempt = 0

        for u in examined:
            login = (u.get("login") or "").strip()
            if login.lower() in exempt:
                users_exempt += 1
                continue
            mfa = snapshot.user_2fa_enabled(u["id"])
            if mfa is None:
                # Endpoint not available on this console at all — skip the rule honestly.
                endpoint_unavailable = True
                break
            if mfa is False:
                users_without_mfa += 1
                role = u.get("role") or {}
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Privileged user '{login}' (role: {role.get('name', role.get('id', '?'))}) "
                        f"has no MFA configured."
                    ),
                    details={
                        "user_id": u["id"],
                        "login": login,
                        "role_id": role.get("id"),
                        "role_name": role.get("name"),
                        "superuser": bool(role.get("superuser")),
                    },
                ))

        if endpoint_unavailable:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "MFA-status endpoint /api/3/users/{id}/2FA returned 404 — "
                        "this console does not expose 2FA state via API. Audit MFA in the UI."
                    ),
                    details={"reason": "2FA endpoint unavailable"},
                )],
                summary={
                    "privileged_users": len(privileged),
                    "users_examined": len(examined),
                    "endpoint_available": False,
                },
                sampled=sampled,
                sample_info=sample_info,
                sources=list(self.sources),
            )

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
            summary={
                "privileged_users": len(privileged),
                "users_examined": len(examined),
                "users_without_mfa": users_without_mfa,
                "users_exempt": users_exempt,
            },
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
