from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding
from rapid7_healthcheck.client import Rapid7ClientError


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
        "without MFA are a separate, lower-priority concern. Requires the "
        "calling key to belong to a Global Administrator: per-user calls "
        "to /api/3/users/{id}/2FA return 401 for non-GA keys."
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
        users_succeeded = 0       # at least one 2FA call returned a status
        users_auth_denied: list[dict] = []  # 401s — disambiguated post-pass

        for u in examined:
            login = (u.get("login") or "").strip()
            if login.lower() in exempt:
                users_exempt += 1
                continue
            try:
                mfa = snapshot.user_2fa_enabled(u["id"])
            except Rapid7ClientError as e:
                if e.status_code == 401:
                    # Could be "user has no MFA" OR "calling key lacks GA";
                    # disambiguate post-pass once we know if any user succeeded.
                    users_auth_denied.append(u)
                    continue
                raise
            users_succeeded += 1
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

        # 404: endpoint absent on this console — preserve existing behavior.
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

        # 401 disambiguation: if no user succeeded, the calling key likely lacks GA.
        if users_auth_denied and users_succeeded == 0:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "All privileged users' 2FA status returned HTTP 401. The "
                        "calling key likely lacks Global Administrator privileges, "
                        "which this rule requires. Audit MFA in the Security "
                        "Console UI, or run the audit with a Global Admin key."
                    ),
                    details={"reason": "401 from /api/3/users/{id}/2FA across all users"},
                )],
                summary={
                    "privileged_users": len(privileged),
                    "users_examined": len(examined),
                    "users_auth_denied": len(users_auth_denied),
                    "users_succeeded": 0,
                    "endpoint_available": True,
                },
                sampled=sampled,
                sample_info=sample_info,
                sources=list(self.sources),
            )

        # At least one user succeeded — 401s on others mean "no MFA configured".
        for u in users_auth_denied:
            login = (u.get("login") or "").strip()
            users_without_mfa += 1
            role = u.get("role") or {}
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Privileged user '{login}' (role: {role.get('name', role.get('id', '?'))}) "
                    f"has no MFA configured (2FA endpoint returned 401)."
                ),
                details={
                    "user_id": u["id"],
                    "login": login,
                    "role_id": role.get("id"),
                    "role_name": role.get("name"),
                    "superuser": bool(role.get("superuser")),
                    "_2fa_status": "401",
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
