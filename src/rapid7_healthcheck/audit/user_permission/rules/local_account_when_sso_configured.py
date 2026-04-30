from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_MAX_LOCAL = 2


@register_user_rule
class LocalAccountWhenSsoConfiguredRule:
    rule_id = "local_account_when_sso_configured"
    rule_name = "Local Accounts When SSO Is Configured"
    description = (
        "When LDAP, Kerberos, or SAML is configured, local (`normal`) "
        "accounts should be the exception (break-glass / service accounts). "
        "Excessive local accounts when SSO is available bypasses central "
        "identity governance. Threshold is configurable via the "
        "`max_local_accounts_when_sso` knob."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#configuring-external-authentication",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_local = int(rule_config.get("max_local_accounts_when_sso", _DEFAULT_MAX_LOCAL))

        sources = snapshot.authentication_sources()
        external_sources = [s for s in sources if s.get("external")]
        if not external_sources:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[],
                summary={"reason": "no external authentication source configured"},
                sources=list(self.sources),
            )

        users = snapshot.users()
        local_users = [
            u for u in users
            if u.get("enabled") and ((u.get("authentication") or {}).get("type") == "normal")
        ]

        findings: list[Finding] = []
        if len(local_users) > max_local:
            findings.append(Finding(
                severity=severity,
                message=(
                    f"{len(local_users)} enabled local (`normal` auth) accounts found "
                    f"with SSO configured (threshold {max_local}). Limit local accounts "
                    f"to break-glass and dedicated service accounts."
                ),
                details={
                    "local_user_count": len(local_users),
                    "threshold": max_local,
                    "external_sources": [s.get("name") for s in external_sources],
                    "local_logins": [u.get("login") for u in local_users][:20],
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
                "local_user_count": len(local_users),
                "external_source_count": len(external_sources),
                "threshold": max_local,
            },
            sources=list(self.sources),
        )
