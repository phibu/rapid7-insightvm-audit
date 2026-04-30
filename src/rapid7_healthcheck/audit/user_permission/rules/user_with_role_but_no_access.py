from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding


@register_user_rule
class UserWithRoleButNoAccessRule:
    rule_id = "user_with_role_but_no_access"
    rule_name = "User Has Role But No Site or Asset Group Access"
    description = (
        "Users with a non-Global role but no `allSites`, no `allAssetGroups`, "
        "and no explicit per-site/per-asset-group binding cannot actually "
        "do anything. Misconfiguration: either the user's access binding "
        "was never set up, or the user is stale and the role should be "
        "removed entirely."
    )
    default_severity = "info"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#assigning-roles-to-users",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        users = snapshot.users()

        # Pre-filter to candidates that COULD be in the failure mode, before
        # spending HTTP calls on the per-user fan-out.
        candidates = []
        for u in users:
            if not u.get("enabled"):
                continue
            role = u.get("role") or {}
            if not role.get("id"):
                continue
            # Global Administrators implicitly have access to everything;
            # superuser is by definition a wildcard. Skip both.
            if role.get("id") == "global-admin" or role.get("superuser"):
                continue
            if role.get("allSites") or role.get("allAssetGroups"):
                continue
            candidates.append(u)

        sampled = False
        sample_info: str | None = None
        examined = candidates
        if not full_scan and len(candidates) > sample_size:
            examined = candidates[:sample_size]
            sampled = True
            sample_info = f"checked {len(examined)} of {len(candidates)} candidate users"

        findings: list[Finding] = []
        for u in examined:
            if snapshot.user_sites(u["id"]):
                continue
            if snapshot.user_asset_groups(u["id"]):
                continue
            role = u.get("role") or {}
            findings.append(Finding(
                severity=severity,
                message=(
                    f"User '{u.get('login')}' has role "
                    f"'{role.get('name', role.get('id'))}' but no site or "
                    f"asset-group access."
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
            summary={
                "candidates": len(candidates),
                "users_examined": len(examined),
                "users_flagged": len(findings),
            },
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
