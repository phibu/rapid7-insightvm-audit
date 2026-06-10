from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import Finding


_HIGH_IMPORTANCE = {"high", "very_high"}


@register_template_rule
class PolicyOnlyTemplateAttachedToVulnSiteRule:
    rule_id = "template.policy_only_template_attached_to_vuln_site"
    rule_name = "Policy-Only Template Attached To High-Importance Site"
    description = (
        "Policy-only templates (`policyEnabled: true`, `vulnerabilityEnabled: "
        "false`) bound as the scan template on a high-importance site. The "
        "site is scanned for policy compliance but receives no vulnerability "
        "assessment — a coverage gap on a business-critical asset. Surfaced "
        "as info because policy-only scans are sometimes intentional, but "
        "they are rarely the right choice for `high` or `very_high` sites."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()

        policy_only = [
            t for t in templates
            if t.get("policyEnabled") and not EnvSnapshot.template_vuln_enabled(t)
        ]
        policy_only_ids = {t.get("id"): t for t in policy_only if t.get("id")}

        sites = snapshot.sites()

        # Map: template_id -> list of high-importance site dicts bound to it
        template_to_sites: dict[str, list[dict]] = {}
        for site in sites:
            tpl_id = EnvSnapshot.site_scan_template_id(site)
            if not tpl_id or tpl_id not in policy_only_ids:
                continue
            if site.get("importance") not in _HIGH_IMPORTANCE:
                continue
            template_to_sites.setdefault(tpl_id, []).append(site)

        findings: list[Finding] = []
        for tpl_id, t in policy_only_ids.items():
            bound_sites = template_to_sites.get(tpl_id) or []
            if not bound_sites:
                continue
            site_summaries = [
                {
                    "site_id": s.get("id"),
                    "site_name": s.get("name"),
                    "importance": s.get("importance"),
                }
                for s in bound_sites
            ]
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Policy-only template '{t.get('name')}' is bound to "
                    f"{len(bound_sites)} high-importance site(s) — those "
                    f"sites receive policy assessment but no vulnerability "
                    f"scanning."
                ),
                details={
                    "template_id": tpl_id,
                    "template_name": t.get("name"),
                    "high_importance_site_count": len(bound_sites),
                    "sites": site_summaries[:20],
                },
            ))

        failed = len(findings)
        examined = len(policy_only)

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
                "policy_only_templates_examined": examined,
                "templates_flagged": failed,
            },
            card_summary={
                "examined": examined,
                "passed": max(0, examined - failed),
                "failed": failed,
            },
            sources=list(self.sources),
        )
