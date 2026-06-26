from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


_WEB_AUTH_SERVICES = {"http-form-auth", "http-headers-auth"}


def _has_web_auth_credential(creds: list[dict]) -> bool:
    for c in creds:
        account = c.get("account") if isinstance(c, dict) else None
        service = (account or {}).get("service") if isinstance(account, dict) else None
        if isinstance(service, str) and service.lower() in _WEB_AUTH_SERVICES:
            return True
    return False


@register_template_rule
class WebSpiderCredentialsMissingRule(AuditRule):
    rule_id = "template.web_spider_credentials_missing"
    rule_name = "Web Spider Without HTTP Authentication Credentials"
    description = (
        "Templates with web spider enabled bound to sites that have no "
        "HTTP-form or HTTP-headers credential configured. Unauthenticated "
        "web scans typically cover ~5x less surface area than authenticated "
        "scans because the spider cannot cross login boundaries -- most "
        "application-layer vulnerabilities sit behind auth."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()
        web_enabled = {
            t.get("id"): t for t in templates
            if t.get("webEnabled") and t.get("id")
        }

        # Map template_id -> list of bound site dicts.
        template_to_sites: dict[str, list[dict]] = {}
        for site in snapshot.sites():
            tpl_id = EnvSnapshot.site_scan_template_id(site)
            if not tpl_id or tpl_id not in web_enabled:
                continue
            template_to_sites.setdefault(tpl_id, []).append(site)

        # Per-rule prefetch (CONTEXT.md): warm the credential cache for every
        # web-enabled-bound site in one concurrent fan-out before the per-site
        # loop below.
        bound_site_ids = [
            s.get("id")
            for sites in template_to_sites.values()
            for s in sites
            if s.get("id") is not None
        ]
        snapshot.prefetch_site_credentials(bound_site_ids)

        findings: list[Finding] = []
        examined = 0
        for tpl_id, t in web_enabled.items():
            bound = template_to_sites.get(tpl_id) or []
            if not bound:
                # Templates with no bound sites aren't actionable for this rule.
                continue
            examined += 1
            any_has_auth = False
            for site in bound:
                sid = site.get("id")
                if sid is None:
                    continue
                creds = snapshot.site_credentials(sid)
                if _has_web_auth_credential(creds):
                    any_has_auth = True
                    break
            if any_has_auth:
                continue
            site_summaries = [
                {"site_id": s.get("id"), "site_name": s.get("name")}
                for s in bound
            ]
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has web spider enabled and "
                    f"is bound to {len(bound)} site(s), none of which have "
                    f"HTTP-form or HTTP-headers credentials configured -- the "
                    f"web scan will not cross authentication boundaries."
                ),
                details={
                    "template_id": tpl_id,
                    "template_name": t.get("name"),
                    "bound_site_count": len(bound),
                    "sites": site_summaries[:20],
                },
            ))

        failed = len(findings)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
            },
            examined=examined,
            failed=failed,
        )
