from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import Finding


_HIGH_IMPORTANCE = {"high", "very_high"}


@register_template_rule
class EnhancedLoggingInProdRule(AuditRule):
    rule_id = "template.enhanced_logging_in_prod"
    rule_name = "Enhanced Logging Template Bound To High-Importance Site"
    description = (
        "Templates with `enhancedLogging: true` (verbose debug logging) "
        "bound as the scan template on a high-importance site. Verbose "
        "logging is intended for short-lived troubleshooting -- leaving it "
        "on for production sites bloats console disk usage and slows scans. "
        "Templates with enhanced logging but no bound high-importance site "
        "are not examined."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        templates = snapshot.templates_full()
        # Examined population = templates with enhancedLogging on. Other
        # templates have nothing to do with this rule and counting them
        # would inflate the passed denominator with irrelevant population.
        enhanced_templates = [
            t for t in templates if t.get("enhancedLogging") is True
        ]
        enhanced_ids = {t.get("id"): t for t in enhanced_templates if t.get("id")}

        sites = snapshot.sites()

        # Map: template_id -> list of high-importance site dicts bound to it
        template_to_sites: dict[str, list[dict]] = {}
        for site in sites:
            tpl_id = EnvSnapshot.site_scan_template_id(site)
            if not tpl_id or tpl_id not in enhanced_ids:
                continue
            if site.get("importance") not in _HIGH_IMPORTANCE:
                continue
            template_to_sites.setdefault(tpl_id, []).append(site)

        examined = len(enhanced_templates)

        findings: list[Finding] = []
        for tpl_id, t in enhanced_ids.items():
            bound_sites = template_to_sites.get(tpl_id) or []
            if not bound_sites:
                continue
            site_names = [s.get("name") for s in bound_sites if s.get("name")]
            overflow = max(0, len(site_names) - 20)
            details = {
                "template_id": tpl_id,
                "template_name": t.get("name"),
                "high_importance_sites": site_names[:20],
                "high_importance_site_count": len(bound_sites),
            }
            if overflow:
                details["high_importance_sites_overflow"] = overflow
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has enhanced (verbose) "
                    f"logging enabled and is bound to {len(bound_sites)} "
                    f"high-importance site(s)."
                ),
                details=details,
            ))

        failed = len(findings)

        return self.result(
            findings,
            severity=severity,
            summary={
                "enhanced_templates_examined": examined,
                "templates_flagged": failed,
            },
            examined=examined,
            failed=failed,
        )
