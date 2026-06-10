from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


def _web_block(template: dict) -> dict:
    web = template.get("web")
    return web if isinstance(web, dict) else {}


@register_template_rule
class WebSpiderEnabledNoTargetsRule:
    rule_id = "template.web_spider_enabled_no_targets"
    rule_name = "Web Spider Enabled But No Targets Configured"
    description = (
        "Scan templates with web spider enabled but neither included paths, "
        "start paths, nor link discovery configured. The web scan runs but "
        "has no surface to crawl — producing zero web findings while "
        "appearing to be a configured web scan."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # NOTE: `template.web` is a freeform object in the v3 spec; sub-field
        # names (`includedPaths`, `startPaths`, `discoveryEnabled`) are based
        # on observed shapes. If a console exposes these under different keys,
        # the rule defensively will not flag.
        templates = snapshot.templates_full()
        web_enabled = [t for t in templates if t.get("webEnabled")]

        findings: list[Finding] = []
        for t in web_enabled:
            web = _web_block(t)
            included = web.get("includedPaths") or []
            start = web.get("startPaths") or []
            discovery = web.get("discoveryEnabled")
            if included or start or discovery:
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has web spider enabled but "
                    f"no included paths, start paths, or link discovery — the "
                    f"web scan has no surface to crawl."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                },
            ))

        failed = len(findings)
        examined = len(web_enabled)

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
                "templates_examined": examined,
                "templates_flagged": failed,
            },
            card_summary={
                "examined": examined,
                "passed": max(0, examined - failed),
                "failed": failed,
            },
            sources=list(self.sources),
        )
