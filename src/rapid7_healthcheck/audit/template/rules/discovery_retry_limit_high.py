from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.template.rules._applicability import performs_discovery
from rapid7_healthcheck.checks import Finding


def _retry_limit(template: dict):
    return ((template.get("discovery") or {}).get("performance") or {}).get(
        "retryLimit"
    )


@register_template_rule
class DiscoveryRetryLimitHighRule(AuditRule):
    rule_id = "template.discovery_retry_limit_high"
    rule_name = "Discovery Retry Limit Higher Than Recommended"
    description = (
        "Discovery-active templates whose `discovery.performance.retryLimit` "
        "exceeds the recommended maximum (default 1). Retries apply per dead "
        "port, so a high retry limit multiplies wasted wait time on modern, "
        "low-latency networks. Rapid7 recommends lowering this to 1 unless "
        "the network is genuinely timeout-prone. Templates without the field "
        "use the engine default and are not examined (skip-absent). "
        "Knob: `max_retry_limit` (default 1)."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_retry_limit = int(rule_config.get("max_retry_limit", 1))

        # Examined = discovery-active templates with an integer retryLimit set.
        # Absent or non-int → not applicable (skip-absent / defensive).
        applicable = []
        for t in snapshot.templates_full():
            if not performs_discovery(t):
                continue
            if isinstance(_retry_limit(t), int):
                applicable.append(t)

        findings: list[Finding] = []
        for t in applicable:
            value = _retry_limit(t)
            if value <= max_retry_limit:
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has retryLimit={value}, above "
                    f"the recommended maximum of {max_retry_limit} — retries "
                    f"apply per dead port and inflate scan time on modern nets."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "retry_limit": value,
                    "max_retry_limit": max_retry_limit,
                },
            ))

        failed = len(findings)
        examined = len(applicable)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
                "max_retry_limit": max_retry_limit,
            },
            examined=examined,
            failed=failed,
        )
