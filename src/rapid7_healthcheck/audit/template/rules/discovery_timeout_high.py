from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.audit.template.rules._applicability import (
    parse_iso8601_seconds_to_ms,
    performs_discovery,
)
from rapid7_healthcheck.checks import Finding


def _timeout_block(template: dict) -> dict:
    return ((template.get("discovery") or {}).get("performance") or {}).get(
        "timeout"
    ) or {}


@register_template_rule
class DiscoveryTimeoutHighRule(AuditRule):
    rule_id = "template.discovery_timeout_high"
    rule_name = "Discovery Timeout Higher Than Recommended"
    description = (
        "Discovery-active templates whose discovery timeout is higher than "
        "recommended. The InsightVM `discovery.performance.timeout.initial` "
        "field (the first per-port wait; default `PT0.5S`/500ms) and "
        "`timeout.maximum` (the ceiling after retries; default `PT3S`/3000ms) "
        "are ISO-8601 durations. Rapid7 recommends lowering the initial wait "
        "to ~200ms and the ceiling to ~500ms on modern networks. Values are "
        "parsed defensively — a value that is not a `PnS`/`PTnS` duration is "
        "skipped, never crashed or false-flagged. Templates without a timeout "
        "block use the engine default and are not examined (skip-absent). "
        "Knobs: `max_timeout_initial_ms` (200), `max_timeout_ceiling_ms` (500)."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_initial = int(rule_config.get("max_timeout_initial_ms", 200))
        max_ceiling = int(rule_config.get("max_timeout_ceiling_ms", 500))

        findings: list[Finding] = []
        examined = 0
        for t in snapshot.templates_full():
            if not performs_discovery(t):
                continue
            block = _timeout_block(t)
            if not block:
                continue  # skip-absent: no explicit timeout block
            # API field names: `initial` (first wait) and `maximum` (ceiling).
            initial_ms = parse_iso8601_seconds_to_ms(block.get("initial"))
            ceiling_ms = parse_iso8601_seconds_to_ms(block.get("maximum"))
            if initial_ms is None and ceiling_ms is None:
                continue  # nothing parseable → skip this template entirely
            examined += 1

            breaches = []
            if initial_ms is not None and initial_ms > max_initial:
                breaches.append(f"initial wait {initial_ms:.0f}ms > {max_initial}ms")
            if ceiling_ms is not None and ceiling_ms > max_ceiling:
                breaches.append(f"ceiling {ceiling_ms:.0f}ms > {max_ceiling}ms")
            if not breaches:
                continue

            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' discovery timeout is high "
                    f"({'; '.join(breaches)}) — inflates wait time per dead "
                    f"port on modern networks."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "timeout_initial_ms": initial_ms,
                    "timeout_ceiling_ms": ceiling_ms,
                    "max_timeout_initial_ms": max_initial,
                    "max_timeout_ceiling_ms": max_ceiling,
                },
            ))

        failed = len(findings)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
                "max_timeout_initial_ms": max_initial,
                "max_timeout_ceiling_ms": max_ceiling,
            },
            examined=examined,
            failed=failed,
        )
