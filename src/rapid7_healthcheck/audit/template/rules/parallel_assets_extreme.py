from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult
from rapid7_healthcheck.audit.template import register_template_rule
from rapid7_healthcheck.checks import Finding


@register_template_rule
class ParallelAssetsExtremeRule(AuditRule):
    rule_id = "template.parallel_assets_extreme"
    rule_name = "Parallel Asset Count Outside Expected Range"
    description = (
        "Templates whose `maxParallelAssets` is outside a configurable range "
        "([min, max], default [2, 50]). Extremely low values (1) serialize "
        "scans and inflate scan duration; extremely high values can starve "
        "the engine of resources and produce timeouts. Templates without "
        "the field set are not examined -- they use the engine default, "
        "which is by definition not extreme."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-templates/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        min_threshold = max(1, int(rule_config.get("parallel_assets_min", 2)))
        max_threshold = max(min_threshold, int(rule_config.get("parallel_assets_max", 50)))

        templates = snapshot.templates_full()
        # Only templates with `maxParallelAssets` set are applicable to this
        # rule. Templates without the field run with the engine default --
        # not "extreme" by definition. Counting them as "examined" would
        # inflate the passed denominator with irrelevant population.
        templates_with_value = [
            t for t in templates if t.get("maxParallelAssets") is not None
        ]
        examined = len(templates_with_value)

        findings: list[Finding] = []
        for t in templates_with_value:
            value = t.get("maxParallelAssets")
            if not isinstance(value, int):
                # Defensive: spec says integer but skip non-int values rather
                # than crash. Treat as not applicable.
                continue
            # Inclusive bounds: a user setting min=2/max=50 means "values
            # 2 through 50 are acceptable." Only flag values strictly
            # outside the closed interval [min_threshold, max_threshold].
            # The finding message reflects this with [..] bracket notation.
            if min_threshold <= value <= max_threshold:
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Template '{t.get('name')}' has maxParallelAssets={value}, "
                    f"outside expected range [{min_threshold}, {max_threshold}]."
                ),
                details={
                    "template_id": t.get("id"),
                    "template_name": t.get("name"),
                    "max_parallel_assets": value,
                    "min_threshold": min_threshold,
                    "max_threshold": max_threshold,
                },
            ))

        failed = len(findings)

        return self.result(
            findings,
            severity=severity,
            summary={
                "templates_examined": examined,
                "templates_flagged": failed,
                "min_threshold": min_threshold,
                "max_threshold": max_threshold,
            },
            examined=examined,
            failed=failed,
        )
