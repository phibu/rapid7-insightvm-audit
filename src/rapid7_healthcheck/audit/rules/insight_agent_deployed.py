from __future__ import annotations

from rapid7_healthcheck.audit import AuditRule, RuleResult, register
from rapid7_healthcheck.checks import Finding

_DEFAULT_WARN_BELOW_PERCENT = 70


@register
class InsightAgentDeployedRule(AuditRule):
    rule_id = "insight_agent_deployed"
    rule_name = "Insight Agent Fleet Coverage"
    description = (
        "Measures Insight Agent coverage across the asset inventory. "
        "Zero agents means agent-aware rules in this audit can't run and "
        "credentialed assessment relies entirely on network-credential scans. "
        "Partial coverage (some agents but well below the asset count) is the "
        "riskiest state: agent-aware rules under-report because they only see "
        "the covered slice. Coverage at or above the configured threshold "
        "passes; below threshold warns."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/insight-agent-overview/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Read the fleet total from the cheap size=1 head-probe -- this rule
        # only needs the count, never the agent bodies. agent_count() primes
        # the same is_agents_unavailable() flag agents() did, so the skip
        # branch below is unaffected; under full_scan this drops a full-fleet
        # pagination to a single GET.
        agents_total = snapshot.agent_count()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[],
                summary={
                    "reason": (
                        "/api/3/agents could not be enumerated (404, gateway "
                        "timeout 502/503/504, or network error). Audit agent "
                        "deployment and coverage via the Security Console UI."
                    ),
                    "endpoint_available": False,
                },
                sources=list(self.sources),
            )

        warn_below = int((rule_config or {}).get("warn_below_percent", _DEFAULT_WARN_BELOW_PERCENT))
        try:
            assets_total = int(snapshot.total_asset_count())
        except Exception:
            assets_total = 0

        coverage_pct: float | None
        if assets_total > 0:
            coverage_pct = round(agents_total / assets_total * 100, 1)
        else:
            coverage_pct = None

        findings: list[Finding] = []
        if agents_total == 0:
            findings.append(Finding(
                severity=severity,
                message="No Insight Agents deployed in this environment.",
                details={"agents_total": 0, "assets_total": assets_total},
            ))
        elif coverage_pct is not None and coverage_pct < warn_below:
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Insight Agent coverage is {coverage_pct}% "
                    f"({agents_total:,} agents / {assets_total:,} assets). "
                    f"Below the {warn_below}% threshold -- agent-aware audit "
                    f"rules will under-report on the uncovered slice."
                ),
                details={
                    "agents_total": agents_total,
                    "assets_total": assets_total,
                    "coverage_percent": coverage_pct,
                    "warn_below_percent": warn_below,
                },
            ))

        summary: dict = {
            "agents_total": agents_total,
            "assets_total": assets_total,
            "warn_below_percent": warn_below,
        }
        if coverage_pct is not None:
            summary["coverage_percent"] = coverage_pct

        return self.result(
            findings,
            severity=severity,
            summary=summary,
        )
