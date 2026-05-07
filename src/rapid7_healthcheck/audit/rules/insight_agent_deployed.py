from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


@register
class InsightAgentDeployedRule:
    rule_id = "insight_agent_deployed"
    rule_name = "Insight Agent Fleet Presence"
    description = (
        "Reports whether any Insight Agents are deployed in the environment. "
        "If zero agents are detected, agent-aware rules in this audit can't "
        "run and credentialed assessment relies entirely on network-credential "
        "scans. Severity is configurable; default 'info' because some "
        "environments are intentionally agentless."
    )
    default_severity = "info"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/insight-agent-overview/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        agents, total = snapshot.agents()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "/api/3/agents could not be enumerated (returned 404, or "
                        "timed out / network-errored). Either this console does "
                        "not expose the Insight Agent fleet via API, or the "
                        "endpoint is too slow on this environment. Audit agent "
                        "deployment via the Security Console UI."
                    ),
                    details={"reason": "agents endpoint unavailable"},
                )],
                summary={"agents_total": 0, "endpoint_available": False},
                sources=list(self.sources),
            )

        findings: list[Finding] = []
        if total == 0:
            findings.append(Finding(
                severity=severity,
                message="No Insight Agents deployed in this environment.",
                details={"agents_total": 0},
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
            summary={"agents_total": total},
            sources=list(self.sources),
        )
