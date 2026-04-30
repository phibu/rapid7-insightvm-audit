from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules._agent_version import find_agent_version
from rapid7_healthcheck.checks import Finding


def _format_version(v: tuple[int, int, int, int]) -> str:
    return ".".join(str(x) for x in v)


@register
class InsightAgentVersionCurrencyRule:
    rule_id = "insight_agent_version_currency"
    rule_name = "Insight Agent Version Currency"
    description = (
        "Flags Insight Agents running versions more than `version_drift_minor` "
        "(default 1) minor versions behind the newest version observed in the "
        "fleet. Self-bootstrapping — no hardcoded 'latest' knob to maintain. "
        "Does NOT detect uniform fleet staleness (different rule territory)."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/insight-agent-overview/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        drift_threshold = rule_config.get("version_drift_minor", 1)
        try:
            drift_threshold = int(drift_threshold)
        except (TypeError, ValueError):
            drift_threshold = 1

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
                        "/api/3/agents returned 404 — this console does not expose "
                        "the Insight Agent fleet via API. Audit agent versions via "
                        "the Security Console UI."
                    ),
                    details={"reason": "agents endpoint unavailable"},
                )],
                summary={"agents_total": 0, "endpoint_available": False},
                sources=list(self.sources),
            )

        if total == 0:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message="No Insight Agents deployed — nothing to compare.",
                    details={"reason": "empty fleet"},
                )],
                summary={"agents_total": 0, "agents_examined": 0},
                sources=list(self.sources),
            )

        # Parse versions from each agent.
        parsed: list[tuple[dict, tuple[int, int, int, int]]] = []
        unparseable = 0
        for agent in agents:
            v = find_agent_version(agent)
            if v is None:
                unparseable += 1
                continue
            parsed.append((agent, v))

        if len(parsed) < 2:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"Only {len(parsed)} agent(s) had parseable Insight Agent "
                        f"version strings; need at least 2 to compute drift."
                    ),
                    details={"reason": "insufficient parseable versions"},
                )],
                summary={
                    "agents_total": total,
                    "agents_examined": len(parsed),
                    "agents_unparseable": unparseable,
                },
                sources=list(self.sources),
            )

        # Newest-in-fleet reference.
        newest = max(v for _, v in parsed)

        findings: list[Finding] = []
        drifted = 0
        for agent, version in parsed:
            minor_drift = (newest[0] - version[0]) * 1000 + (newest[1] - version[1])
            if minor_drift > drift_threshold:
                drifted += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Insight Agent on '{agent.get('hostName', agent.get('id', '?'))}' "
                        f"is running {_format_version(version)} — "
                        f"{minor_drift} minor version(s) behind newest "
                        f"({_format_version(newest)})."
                    ),
                    details={
                        "agentId": agent.get("agentId"),
                        "hostName": agent.get("hostName"),
                        "observed_version": _format_version(version),
                        "newest_version": _format_version(newest),
                        "minor_drift": minor_drift,
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
                "agents_total": total,
                "agents_examined": len(parsed),
                "agents_unparseable": unparseable,
                "agents_drifted": drifted,
                "newest_version": _format_version(newest),
                "drift_threshold": drift_threshold,
            },
            sources=list(self.sources),
        )
