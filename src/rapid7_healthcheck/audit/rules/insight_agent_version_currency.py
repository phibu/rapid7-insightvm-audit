from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules._agent_version import (
    LATEST_KNOWN_INSIGHT_AGENT_VERSION,
    find_agent_version,
)
from rapid7_healthcheck.checks import Finding


def _format_version(v: tuple[int, int, int, int]) -> str:
    return ".".join(str(x) for x in v)


def _parse_version_string(s: str) -> tuple[int, int, int, int] | None:
    """Parse a 4-part dotted version string into a tuple. Returns None on
    any malformedness — the caller decides whether to skip or fall back."""
    if not isinstance(s, str):
        return None
    parts = s.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        ints = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return (ints[0], ints[1], ints[2], ints[3])


def _resolve_mode(rule_config: dict) -> tuple[str, tuple[int, int, int, int] | None, str | None]:
    """Resolve the (mode, reference_tuple, raw_pinned_string) triple.

    Returns:
        (mode, reference, raw):
            mode in {"pinned", "latest_known", "fleet_newest"}.
            reference is the parsed version tuple, or None for fleet_newest
                (computed later from the fleet) or pinned-with-bad-input.
            raw is the original pinned_version string when mode is "pinned"
                with unparseable input — used in the skip message.
    """
    pinned_raw = rule_config.get("pinned_version")
    if pinned_raw is not None:
        parsed = _parse_version_string(pinned_raw)
        return ("pinned", parsed, pinned_raw if parsed is None else None)
    if rule_config.get("use_latest_known"):
        return ("latest_known", LATEST_KNOWN_INSIGHT_AGENT_VERSION, None)
    return ("fleet_newest", None, None)


@register
class InsightAgentVersionCurrencyRule:
    rule_id = "insight_agent_version_currency"
    rule_name = "Insight Agent Version Currency"
    description = (
        "Flags Insight Agents whose version is out of step with a reference. "
        "Three modes, in precedence order: (1) pinned — `pinned_version: "
        "\"4.1.0.2\"` requires every agent to match exactly; both behind-pin "
        "and ahead-of-pin agents are flagged (the latter is a change-control "
        "gap). (2) latest-known — `use_latest_known: true` compares against "
        "a tool-maintained 'current latest' version, with `version_drift_minor` "
        "tolerance. (3) fleet-newest (default) — self-bootstrapping comparison "
        "against the newest version observed in the fleet, with "
        "`version_drift_minor` tolerance. Does NOT detect uniform fleet "
        "staleness in fleet-newest mode (different rule territory)."
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

        mode, reference, raw_pinned = _resolve_mode(rule_config)

        # Pinned mode with unparseable input — skip loudly.
        if mode == "pinned" and reference is None:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"pinned_version '{raw_pinned}' is not a parseable "
                        f"4-part version (e.g. '4.1.0.2'). Fix config or "
                        f"remove the knob to fall back to drift detection."
                    ),
                    details={"reason": "unparseable pinned_version", "pinned_version_raw": raw_pinned},
                )],
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": "pinned",
                    "reference_version": None,
                },
                sources=list(self.sources),
            )

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
                summary={
                    "agents_total": 0,
                    "endpoint_available": False,
                    "reference_mode": mode,
                },
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
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": mode,
                },
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

        # Fleet-newest needs >=2 parseable agents to compute drift; pinned and
        # latest-known only need >=1 (they have an external reference).
        min_required = 2 if mode == "fleet_newest" else 1
        if len(parsed) < min_required:
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
                        f"version strings; need at least {min_required} for "
                        f"{mode} mode."
                    ),
                    details={"reason": "insufficient parseable versions"},
                )],
                summary={
                    "agents_total": total,
                    "agents_examined": len(parsed),
                    "agents_unparseable": unparseable,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        # Resolve the reference for fleet-newest mode now that we have parsed agents.
        if mode == "fleet_newest":
            reference = max(v for _, v in parsed)

        findings: list[Finding] = []
        drifted = 0
        ahead_of_pin = 0

        for agent, version in parsed:
            host = agent.get("hostName") or agent.get("id") or "?"
            if mode == "pinned":
                if version == reference:
                    continue
                drifted += 1
                if version > reference:
                    ahead_of_pin += 1
                    direction = "ahead"
                    msg = (
                        f"Insight Agent on '{host}' is running "
                        f"{_format_version(version)} — ahead of pinned version "
                        f"{_format_version(reference)} (change-control gap)."
                    )
                else:
                    direction = "behind"
                    msg = (
                        f"Insight Agent on '{host}' is running "
                        f"{_format_version(version)} — behind pinned version "
                        f"{_format_version(reference)}."
                    )
                findings.append(Finding(
                    severity=severity,
                    message=msg,
                    details={
                        "agentId": agent.get("agentId"),
                        "hostName": agent.get("hostName"),
                        "observed_version": _format_version(version),
                        "pinned_version": _format_version(reference),
                        "drift_direction": direction,
                    },
                ))
            else:
                # fleet_newest or latest_known — minor-drift logic.
                minor_drift = (reference[0] - version[0]) * 1000 + (reference[1] - version[1])
                if minor_drift > drift_threshold:
                    drifted += 1
                    if mode == "latest_known":
                        msg = (
                            f"Insight Agent on '{host}' is running "
                            f"{_format_version(version)} — behind known-current "
                            f"{_format_version(reference)} by {minor_drift} minor "
                            f"version(s)."
                        )
                    else:  # fleet_newest
                        msg = (
                            f"Insight Agent on '{host}' is running "
                            f"{_format_version(version)} — {minor_drift} minor "
                            f"version(s) behind newest "
                            f"({_format_version(reference)})."
                        )
                    findings.append(Finding(
                        severity=severity,
                        message=msg,
                        details={
                            "agentId": agent.get("agentId"),
                            "hostName": agent.get("hostName"),
                            "observed_version": _format_version(version),
                            "reference_version": _format_version(reference),
                            "minor_drift": minor_drift,
                        },
                    ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        summary: dict = {
            "agents_total": total,
            "agents_examined": len(parsed),
            "agents_unparseable": unparseable,
            "agents_drifted": drifted,
            "reference_version": _format_version(reference),
            "reference_mode": mode,
        }
        if mode == "pinned":
            summary["agents_ahead_of_pin"] = ahead_of_pin
        else:
            summary["drift_threshold"] = drift_threshold

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary=summary,
            sources=list(self.sources),
        )
