from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterator, Literal, Protocol

from rapid7_healthcheck.config import AppConfig

if TYPE_CHECKING:
    from rapid7_healthcheck.audit import RuleResult
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot


Severity = Literal["info", "warn", "fail"]
Status = Literal["pass", "warn", "fail", "error", "skipped"]


@dataclass(frozen=True)
class Finding:
    severity: Severity
    message: str
    details: dict[str, Any] | None = None


@dataclass
class CheckResult:
    name: str
    description: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None
    rule_results: list["RuleResult"] | None = None


def findings_of(check: CheckResult) -> Iterator[tuple[str, Finding]]:
    """Iterate a check's findings as ``(rule_id, finding)`` pairs.

    The single place that owns the rule-vs-flat traversal invariant: when a
    check has ``rule_results``, walk each rule's findings tagged with that
    rule's ``rule_id``; the top-level ``findings`` mirror is **ignored** so a
    finding is never double-counted in the delta-blob signature index. A legacy
    (pre-0.2.6) check with only top-level findings yields them tagged with the
    check ``name`` — matching the historical delta-index fallback.
    """
    if check.rule_results:
        for rr in check.rule_results:
            for f in rr.findings:
                yield rr.rule_id, f
    else:
        for f in check.findings:
            yield check.name, f


def rollup_status(findings: list[Finding]) -> Status:
    if any(f.severity == "fail" for f in findings):
        return "fail"
    if any(f.severity == "warn" for f in findings):
        return "warn"
    return "pass"


class Check(Protocol):
    name: str
    description: str

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: "EnvSnapshot | None" = None,
    ) -> CheckResult: ...
