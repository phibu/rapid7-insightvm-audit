from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from rapid7_healthcheck.config import AppConfig


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


def rollup_status(findings: list[Finding]) -> Status:
    if any(f.severity == "fail" for f in findings):
        return "fail"
    if any(f.severity == "warn" for f in findings):
        return "warn"
    return "pass"


class Check(Protocol):
    name: str
    description: str

    def run(self, client: Any, config: AppConfig) -> CheckResult: ...
