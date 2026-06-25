"""The single operational-check envelope, shared by all four op-checks.

Scan Engines, Scan Activity, Asset Coverage and Data Quality each emit a list
of ``RuleResult``s, but -- unlike the audit categories -- their rules do not
share a uniform contract: each rule takes its own positional args, checks share
an upstream fetch through a closure, and gating is by *threshold* not by a
``rules:`` registry. So they cannot reuse ``AuditRunner`` verbatim; the shared
spine is narrower.

``OpCheckRunner`` owns that narrow spine once -- the envelope every ``Check.run``
repeats verbatim: start the timer, roll up the status, flatten the findings
mirror, build the ``rules_*`` summary, and assemble the ``CheckResult``. It
learns the per-check differences from an injected ``OpCheckDescriptor`` whose
one behavioural callable, ``produce_rule_results``, holds everything that
varies (the shared-fetch closures, the heterogeneous per-rule ``run`` calls,
the ``safe_run_rule`` per-rule trap). The operational-vertical mirror of
``AuditRunner`` / ``AuditCategory`` -- thinner, because its descriptor needs one
callable where the audit descriptor needs three plus a registry. See CONTEXT.md
("Operational-check orchestration").
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.checks._op_rule import (
    flatten_findings,
    rollup_check_status,
    rule_summary,
)


@dataclass(frozen=True)
class OpCheckDescriptor:
    """The seam: everything that differs between the four operational checks.

    Identity (``name``/``description``) plus one callable. All per-check
    irreducible behaviour lives inside ``produce_rule_results`` -- the shared
    fetch memoized behind a closure, the peek/oversize/paginate dances, the
    heterogeneous ``rule.run(...)`` calls, and the per-rule exception trap
    (``safe_run_rule``). The runner owns only the envelope around it.

    ``produce_rule_results`` is expected to never raise for an individual
    rule's failure -- op-checks wrap each rule in ``safe_run_rule`` so one bad
    rule surfaces as a ``status="error"`` card rather than aborting the check.
    A failure that escapes (e.g. building the shared data the rules read)
    propagates to ``__main__``'s per-check isolation, exactly as a snapshot
    failure does today.

    ``summary_extra`` is the one concession to checks whose check-level summary
    carries more than the ``rules_*`` rollup: Scan Engines folds in engine
    counts (``engines_total`` etc.). When set, the runner merges its returned
    dict on top of ``rule_summary``. Left None for the three checks whose
    summary is exactly the rollup.
    """
    name: str
    description: str
    produce_rule_results: Callable[[Any, Any, Any], list[RuleResult]]
    summary_extra: Callable[[list[RuleResult]], dict] | None = None


class OpCheckRunner:
    """Runs one ``OpCheckDescriptor``'s rules and rolls them into a
    ``CheckResult``. Stateless; a single shared instance is fine."""

    def run(
        self,
        descriptor: OpCheckDescriptor,
        *,
        client: Any,
        config: Any,
        snapshot: Any,
    ) -> CheckResult:
        start = time.monotonic()
        rule_results = descriptor.produce_rule_results(client, config, snapshot)
        summary = rule_summary(rule_results)
        if descriptor.summary_extra is not None:
            summary.update(descriptor.summary_extra(rule_results))
        return CheckResult(
            name=descriptor.name,
            description=descriptor.description,
            status=rollup_check_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=summary,
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )
