"""The single audit loop, shared by all four audit categories.

Configuration Audit, Template Configuration Audit, User & Permission Audit and
Cloud Drift Audit each define their own rule registry and config block, but the
loop that turns a registry into a ``CheckResult`` is ~95% identical across all
four: enabled-skip envelope, per-rule enable/skip cards, progress step/done,
per-rule timing, exception trapping, status rollup, ``rules_*`` summary counts.

``AuditRunner`` owns that loop once. It learns the per-category differences from
an injected ``AuditCategory`` descriptor — the same shape as ``HttpTransport``
learning per-API differences from an ``ApiDialect`` (see CONTEXT.md). The four
``Check`` classes become thin suppliers: they build an ``AuditCategory`` and
delegate to the runner.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from rapid7_healthcheck.audit import (
    Rule,
    RuleResult,
    _extract_diagnostics,
)
from rapid7_healthcheck.audit.rule_rollup import (
    flatten_findings,
    rollup_status,
    rule_summary,
)
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.config import AppConfig, RuleConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GateDecision:
    """Outcome of a category's enabled gate.

    ``enabled=True`` -> the runner builds the snapshot and runs the rule loop;
    ``skip_finding``/``skip_reason`` are ignored.

    ``enabled=False`` -> the runner short-circuits with a ``skipped``
    ``CheckResult``: ``findings = [skip_finding]`` (empty when None) and
    ``summary = {"reason": skip_reason}`` (empty when ``skip_reason`` is "").
    Carry a ``skip_finding`` when the operator needs to see *why* the whole
    category self-skipped (cloud-drift's "not configured", for example);
    leave it None for a plain ``<block>.enabled is false`` skip.
    """
    enabled: bool
    skip_reason: str = ""
    skip_finding: Finding | None = None


@dataclass(frozen=True)
class AuditCategory:
    """The seam: everything that differs between the four audit categories.

    Mostly data, with the irreducible per-category behaviour held in three
    callables. ``gate`` decides whether to run at all; ``build_snapshot``
    constructs the (lazy) data container the rules read from; ``prime`` is an
    optional I/O early-exit run after the snapshot is built but before the loop
    (User & Permission uses it to self-skip when ``/api/3/users`` 404s).

    ``registry`` is held by reference, so rule modules registered as a package
    side effect after the descriptor is built are still seen at ``run`` time.
    Rule-id order follows the registry's insertion order, unchanged — the
    cross-run delta-blob signatures depend on it.
    """
    name: str
    description: str
    progress_prefix: str
    registry: Mapping[str, type[Rule]]
    rules_config: Callable[[AppConfig], Mapping[str, RuleConfig]]
    full_scan: bool
    sample_size: int
    gate: Callable[[Any, AppConfig, Any], GateDecision]
    build_snapshot: Callable[[Any, AppConfig, Any], Any]
    prime: Callable[[Any, "AuditCategory", float], CheckResult | None] | None = None


class AuditRunner:
    """Runs one ``AuditCategory``'s rules and rolls them into a ``CheckResult``.

    Stateless; a single shared instance is fine. ``gate``, ``build_snapshot``,
    and ``prime`` may perform I/O and are **not** wrapped in the per-rule
    exception guard — a failure there propagates to ``__main__``'s per-check
    isolation, exactly as a snapshot-construction failure does today. Only
    individual rule ``run`` calls are trapped into ``status="error"``
    ``RuleResult``s so one bad rule never aborts the category.
    """

    def run(
        self,
        category: AuditCategory,
        *,
        client: Any,
        config: AppConfig,
        progress=None,
        cloud_client: Any = None,
    ) -> CheckResult:
        start = time.monotonic()

        decision = category.gate(client, config, cloud_client)
        if not decision.enabled:
            return CheckResult(
                name=category.name,
                description=category.description,
                status="skipped",
                findings=[decision.skip_finding] if decision.skip_finding else [],
                summary={"reason": decision.skip_reason} if decision.skip_reason else {},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        snapshot = category.build_snapshot(client, config, cloud_client)

        if category.prime is not None:
            early = category.prime(snapshot, category, start)
            if early is not None:
                return early

        rules_cfg = category.rules_config(config)
        rule_results: list[RuleResult] = []
        for rule_id, rule_cls in category.registry.items():
            rule_cfg = rules_cfg.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                if progress is not None:
                    progress.finish_rule(rule_cls.rule_name, status_text="skipped")
                continue
            if progress is not None:
                progress.start_rule(rule_cls.rule_name)
            rule_start = time.monotonic()
            try:
                try:
                    result = rule_cls().run(
                        snapshot,
                        rule_cfg.severity,
                        category.full_scan,
                        category.sample_size,
                        rule_cfg.knobs,
                    )
                    result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                    rule_results.append(result)
                except Exception as e:
                    logger.exception("%s rule %s raised", category.progress_prefix, rule_id)
                    error_path, error_status_code = _extract_diagnostics(e)
                    rule_results.append(RuleResult(
                        rule_id=rule_id,
                        rule_name=rule_cls.rule_name,
                        description=rule_cls.description,
                        severity=rule_cfg.severity,
                        status="error",
                        sources=list(rule_cls.sources),
                        error=str(e),
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                        error_path=error_path,
                        error_status_code=error_status_code,
                    ))
            finally:
                if progress is not None:
                    from rapid7_healthcheck.progress import format_duration
                    progress.finish_rule(
                        rule_cls.rule_name,
                        status_text=format_duration(int((time.monotonic() - rule_start) * 1000)),
                    )

        return CheckResult(
            name=category.name,
            description=category.description,
            status=rollup_status(rule_results),
            findings=flatten_findings(rule_results),
            summary=rule_summary(rule_results),
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )
