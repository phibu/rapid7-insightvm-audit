"""Template Configuration audit category.

Fourth audit vertical, sibling to ``rapid7_healthcheck.audit`` (Configuration
Audit), ``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit),
and ``rapid7_healthcheck.audit.cloud_drift`` (Cloud Drift Audit).

Operates on scan-template configuration exposed by ``/api/3/scan_templates``
(via ``EnvSnapshot.templates_full()``). Rule files live under
``audit/template/rules/`` and self-register via ``@register_template_rule``
at import time. Rule modules are imported as a side effect of importing this
package, so the registry is populated whenever
``rapid7_healthcheck.audit.template`` is loaded (typically by ``__main__.py``).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.audit import (
    Rule,
    RuleResult,
    _extract_diagnostics,
    _flatten_findings,
    _rollup_audit_status,
)
from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.checks import CheckResult
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


_TEMPLATE_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_template_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a template-audit rule. Mirror of ``audit.register``,
    ``audit.user_permission.register_user_rule``, and
    ``audit.cloud_drift.register_cloud_rule`` but for the fourth audit category.
    """
    _TEMPLATE_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


class TemplateAuditCheck:
    name = "Template Configuration Audit"
    description = (
        "Best-practice audits over the Security Console's scan templates. "
        "Reviews the ~50 tunable settings on each template (checks, "
        "discovery, web, policy, database, telnet) to catch silent "
        "misconfigurations that produce wrong scan results."
    )

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: EnvSnapshot | None = None,
        progress=None,
        **_kwargs: Any,
    ) -> CheckResult:
        start = time.monotonic()

        if not config.template_audit.enabled:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[],
                summary={"reason": "template_audit.enabled is false"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        # Accept an outer-owned snapshot when the caller provides one (future
        # cleanup path — see __main__._run_checks). Today the orchestrator
        # builds its own to mirror user_permission/cloud_drift, which keeps
        # sampling settings scoped to the audit's own config block.
        if snapshot is None:
            snapshot = EnvSnapshot(
                client,
                full_scan=config.template_audit.full_scan,
                sample_size=config.template_audit.sample_size,
                agents_timeout_seconds=180,
            )

        rule_results: list[RuleResult] = []
        total_rules = len(_TEMPLATE_RULE_REGISTRY)
        for rule_idx, (rule_id, rule_cls) in enumerate(_TEMPLATE_RULE_REGISTRY.items(), start=1):
            rule_cfg = config.template_audit.rules.get(rule_id)
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
                    skipped_label = f"template-audit: {rule_id} (skipped)"
                    progress.step(rule_idx, total_rules, skipped_label)
                    progress.done(rule_idx, total_rules, skipped_label, duration_ms=0)
                continue
            label = f"template-audit: {rule_id}"
            if progress is not None:
                progress.step(rule_idx, total_rules, label)
            rule_start = time.monotonic()
            try:
                try:
                    result = rule_cls().run(
                        snapshot,
                        rule_cfg.severity,
                        config.template_audit.full_scan,
                        config.template_audit.sample_size,
                        rule_cfg.knobs,
                    )
                    result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                    rule_results.append(result)
                except Exception as e:
                    logger.exception("template audit rule %s raised", rule_id)
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
                    progress.done(
                        rule_idx, total_rules, label,
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                    )

        return CheckResult(
            name=self.name,
            description=self.description,
            status=_rollup_audit_status(rule_results),
            findings=_flatten_findings(rule_results),
            summary={
                "rules_total": len(rule_results),
                "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
                "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
                "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
                "rules_error": sum(1 for r in rule_results if r.status == "error"),
                "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )


# Side-effect imports: importing the rules subpackage executes its own
# side-effect block, which registers every rule module with the
# Template Configuration Audit registry. F1 lands with an empty registry;
# F2-F4 will append imports to ``audit/template/rules/__init__.py``.
from rapid7_healthcheck.audit.template import rules  # noqa: E402,F401
