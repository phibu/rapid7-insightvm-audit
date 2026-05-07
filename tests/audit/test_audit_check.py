from __future__ import annotations

from dataclasses import replace

import pytest

from rapid7_healthcheck.audit import _RULE_REGISTRY, ConfigurationAuditCheck
import rapid7_healthcheck.audit.rules.agent_unauth_collision  # noqa: F401
import rapid7_healthcheck.audit.rules.site_vuln_template_no_creds  # noqa: F401
import rapid7_healthcheck.audit.rules.overlapping_scan_windows  # noqa: F401
import rapid7_healthcheck.audit.rules.single_engine_overload  # noqa: F401
import rapid7_healthcheck.audit.rules.discovery_template_on_prod_site  # noqa: F401
import rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template  # noqa: F401
import rapid7_healthcheck.audit.rules.local_engine_production_scope  # noqa: F401
import rapid7_healthcheck.audit.rules.dynamic_groups_and_nested_tags  # noqa: F401
import rapid7_healthcheck.audit.rules.scan_report_schedule_overlap  # noqa: F401
import rapid7_healthcheck.audit.rules.engine_version_drift  # noqa: F401
import rapid7_healthcheck.audit.rules.insight_agent_deployed  # noqa: F401
import rapid7_healthcheck.audit.rules.insight_agent_version_currency  # noqa: F401


def test_all_rules_registered():
    expected = {
        "agent_unauth_collision", "site_vuln_template_no_creds",
        "overlapping_scan_windows",
        "single_engine_overload", "discovery_template_on_prod_site",
        "policy_and_vuln_in_same_template",
        "local_engine_production_scope", "dynamic_groups_and_nested_tags",
        "scan_report_schedule_overlap", "engine_version_drift",
        "insight_agent_deployed", "insight_agent_version_currency",
    }
    assert set(_RULE_REGISTRY.keys()) == expected


def test_audit_skipped_when_audit_enabled_false(app_config, monkeypatch):
    cfg = replace(app_config, audit=replace(app_config.audit, enabled=False))
    result = ConfigurationAuditCheck().run(client=object(), config=cfg)
    assert result.status == "skipped"
    assert result.rule_results == []


def test_audit_skips_disabled_rules(app_config, fake_client, monkeypatch):
    from rapid7_healthcheck.config import AuditConfig, RuleConfig
    rules = {
        rid: RuleConfig(enabled=False, severity="warn", knobs={})
        for rid in _RULE_REGISTRY.keys()
    }
    cfg = replace(app_config, audit=AuditConfig(
        enabled=True, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules=rules,
    ))
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_paginate("/api/3/asset_groups", [])
    fake_client.set_paginate("/api/3/tags", [])
    fake_client.set_paginate("/api/3/reports", [])
    fake_client.set_get("/api/3/administration/properties", {"properties": {}})
    result = ConfigurationAuditCheck().run(fake_client, cfg)
    assert result.status == "pass"
    assert all(rr.status == "skipped" for rr in result.rule_results)


class _RecordingProgress:
    """Captures step()/done() calls for assertions."""
    def __init__(self) -> None:
        self.events: list = []
    def step(self, current, total, label):
        self.events.append(("step", current, total, label))
    def done(self, current, total, label, *, duration_ms):
        self.events.append(("done", current, total, label, duration_ms))
    def newline_if_needed(self):
        pass


def test_audit_emits_skipped_progress_for_disabled_rule(app_config, fake_client, monkeypatch):
    """Rules disabled in config emit a step+done pair tagged '(skipped)'."""
    from rapid7_healthcheck.config import AuditConfig, RuleConfig
    rules = {
        rid: RuleConfig(enabled=False, severity="warn", knobs={})
        for rid in _RULE_REGISTRY.keys()
    }
    cfg = replace(app_config, audit=AuditConfig(
        enabled=True, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules=rules,
    ))
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_paginate("/api/3/asset_groups", [])
    fake_client.set_paginate("/api/3/tags", [])
    fake_client.set_paginate("/api/3/reports", [])
    fake_client.set_get("/api/3/administration/properties", {"properties": {}})

    progress = _RecordingProgress()
    ConfigurationAuditCheck().run(fake_client, cfg, progress=progress)

    skipped_steps = [
        e for e in progress.events
        if e[0] == "step" and "(skipped)" in e[3]
    ]
    skipped_dones = [
        e for e in progress.events
        if e[0] == "done" and "(skipped)" in e[3] and e[4] == 0
    ]
    assert len(skipped_steps) == len(_RULE_REGISTRY), (
        f"expected one (skipped) step per disabled rule, got {len(skipped_steps)}"
    )
    assert len(skipped_dones) == len(_RULE_REGISTRY), (
        f"expected one (skipped) done per disabled rule, got {len(skipped_dones)}"
    )


def test_one_rule_raising_does_not_break_others(app_config, fake_client, monkeypatch):
    from rapid7_healthcheck.config import AuditConfig, RuleConfig
    rules = {
        rid: RuleConfig(enabled=True, severity="warn", knobs={})
        for rid in _RULE_REGISTRY.keys()
    }
    cfg = replace(app_config, audit=AuditConfig(
        enabled=True, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules=rules,
    ))
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_get("/api/3/scan_engines", {"resources": []})
    fake_client.set_get("/api/3/shared_credentials", {"resources": []})
    fake_client.set_get("/api/3/agents", {"page": {"totalResources": 0}, "resources": []})
    fake_client.set_paginate("/api/3/agents", [])
    fake_client.set_paginate("/api/3/asset_groups", [])
    fake_client.set_paginate("/api/3/tags", [])
    fake_client.set_paginate("/api/3/reports", [])
    fake_client.set_get("/api/3/administration/properties", {"properties": {}})

    from rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template import (
        PolicyAndVulnInSameTemplateRule,
    )
    def boom(self, *args, **kw): raise RuntimeError("simulated rule failure")
    monkeypatch.setattr(PolicyAndVulnInSameTemplateRule, "run", boom)

    result = ConfigurationAuditCheck().run(fake_client, cfg)
    error_rules = [rr for rr in result.rule_results if rr.status == "error"]
    pass_rules = [rr for rr in result.rule_results if rr.status == "pass"]
    assert len(error_rules) == 1
    assert error_rules[0].rule_id == "policy_and_vuln_in_same_template"
    assert "simulated" in (error_rules[0].error or "")
    assert len(pass_rules) >= 1
