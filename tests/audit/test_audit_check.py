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


def test_all_rules_registered():
    expected = {
        "agent_unauth_collision", "site_vuln_template_no_creds",
        "overlapping_scan_windows",
        "single_engine_overload", "discovery_template_on_prod_site",
        "policy_and_vuln_in_same_template",
        "local_engine_production_scope", "dynamic_groups_and_nested_tags",
        "scan_report_schedule_overlap", "engine_version_drift",
        "insight_agent_deployed",
        "site_credential_centralization_candidates",
        "duplicate_credential_clusters",
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
    """Captures the hierarchical progress calls for assertions."""
    def __init__(self) -> None:
        self.events: list = []
    def start_check(self, idx, total, name):
        self.events.append(("start_check", idx, total, name))
    def finish_check(self, idx, total, name, *, status_text):
        self.events.append(("finish_check", idx, total, name, status_text))
    def start_rule(self, name):
        self.events.append(("start_rule", name))
    def finish_rule(self, name, *, status_text):
        self.events.append(("finish_rule", name, status_text))
    def newline_if_needed(self):
        pass


def test_audit_emits_skipped_progress_for_disabled_rule(app_config, fake_client, monkeypatch):
    """Each disabled rule finishes with a 'skipped' status (and no start_rule,
    since it never ran)."""
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

    skipped_finishes = [
        e for e in progress.events
        if e[0] == "finish_rule" and e[2] == "skipped"
    ]
    assert len(skipped_finishes) == len(_RULE_REGISTRY), (
        f"expected one skipped finish per disabled rule, got {len(skipped_finishes)}"
    )
    # No rule should have been started (all disabled), and no false 0ms anywhere.
    assert not any(e[0] == "start_rule" for e in progress.events)
    assert not any(len(e) > 2 and e[2] == "0ms" for e in progress.events)


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
