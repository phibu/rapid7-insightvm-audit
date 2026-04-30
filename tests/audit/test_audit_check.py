from __future__ import annotations

from dataclasses import replace

import pytest

from rapid7_healthcheck.audit import _RULE_REGISTRY, ConfigurationAuditCheck
import rapid7_healthcheck.audit.rules.agent_unauth_collision  # noqa: F401
import rapid7_healthcheck.audit.rules.site_vuln_template_no_creds  # noqa: F401
import rapid7_healthcheck.audit.rules.credential_failure_in_recent_scans  # noqa: F401
import rapid7_healthcheck.audit.rules.overlapping_scan_windows  # noqa: F401
import rapid7_healthcheck.audit.rules.single_engine_overload  # noqa: F401
import rapid7_healthcheck.audit.rules.discovery_template_on_prod_site  # noqa: F401
import rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template  # noqa: F401
import rapid7_healthcheck.audit.rules.store_invulnerable_results  # noqa: F401
import rapid7_healthcheck.audit.rules.local_engine_production_scope  # noqa: F401
import rapid7_healthcheck.audit.rules.dynamic_groups_and_nested_tags  # noqa: F401
import rapid7_healthcheck.audit.rules.scan_report_schedule_overlap  # noqa: F401
import rapid7_healthcheck.audit.rules.engine_version_drift  # noqa: F401
import rapid7_healthcheck.audit.rules.insight_agent_deployed  # noqa: F401
import rapid7_healthcheck.audit.rules.insight_agent_version_currency  # noqa: F401


def test_all_rules_registered():
    expected = {
        "agent_unauth_collision", "site_vuln_template_no_creds",
        "credential_failure_in_recent_scans", "overlapping_scan_windows",
        "single_engine_overload", "discovery_template_on_prod_site",
        "policy_and_vuln_in_same_template", "store_invulnerable_results",
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
        enabled=True, full_scan=False, sample_size=500, rules=rules,
    ))
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_paginate("/api/3/asset_groups", [])
    fake_client.set_paginate("/api/3/tags", [])
    fake_client.set_paginate("/api/3/reports", [])
    fake_client.set_get("/api/3/administration/properties", {"properties": {}})
    result = ConfigurationAuditCheck().run(fake_client, cfg)
    assert result.status == "pass"
    assert all(rr.status == "skipped" for rr in result.rule_results)


def test_one_rule_raising_does_not_break_others(app_config, fake_client, monkeypatch):
    from rapid7_healthcheck.config import AuditConfig, RuleConfig
    rules = {
        rid: RuleConfig(enabled=True, severity="warn", knobs={})
        for rid in _RULE_REGISTRY.keys()
    }
    cfg = replace(app_config, audit=AuditConfig(
        enabled=True, full_scan=False, sample_size=500, rules=rules,
    ))
    fake_client.set_paginate("/api/3/sites", [])
    fake_client.set_get("/api/3/scan_engines", {"resources": []})
    fake_client.set_get("/api/3/shared_credentials", {"resources": []})
    fake_client.set_get("/api/3/blackouts", {"resources": []})
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
