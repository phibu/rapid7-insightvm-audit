"""Direct tests for the descriptor-driven config builder seam.

`_build_rule_audit_config(data, spec, *, default)` is the single deep builder
behind the four `_build_*_audit_config` shims. These tests exercise it through
its `ConfigBlockSpec` interface directly (not via `load_config`), pinning the
two behaviours the collapse introduced: the `body is None` rules-only dispatch
and the explicit `BodySpec.required` gate. See CONTEXT.md "ConfigBlockSpec".
"""
from __future__ import annotations

import pytest

from rapid7_healthcheck.config import (
    AuditConfig,
    BodySpec,
    CloudDriftConfig,
    ConfigBlockSpec,
    ConfigError,
    RuleConfig,
    TemplateAuditConfig,
    _build_rule_audit_config,
    _positive_int_fields,
)


def _bodied_spec() -> ConfigBlockSpec:
    """A spec with a body and one valid rule id, no required keys."""
    return ConfigBlockSpec(
        path="probe.rules",
        body_path="probe",
        registry=lambda: frozenset({"r.ok"}),
        body=BodySpec(
            cls=AuditConfig,
            pv=lambda obj: _positive_int_fields(obj, "probe", ("sample_size",)),
        ),
    )


def _rules_only_spec() -> ConfigBlockSpec:
    """A spec with no body (cloud_drift-shaped) and one valid rule id."""
    return ConfigBlockSpec(
        path="probe.rules",
        body_path="probe",
        registry=lambda: frozenset({"r.ok"}),
        body=None,
    )


def test_none_data_returns_default_untouched():
    default = CloudDriftConfig(rules={})
    out = _build_rule_audit_config(None, _rules_only_spec(), default=default)
    assert out is default


def test_rules_only_path_rejects_body_key():
    """body=None ⇒ the only allowed top-level key is `rules`. A scalar body key
    (which a bodied spec would parse) must be rejected as an unknown key."""
    with pytest.raises(ConfigError, match=r"probe: unknown key\(s\)"):
        _build_rule_audit_config(
            {"rules": {}, "enabled": True},
            _rules_only_spec(),
            default=CloudDriftConfig(rules={}),
        )


def test_rules_only_path_builds_rules():
    out = _build_rule_audit_config(
        {"rules": {"r.ok": {"enabled": True, "severity": "warn"}}},
        _rules_only_spec(),
        default=CloudDriftConfig(rules={}),
    )
    assert isinstance(out, CloudDriftConfig)
    assert out.rules["r.ok"] == RuleConfig(enabled=True, severity="warn", knobs={})


def test_required_gate_catches_keys_the_dataclass_would_default():
    """The load-bearing case: `BodySpec.required` must reject a missing key even
    when the body dataclass *gives it a default* -- otherwise `_from_dict`'s
    MISSING-derivation wouldn't catch it and the block would silently validate.

    Uses `TemplateAuditConfig`, whose `sample_size` carries a default (500), so
    only the explicit gate can reject its omission. Sabotaging the gate makes
    this test fail (verified), unlike a body whose field has no default.
    """
    spec = ConfigBlockSpec(
        path="probe.rules",
        body_path="probe",
        registry=lambda: frozenset({"r.ok"}),
        body=BodySpec(
            cls=TemplateAuditConfig,
            pv=lambda obj: _positive_int_fields(obj, "probe", ("sample_size",)),
            required=frozenset({"enabled", "full_scan", "sample_size"}),
        ),
    )
    with pytest.raises(ConfigError, match=r"probe: missing required key\(s\)"):
        _build_rule_audit_config(
            {"enabled": True},  # full_scan + sample_size omitted; both have defaults
            spec,
            default=TemplateAuditConfig(),
        )


def test_bodied_path_unknown_rule_id_uses_path_prefix():
    with pytest.raises(ConfigError, match=r"probe\.rules: unknown rule id 'r.nope'"):
        _build_rule_audit_config(
            {"enabled": True, "full_scan": False, "sample_size": 10,
             "rules": {"r.nope": {"enabled": True, "severity": "warn"}}},
            _bodied_spec(),
            default=AuditConfig(enabled=False, full_scan=False, sample_size=500),
        )
