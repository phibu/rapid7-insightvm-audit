# Configuration Audit -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fifth check category -- `ConfigurationAuditCheck` -- that audits an InsightVM environment against eight Rapid7-documented best-practice rules, integrated into the existing `rapid7_healthcheck` tool.

**Architecture:** A single new `Check` class wraps a small rule engine. Eight rules share a lazy-loaded `EnvSnapshot` (sites, scan templates, credentials, schedules), so per-rule API cost stays bounded. Each rule is its own file under `audit/rules/`, declares its Rapid7 source URLs, and emits findings via the existing `Finding` type. The HTML report grows a conditional per-rule sub-section when `CheckResult.rule_results` is set.

**Tech Stack:** Python 3.11+, existing `requests` / `PyYAML` / `Jinja2` / `python-dotenv` / `pytest`. No new dependencies. Builds on commits up through `4a08be1` of the existing tool. Spec: `docs/superpowers/specs/2026-04-28-configuration-audit-design.md`. Research: `docs/research/best_practice_audit_rules.md`.

---

## File Map

**Created (audit subsystem):**
- `rapid7_healthcheck/audit/__init__.py` -- `Rule` Protocol, `RuleResult` dataclass, `_RULE_REGISTRY`, `ConfigurationAuditCheck` class.
- `rapid7_healthcheck/audit/snapshot.py` -- `EnvSnapshot` (lazy data container).
- `rapid7_healthcheck/audit/rules/__init__.py` -- empty package marker.
- `rapid7_healthcheck/audit/rules/agent_unauth_collision.py`
- `rapid7_healthcheck/audit/rules/site_vuln_template_no_creds.py`
- `rapid7_healthcheck/audit/rules/credential_failure_in_recent_scans.py`
- `rapid7_healthcheck/audit/rules/overlapping_scan_windows.py`
- `rapid7_healthcheck/audit/rules/single_engine_overload.py`
- `rapid7_healthcheck/audit/rules/discovery_template_on_prod_site.py`
- `rapid7_healthcheck/audit/rules/policy_and_vuln_in_same_template.py`
- `rapid7_healthcheck/audit/rules/store_invulnerable_results.py`

**Created (tests):**
- `tests/audit/__init__.py`, `tests/audit/conftest.py` (`FakeSnapshot`, fixtures)
- `tests/audit/test_snapshot.py`, `tests/audit/test_audit_check.py`
- `tests/audit/rules/__init__.py`, plus eight `test_<rule_id>.py` files

**Modified:**
- `rapid7_healthcheck/config.py` -- `AuditConfig`, `RuleConfig` dataclasses; extended root validation.
- `rapid7_healthcheck/checks/__init__.py` -- `CheckResult` gains `rule_results: list[RuleResult] | None = None`.
- `rapid7_healthcheck/templates/report.html.j2` -- conditional per-rule sub-section.
- `rapid7_healthcheck/__main__.py` -- `_REGISTRY` gains `configuration_audit: ConfigurationAuditCheck`.
- `rapid7_healthcheck/report.py` -- passes the new `rule_results` through to the template.
- `tests/test_config.py`, `tests/test_main.py`, `tests/test_report.py` -- extended.
- `config.example.yaml` -- adds the `audit:` block and the new `checks.configuration_audit` entry.
- `README.md` -- adds Configuration Audit overview, config reference, sources note.

---

## Task ordering

The plan is sequenced so each task builds on previous ones and the test suite stays green throughout. Cheap rules ship before expensive ones; the report integration ships before any rule findings can render; the orchestrator hookup ships last so the audit becomes user-visible only after all rules pass their tests.

1. Config schema + parsing (foundation)
2. Audit primitives (`Rule`, `RuleResult`, registry, `ConfigurationAuditCheck` skeleton)
3. `EnvSnapshot` (data layer)
4. Test fixtures (`FakeSnapshot`)
5. `CheckResult.rule_results` field + report renderer extension
6-13. The eight rules (one per task)
14. Orchestrator hookup + end-to-end test
15. README + smoke verification

Each rule task uses strict TDD: write the failing test using `FakeSnapshot`, run it, implement the rule, run again, commit.

---

## Task 1: `audit:` config schema

**Files:**
- Modify: `rapid7_healthcheck/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config.py`:

```python
AUDIT_BLOCK = textwrap.dedent("""
    audit:
      enabled: true
      full_scan: false
      sample_size: 500
      rules:
        agent_unauth_collision:
          enabled: true
          severity: fail
        site_vuln_template_no_creds:
          enabled: true
          severity: fail
        credential_failure_in_recent_scans:
          enabled: true
          severity: warn
        overlapping_scan_windows:
          enabled: true
          severity: warn
        single_engine_overload:
          enabled: true
          severity: warn
          asset_count_threshold: 5000
        discovery_template_on_prod_site:
          enabled: true
          severity: warn
        policy_and_vuln_in_same_template:
          enabled: true
          severity: warn
        store_invulnerable_results:
          enabled: true
          severity: info
""")


def _yaml_with_audit(checks_audit: bool = True) -> str:
    body = VALID_YAML
    body = body.replace(
        "  data_quality: true",
        "  data_quality: true\n  configuration_audit: " + ("true" if checks_audit else "false"),
    )
    return body + AUDIT_BLOCK


def test_audit_config_loads(tmp_path):
    cfg = load_config(write(tmp_path, _yaml_with_audit()))
    assert cfg.audit.enabled is True
    assert cfg.audit.full_scan is False
    assert cfg.audit.sample_size == 500
    assert cfg.audit.rules["agent_unauth_collision"].enabled is True
    assert cfg.audit.rules["agent_unauth_collision"].severity == "fail"
    assert cfg.audit.rules["single_engine_overload"].knobs["asset_count_threshold"] == 5000
    assert cfg.checks["configuration_audit"] is True


def test_audit_unknown_rule_id_raises(tmp_path):
    body = _yaml_with_audit().replace(
        "agent_unauth_collision:",
        "not_a_real_rule:",
        1,
    )
    with pytest.raises(ConfigError, match="not_a_real_rule"):
        load_config(write(tmp_path, body))


def test_audit_invalid_severity_raises(tmp_path):
    body = _yaml_with_audit().replace(
        "severity: fail",
        "severity: catastrophic",
        1,
    )
    with pytest.raises(ConfigError, match="severity"):
        load_config(write(tmp_path, body))


def test_audit_unknown_rule_knobs_silently_ignored(tmp_path):
    body = _yaml_with_audit().replace(
        "asset_count_threshold: 5000",
        "asset_count_threshold: 5000\n          future_knob: 42",
    )
    cfg = load_config(write(tmp_path, body))
    assert cfg.audit.rules["single_engine_overload"].knobs["asset_count_threshold"] == 5000
    assert cfg.audit.rules["single_engine_overload"].knobs.get("future_knob") == 42


def test_audit_missing_block_defaults_disabled(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert cfg.audit.enabled is False
    assert cfg.audit.rules == {}


def test_checks_configuration_audit_default_when_missing(tmp_path):
    cfg = load_config(write(tmp_path, _yaml_with_audit()))
    assert cfg.checks["configuration_audit"] is True
```

- [ ] **Step 2: Run tests, see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_config.py -v -k audit or test_checks_configuration_audit`
Expected: failures (`AppConfig` has no `audit` attribute).

- [ ] **Step 3: Extend `config.py` with audit dataclasses**

Append to `rapid7_healthcheck/config.py` (above `def load_config`):

```python
_VALID_RULE_IDS = {
    "agent_unauth_collision",
    "site_vuln_template_no_creds",
    "credential_failure_in_recent_scans",
    "overlapping_scan_windows",
    "single_engine_overload",
    "discovery_template_on_prod_site",
    "policy_and_vuln_in_same_template",
    "store_invulnerable_results",
}
_VALID_SEVERITIES = {"info", "warn", "fail"}


@dataclass(frozen=True)
class RuleConfig:
    enabled: bool
    severity: str
    knobs: dict


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool
    full_scan: bool
    sample_size: int
    rules: dict  # str -> RuleConfig
```

Modify `AppConfig` to add the field:

```python
@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict
    audit: AuditConfig
```

Add a builder helper above `_build_app_config`:

```python
def _build_audit_config(data: dict | None) -> AuditConfig:
    if data is None:
        return AuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})
    if not isinstance(data, dict):
        raise ConfigError("audit: expected mapping")
    expected = {"enabled", "full_scan", "sample_size", "rules"}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"audit: unknown key(s): {sorted(unknown)}")
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("audit.enabled: expected bool")
    if not isinstance(data.get("full_scan"), bool):
        raise ConfigError("audit.full_scan: expected bool")
    if not isinstance(data.get("sample_size"), int) or isinstance(data.get("sample_size"), bool) or data["sample_size"] <= 0:
        raise ConfigError("audit.sample_size: expected positive int")

    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("audit.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_RULE_IDS:
            raise ConfigError(f"audit.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"audit.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"audit.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"audit.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)

    return AuditConfig(
        enabled=data["enabled"],
        full_scan=data["full_scan"],
        sample_size=data["sample_size"],
        rules=rules,
    )
```

In `_build_app_config`, change the expected-root set and wire in audit:

```python
def _build_app_config(data: dict) -> AppConfig:
    expected_root = {"rapid7", "report", "thresholds", "checks", "audit"}
    unknown = set(data.keys()) - expected_root
    if unknown:
        raise ConfigError(f"unknown root key(s): {sorted(unknown)}")
    required_root = expected_root - {"audit"}  # audit is optional
    missing = required_root - set(data.keys())
    if missing:
        raise ConfigError(f"missing required root key(s): {sorted(missing)}")

    rapid7_data = dict(data["rapid7"])
    if isinstance(rapid7_data.get("base_url"), str):
        rapid7_data["base_url"] = rapid7_data["base_url"].strip()
    rapid7 = _from_dict(Rapid7Config, rapid7_data, "rapid7")
    if not rapid7.base_url.startswith("https://"):
        raise ConfigError("rapid7.base_url must start with https://")

    report = _from_dict(ReportConfig, data["report"], "report")
    thresholds = _build_thresholds(data["thresholds"])

    checks = data["checks"]
    if not isinstance(checks, dict) or not all(isinstance(v, bool) for v in checks.values()):
        raise ConfigError("checks: expected mapping of name -> bool")
    if "configuration_audit" not in checks:
        checks = dict(checks)
        checks["configuration_audit"] = True

    audit = _build_audit_config(data.get("audit"))
    return AppConfig(rapid7=rapid7, report=report, thresholds=thresholds, checks=checks, audit=audit)
```

- [ ] **Step 4: Run tests, see them pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_config.py -v`
Expected: 14 original + 6 new = 20 passed.

- [ ] **Step 5: Run full suite for no regression**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 70 + 6 = 76 passed.

- [ ] **Step 6: Update `config.example.yaml`**

Add at the bottom (after the existing `checks:` block) and add `configuration_audit: true` inside the existing `checks:` block.

```yaml
  configuration_audit: true   # NEW: master toggle for the Configuration Audit check

audit:
  enabled: true
  full_scan: false
  sample_size: 500
  rules:
    agent_unauth_collision:
      enabled: true
      severity: fail
    site_vuln_template_no_creds:
      enabled: true
      severity: fail
    credential_failure_in_recent_scans:
      enabled: true
      severity: warn
    overlapping_scan_windows:
      enabled: true
      severity: warn
    single_engine_overload:
      enabled: true
      severity: warn
      asset_count_threshold: 5000
    discovery_template_on_prod_site:
      enabled: true
      severity: warn
    policy_and_vuln_in_same_template:
      enabled: true
      severity: warn
    store_invulnerable_results:
      enabled: true
      severity: info
```

- [ ] **Step 7: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/config.py tests/test_config.py config.example.yaml
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(config): add audit block with per-rule severity and knobs"
```

---

## Task 2: Audit primitives -- `Rule`, `RuleResult`, `ConfigurationAuditCheck` skeleton

**Files:**
- Create: `rapid7_healthcheck/audit/__init__.py`

This task only ships the contract and an empty registry. The `ConfigurationAuditCheck` produces a "no rules" result. Subsequent tasks register rules.

- [ ] **Step 1: Create the file**

```python
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from rapid7_healthcheck.checks import CheckResult, Finding, Severity, Status
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    sampled: bool = False
    sample_info: str | None = None
    sources: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0


class Rule(Protocol):
    rule_id: str
    rule_name: str
    description: str
    default_severity: Severity
    expensive: bool
    sources: list[str]

    def run(
        self,
        snapshot: Any,        # EnvSnapshot -- late-bound to avoid circular import
        severity: Severity,
        full_scan: bool,
        sample_size: int,
        rule_config: dict,
    ) -> RuleResult: ...


_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register(rule_cls: type[Rule]) -> type[Rule]:
    _RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


def _rollup_audit_status(rule_results: list[RuleResult]) -> Status:
    if any(r.status in ("fail", "error") for r in rule_results):
        return "fail"
    if any(r.status == "warn" for r in rule_results):
        return "warn"
    return "pass"


def _flatten_findings(rule_results: list[RuleResult]) -> list[Finding]:
    return [f for r in rule_results for f in r.findings]


class ConfigurationAuditCheck:
    name = "Configuration Audit"
    description = "Best-practice configuration audits sourced from Rapid7 documentation."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()

        if not config.audit.enabled:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[],
                summary={"reason": "audit.enabled is false"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        from rapid7_healthcheck.audit.snapshot import EnvSnapshot
        snapshot = EnvSnapshot(
            client,
            full_scan=config.audit.full_scan,
            sample_size=config.audit.sample_size,
        )

        rule_results: list[RuleResult] = []
        for rule_id, rule_cls in _RULE_REGISTRY.items():
            rule_cfg = config.audit.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                continue
            rule_start = time.monotonic()
            try:
                result = rule_cls().run(
                    snapshot,
                    rule_cfg.severity,
                    config.audit.full_scan,
                    config.audit.sample_size,
                    rule_cfg.knobs,
                )
                result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                rule_results.append(result)
            except Exception as e:  # per-rule isolation
                logger.exception("audit rule %s raised", rule_id)
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity=rule_cfg.severity,
                    status="error",
                    sources=list(rule_cls.sources),
                    error=str(e),
                    duration_ms=int((time.monotonic() - rule_start) * 1000),
                ))

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
```

This file references `CheckResult.rule_results`, which doesn't exist yet -- Task 3 adds it. We commit Task 2 + Task 3 together to avoid a broken intermediate state.

- [ ] **Step 2: Defer commit until Task 3**

Move on to Task 3.

---

## Task 3: `CheckResult.rule_results` field

**Files:**
- Modify: `rapid7_healthcheck/checks/__init__.py`

- [ ] **Step 1: Add the optional field**

Open `rapid7_healthcheck/checks/__init__.py` and modify the `CheckResult` dataclass. Add the import for `RuleResult` lazily inside a `TYPE_CHECKING` block to avoid circular import:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from rapid7_healthcheck.config import AppConfig

if TYPE_CHECKING:
    from rapid7_healthcheck.audit import RuleResult


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
```

- [ ] **Step 2: Verify imports**

Run: `.venv/Scripts/python.exe -c "from rapid7_healthcheck.checks import CheckResult; print(CheckResult(name='x', description='y', status='pass').rule_results)"`
Expected: `None`

- [ ] **Step 3: Run full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: still 76 passed (no behavior change for existing checks).

- [ ] **Step 4: Commit Tasks 2 + 3 together**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/__init__.py rapid7_healthcheck/checks/__init__.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add Rule contract, registry, and ConfigurationAuditCheck skeleton"
```

---

## Task 4: `EnvSnapshot`

**Files:**
- Create: `rapid7_healthcheck/audit/snapshot.py`
- Create: `tests/audit/__init__.py`, `tests/audit/conftest.py` (placeholder fixtures), `tests/audit/test_snapshot.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/audit/__init__.py` (empty).

Create `tests/audit/test_snapshot.py`:

```python
from __future__ import annotations

import pytest

from rapid7_healthcheck.audit.snapshot import EnvSnapshot


class _FakeClient:
    def __init__(self):
        self.get_calls: list[tuple[str, dict | None]] = []
        self.paginate_calls: list[tuple[str, dict | None]] = []
        self._get: dict[str, dict] = {}
        self._paginate: dict[str, list[dict]] = {}

    def set_get(self, path: str, body: dict): self._get[path] = body

    def set_paginate(self, path: str, items: list[dict]): self._paginate[path] = items

    def get(self, path: str, params: dict | None = None) -> dict:
        self.get_calls.append((path, params))
        if path not in self._get:
            raise AssertionError(f"unexpected GET {path}")
        return self._get[path]

    def paginate(self, path: str, params: dict | None = None, page_size: int = 500):
        self.paginate_calls.append((path, params))
        if path not in self._paginate:
            raise AssertionError(f"unexpected paginate {path}")
        yield from self._paginate[path]


def test_sites_cached():
    c = _FakeClient()
    c.set_paginate("/api/3/sites", [{"id": 1}, {"id": 2}])
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert [x["id"] for x in s.sites()] == [1, 2]
    assert [x["id"] for x in s.sites()] == [1, 2]
    assert len(c.paginate_calls) == 1


def test_scan_template_cached_per_id():
    c = _FakeClient()
    c.set_get("/api/3/scan_templates/full-audit", {"id": "full-audit", "name": "Full"})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.scan_template("full-audit")
    s.scan_template("full-audit")
    assert sum(1 for p, _ in c.get_calls if p == "/api/3/scan_templates/full-audit") == 1


def test_site_asset_count_uses_size_one():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 42}})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    assert s.site_asset_count(7) == 42
    path, params = c.get_calls[0]
    assert path == "/api/3/sites/7/assets"
    assert params == {"size": 1}


def test_asset_sample_returns_total_when_sampling():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 9999}})
    c.set_paginate("/api/3/sites/7/assets", [{"id": i} for i in range(7)])
    s = EnvSnapshot(c, full_scan=False, sample_size=5)
    sampled, total = s.asset_sample(7)
    assert total == 9999
    assert len(sampled) == 5
    assert [a["id"] for a in sampled] == [0, 1, 2, 3, 4]


def test_asset_sample_full_scan_returns_all():
    c = _FakeClient()
    c.set_get("/api/3/sites/7/assets", {"resources": [], "page": {"totalResources": 7}})
    c.set_paginate("/api/3/sites/7/assets", [{"id": i} for i in range(7)])
    s = EnvSnapshot(c, full_scan=True, sample_size=5)
    sampled, total = s.asset_sample(7)
    assert total == 7
    assert len(sampled) == 7
```

- [ ] **Step 2: Run tests, see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/test_snapshot.py -v`
Expected: import error (no `EnvSnapshot` yet).

- [ ] **Step 3: Implement `EnvSnapshot`**

Create `rapid7_healthcheck/audit/snapshot.py`:

```python
from __future__ import annotations

import itertools
import logging
from typing import Any

logger = logging.getLogger(__name__)


class EnvSnapshot:
    def __init__(self, client: Any, *, full_scan: bool, sample_size: int) -> None:
        self._client = client
        self._full_scan = full_scan
        self._sample_size = sample_size

        self._sites: list[dict] | None = None
        self._scan_engines: list[dict] | None = None
        self._shared_credentials: list[dict] | None = None
        self._blackouts: list[dict] | None = None
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._site_recent_scans: dict[tuple[int, int], list[dict]] = {}
        self._asset_history: dict[int, list[dict]] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}

    @property
    def full_scan(self) -> bool:
        return self._full_scan

    @property
    def sample_size(self) -> int:
        return self._sample_size

    def sites(self) -> list[dict]:
        if self._sites is None:
            self._sites = list(self._client.paginate("/api/3/sites"))
        return self._sites

    def scan_engines(self) -> list[dict]:
        if self._scan_engines is None:
            body = self._client.get("/api/3/scan_engines")
            self._scan_engines = list(body.get("resources", []))
        return self._scan_engines

    def shared_credentials(self) -> list[dict]:
        if self._shared_credentials is None:
            body = self._client.get("/api/3/shared_credentials")
            self._shared_credentials = list(body.get("resources", []))
        return self._shared_credentials

    def blackouts(self) -> list[dict]:
        if self._blackouts is None:
            body = self._client.get("/api/3/blackouts")
            self._blackouts = list(body.get("resources", []))
        return self._blackouts

    def site_credentials(self, site_id: int) -> list[dict]:
        if site_id not in self._site_credentials:
            body = self._client.get(f"/api/3/sites/{site_id}/site_credentials")
            self._site_credentials[site_id] = list(body.get("resources", []))
        return self._site_credentials[site_id]

    def site_schedules(self, site_id: int) -> list[dict]:
        if site_id not in self._site_schedules:
            body = self._client.get(f"/api/3/sites/{site_id}/scan_schedules")
            self._site_schedules[site_id] = list(body.get("resources", []))
        return self._site_schedules[site_id]

    def site_included_targets(self, site_id: int) -> list[dict]:
        if site_id not in self._site_included_targets:
            body = self._client.get(f"/api/3/sites/{site_id}/included_targets")
            self._site_included_targets[site_id] = list(body.get("addresses", body.get("resources", [])))
        return self._site_included_targets[site_id]

    def site_asset_count(self, site_id: int) -> int:
        if site_id not in self._site_asset_count:
            body = self._client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
            self._site_asset_count[site_id] = int(body.get("page", {}).get("totalResources", 0))
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            self._scan_templates[template_id] = self._client.get(
                f"/api/3/scan_templates/{template_id}"
            )
        return self._scan_templates[template_id]

    def site_recent_scans(self, site_id: int, max_n: int = 20) -> list[dict]:
        key = (site_id, max_n)
        if key not in self._site_recent_scans:
            body = self._client.get(
                f"/api/3/sites/{site_id}/scans",
                params={"sort": "startTime,DESC", "size": max_n},
            )
            self._site_recent_scans[key] = list(body.get("resources", []))
        return self._site_recent_scans[key]

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            total = self.site_asset_count(site_id)
            it = self._client.paginate(f"/api/3/sites/{site_id}/assets")
            if self._full_scan:
                items = list(it)
            else:
                items = list(itertools.islice(it, self._sample_size))
            self._asset_samples[site_id] = (items, total)
        return self._asset_samples[site_id]

    def asset_history(self, asset_id: int) -> list[dict]:
        if asset_id not in self._asset_history:
            body = self._client.get(f"/api/3/assets/{asset_id}/history")
            self._asset_history[asset_id] = list(body.get("history", body.get("resources", [])))
        return self._asset_history[asset_id]
```

- [ ] **Step 4: Run tests, see them pass**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/test_snapshot.py -v`
Expected: 5 passed.

- [ ] **Step 5: Run full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 76 + 5 = 81 passed.

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/snapshot.py tests/audit/__init__.py tests/audit/test_snapshot.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add EnvSnapshot with lazy caching and sampling"
```

---

## Task 5: `FakeSnapshot` and shared audit fixtures

**Files:**
- Create: `tests/audit/conftest.py`
- Create: `tests/audit/rules/__init__.py`

- [ ] **Step 1: Create the test fixtures**

Create `tests/audit/rules/__init__.py` (empty).

Create `tests/audit/conftest.py`:

```python
from __future__ import annotations

from typing import Any

import pytest


class FakeSnapshot:
    """Test double for EnvSnapshot. Each public method is backed by a settable dict.

    Tests register the data their rule will consume; unregistered calls raise
    AssertionError (so a typo in a rule shows up loudly in tests).
    """

    def __init__(self, *, full_scan: bool = False, sample_size: int = 500) -> None:
        self._full_scan = full_scan
        self._sample_size = sample_size
        self._sites: list[dict] = []
        self._scan_engines: list[dict] = []
        self._shared_credentials: list[dict] = []
        self._blackouts: list[dict] = []
        self._site_credentials: dict[int, list[dict]] = {}
        self._site_schedules: dict[int, list[dict]] = {}
        self._site_included_targets: dict[int, list[dict]] = {}
        self._site_asset_count: dict[int, int] = {}
        self._scan_templates: dict[str, dict] = {}
        self._site_recent_scans: dict[int, list[dict]] = {}
        self._asset_samples: dict[int, tuple[list[dict], int]] = {}
        self._asset_history: dict[int, list[dict]] = {}

    @property
    def full_scan(self) -> bool: return self._full_scan

    @property
    def sample_size(self) -> int: return self._sample_size

    # ---- registration helpers used by tests ----

    def set_sites(self, sites: list[dict]) -> None: self._sites = sites
    def set_scan_engines(self, engines: list[dict]) -> None: self._scan_engines = engines
    def set_shared_credentials(self, creds: list[dict]) -> None: self._shared_credentials = creds
    def set_blackouts(self, blackouts: list[dict]) -> None: self._blackouts = blackouts
    def set_site_credentials(self, site_id: int, creds: list[dict]) -> None: self._site_credentials[site_id] = creds
    def set_site_schedules(self, site_id: int, schedules: list[dict]) -> None: self._site_schedules[site_id] = schedules
    def set_site_included_targets(self, site_id: int, targets: list[dict]) -> None: self._site_included_targets[site_id] = targets
    def set_site_asset_count(self, site_id: int, n: int) -> None: self._site_asset_count[site_id] = n
    def set_scan_template(self, template_id: str, template: dict) -> None: self._scan_templates[template_id] = template
    def set_site_recent_scans(self, site_id: int, scans: list[dict]) -> None: self._site_recent_scans[site_id] = scans
    def set_asset_sample(self, site_id: int, assets: list[dict], total: int) -> None: self._asset_samples[site_id] = (assets, total)
    def set_asset_history(self, asset_id: int, history: list[dict]) -> None: self._asset_history[asset_id] = history

    # ---- mirror of EnvSnapshot's public API ----

    def sites(self) -> list[dict]: return self._sites
    def scan_engines(self) -> list[dict]: return self._scan_engines
    def shared_credentials(self) -> list[dict]: return self._shared_credentials
    def blackouts(self) -> list[dict]: return self._blackouts

    def site_credentials(self, site_id: int) -> list[dict]:
        if site_id not in self._site_credentials:
            raise AssertionError(f"FakeSnapshot.site_credentials({site_id}) not registered")
        return self._site_credentials[site_id]

    def site_schedules(self, site_id: int) -> list[dict]:
        if site_id not in self._site_schedules:
            raise AssertionError(f"FakeSnapshot.site_schedules({site_id}) not registered")
        return self._site_schedules[site_id]

    def site_included_targets(self, site_id: int) -> list[dict]:
        if site_id not in self._site_included_targets:
            raise AssertionError(f"FakeSnapshot.site_included_targets({site_id}) not registered")
        return self._site_included_targets[site_id]

    def site_asset_count(self, site_id: int) -> int:
        if site_id not in self._site_asset_count:
            raise AssertionError(f"FakeSnapshot.site_asset_count({site_id}) not registered")
        return self._site_asset_count[site_id]

    def scan_template(self, template_id: str) -> dict:
        if template_id not in self._scan_templates:
            raise AssertionError(f"FakeSnapshot.scan_template({template_id!r}) not registered")
        return self._scan_templates[template_id]

    def site_recent_scans(self, site_id: int, max_n: int = 20) -> list[dict]:
        if site_id not in self._site_recent_scans:
            raise AssertionError(f"FakeSnapshot.site_recent_scans({site_id}) not registered")
        return self._site_recent_scans[site_id][:max_n]

    def asset_sample(self, site_id: int) -> tuple[list[dict], int]:
        if site_id not in self._asset_samples:
            raise AssertionError(f"FakeSnapshot.asset_sample({site_id}) not registered")
        return self._asset_samples[site_id]

    def asset_history(self, asset_id: int) -> list[dict]:
        if asset_id not in self._asset_history:
            raise AssertionError(f"FakeSnapshot.asset_history({asset_id}) not registered")
        return self._asset_history[asset_id]


@pytest.fixture
def fake_snapshot() -> FakeSnapshot:
    return FakeSnapshot()
```

- [ ] **Step 2: Verify import**

Run: `.venv/Scripts/python.exe -m pytest tests/audit -v --collect-only`
Expected: collects existing snapshot tests; no errors.

- [ ] **Step 3: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add tests/audit/conftest.py tests/audit/rules/__init__.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "test(audit): add FakeSnapshot test double"
```

---

## Task 6: Report rendering -- per-rule sub-section

**Files:**
- Modify: `rapid7_healthcheck/templates/report.html.j2`
- Modify: `rapid7_healthcheck/report.py`
- Modify: `tests/test_report.py`

This task ensures the report renders an audit-style `CheckResult` correctly *before* any rules ship findings. We synthesize a `CheckResult` with `rule_results` and assert the HTML.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_report.py`:

```python
from rapid7_healthcheck.audit import RuleResult


def test_audit_section_renders_per_rule_table():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="rule one desc",
            severity="warn", status="warn",
            findings=[Finding(severity="warn", message="something off")],
            sources=["https://docs.rapid7.com/foo"],
        ),
        RuleResult(
            rule_id="r2", rule_name="Rule Two", description="rule two desc",
            severity="info", status="pass",
            sources=["https://docs.rapid7.com/bar"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="warn",
        findings=[Finding(severity="warn", message="something off")],
        summary={"rules_total": 2, "rules_warn": 1, "rules_pass": 1},
        rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    # Per-rule table headers
    assert "Rule One" in html
    assert "Rule Two" in html
    assert "rule one desc" in html
    assert "https://docs.rapid7.com/foo" in html
    assert "https://docs.rapid7.com/bar" in html
    # Sources rendered as anchor tags
    assert 'href="https://docs.rapid7.com/foo"' in html
    # No <script> tags introduced
    assert "<script" not in html


def test_audit_section_shows_sampling_note():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="d",
            severity="warn", status="warn",
            findings=[Finding(severity="warn", message="m")],
            sampled=True, sample_info="checked 500 of 4200 assets",
            sources=["https://docs.rapid7.com/foo"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="warn", findings=[Finding(severity="warn", message="m")],
        rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    assert "checked 500 of 4200 assets" in html


def test_audit_section_shows_rule_error():
    rr = [
        RuleResult(
            rule_id="r1", rule_name="Rule One", description="d",
            severity="fail", status="error",
            error="boom: KeyError 'sites'",
            sources=["https://docs.rapid7.com/foo"],
        ),
    ]
    cr = CheckResult(
        name="Configuration Audit", description="d",
        status="fail", rule_results=rr,
    )
    html = render_report(_ctx([cr]))
    assert "boom: KeyError" in html


def test_non_audit_check_unchanged_when_rule_results_none():
    cr = CheckResult(name="Scan Engines", description="d", status="pass", findings=[])
    html = render_report(_ctx([cr]))
    # No per-rule artifacts leak into a plain check
    assert "Rule One" not in html
```

- [ ] **Step 2: Run tests, see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_report.py -v -k audit_section`
Expected: failures (template doesn't render rule_results yet).

- [ ] **Step 3: Extend the template**

Open `rapid7_healthcheck/templates/report.html.j2`. Inside the per-check section block (the `{% for r in results %}` loop), find the existing branch for normal checks (the `else` branch under `{% if r.status == "error" %}` ... `{% elif r.status == "skipped" %}` ... `{% else %}`). Add a sub-branch at the START of the `else` body that handles the audit-shape `CheckResult`:

Replace:

```html
  {% else %}
    {% if r.summary %}
    <div class="tiles">
```

with:

```html
  {% else %}
    {% if r.rule_results %}
      <div class="tiles">
        <div class="tile"><b>{{ r.summary.rules_total }}</b> rules</div>
        <div class="tile"><b>{{ r.summary.rules_pass }}</b> pass</div>
        <div class="tile"><b>{{ r.summary.rules_warn }}</b> warn</div>
        <div class="tile"><b>{{ r.summary.rules_fail }}</b> fail</div>
        <div class="tile"><b>{{ r.summary.rules_error }}</b> error</div>
        <div class="tile"><b>{{ r.summary.rules_skipped }}</b> skipped</div>
      </div>

      <table>
        <thead><tr><th>Rule</th><th>Status</th><th>Findings</th><th>Notes</th></tr></thead>
        <tbody>
        {% for rr in r.rule_results %}
          <tr>
            <td><a href="#rule-{{ loop.index0 }}-{{ loop.index }}">{{ rr.rule_name }}</a></td>
            <td><span class="badge {{ rr.status }}">{{ rr.status|upper }}</span></td>
            <td>{{ rr.findings|length }}</td>
            <td>{% if rr.sampled %}sampled{% endif %}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>

      {% for rr in r.rule_results %}
      <details id="rule-{{ loop.index0 }}-{{ loop.index }}">
        <summary><b>{{ rr.rule_name }}</b> <span class="badge {{ rr.status }}">{{ rr.status|upper }}</span></summary>
        <p class="check-desc">{{ rr.description }}</p>

        {% if rr.status == "error" %}
          <div class="error-box"><b>Rule failed to run:</b> {{ rr.error }}</div>
        {% elif rr.status == "skipped" %}
          <div class="skipped-box">This rule is disabled in <code>config.yaml</code> (audit.rules.{{ rr.rule_id }}.enabled: false).</div>
        {% else %}
          {% if rr.sampled %}
            <p class="check-desc"><i>Note: {{ rr.sample_info }}</i></p>
          {% endif %}
          {% if rr.findings %}
          <table>
            <thead><tr><th>Severity</th><th>Message</th></tr></thead>
            <tbody>
            {% for f in rr.findings %}
              <tr>
                <td><span class="badge {{ 'fail' if f.severity == 'fail' else 'warn' if f.severity == 'warn' else 'pass' }}">{{ f.severity|upper }}</span></td>
                <td>
                  {{ f.message }}
                  {% if f.details %}
                    <details><summary>details</summary><pre>{{ f.details_json }}</pre></details>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% else %}
          <p>No findings.</p>
          {% endif %}
        {% endif %}

        {% if rr.sources %}
        <p class="check-desc"><b>Sources:</b></p>
        <ul>
          {% for src in rr.sources %}
            <li><a href="{{ src }}" target="_blank" rel="noopener noreferrer">{{ src }}</a></li>
          {% endfor %}
        </ul>
        {% endif %}
      </details>
      {% endfor %}

    {% elif r.summary %}
    <div class="tiles">
```

(Note the `{% elif r.summary %}` continuation -- the existing summary-tile + findings-table block becomes the fallback for non-audit checks. Leave the rest of that block intact.)

- [ ] **Step 4: Update `_annotate_findings` to also annotate rule_results' findings**

In `rapid7_healthcheck/report.py`, modify `_annotate_findings`:

```python
def _annotate_findings(results: list[CheckResult]) -> None:
    """Attach a pre-serialized JSON string for each finding's details.

    `Finding` is `frozen=True`, so attribute assignment is normally blocked.
    `object.__setattr__` bypasses that to attach a `details_json` slot used by
    the Jinja template. We pre-serialize here (rather than in the template) so
    autoescape treats the JSON as plain text -- `<` characters in details would
    otherwise break the HTML. The mutation is intentional and confined to the
    render path; downstream code does not rely on `Finding` immutability.
    """
    def annotate_one(f):
        if f.details is not None:
            object.__setattr__(f, "details_json", json.dumps(f.details, indent=2, default=str))
        else:
            object.__setattr__(f, "details_json", "")

    for r in results:
        for f in r.findings:
            annotate_one(f)
        if r.rule_results:
            for rr in r.rule_results:
                for f in rr.findings:
                    annotate_one(f)
```

- [ ] **Step 5: Run tests, see them pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_report.py -v`
Expected: 9 existing + 4 new = 13 passed.

- [ ] **Step 6: Run full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 81 + 4 = 85 passed.

- [ ] **Step 7: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/templates/report.html.j2 rapid7_healthcheck/report.py tests/test_report.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(report): render per-rule sub-section for audit CheckResults"
```

---

## Task 7: Rule -- `site_vuln_template_no_creds` (cheap, foundational)

**Why first among rules:** simplest and exercises the full plumbing (snapshot → rule → registry → audit check). The other rules build on the same shape.

**Files:**
- Create: `rapid7_healthcheck/audit/rules/site_vuln_template_no_creds.py`
- Create: `tests/audit/rules/test_site_vuln_template_no_creds.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/audit/rules/test_site_vuln_template_no_creds.py`:

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import (
    SiteVulnTemplateNoCredsRule,
)


def test_no_findings_when_creds_present(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []


def test_finding_when_vuln_template_and_no_creds(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "fail"
    assert "Prod" in r.findings[0].message


def test_skip_when_template_has_no_vuln_checks(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "DiscOnly", "scanTemplate": {"id": "tpl-disc"}}])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_skip_empty_site(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Empty", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 0)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_shared_credentials_count(fake_snapshot):
    # A shared credential restricted to site 1 should satisfy the rule.
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([{"id": 9, "enabled": True, "sites": [1]}])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_severity_override_warns(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod", "scanTemplate": {"id": "tpl-vuln"}}])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 100)
    r = SiteVulnTemplateNoCredsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.findings[0].severity == "warn"
```

- [ ] **Step 2: Run tests, see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/rules/test_site_vuln_template_no_creds.py -v`
Expected: import error.

- [ ] **Step 3: Implement the rule**

Create `rapid7_healthcheck/audit/rules/site_vuln_template_no_creds.py`:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import Rule, RuleResult, register
from rapid7_healthcheck.checks import Finding


def _site_has_credentials(snapshot, site_id: int) -> bool:
    site_creds = snapshot.site_credentials(site_id)
    if any(c.get("enabled", False) for c in site_creds):
        return True
    for shared in snapshot.shared_credentials():
        if not shared.get("enabled", False):
            continue
        sites_restriction = shared.get("sites")
        if sites_restriction is None:
            return True  # unrestricted shared credential applies everywhere
        if site_id in sites_restriction:
            return True
    return False


@register
class SiteVulnTemplateNoCredsRule:
    rule_id = "site_vuln_template_no_creds"
    rule_name = "Vulnerability Template Without Credentials"
    description = (
        "Sites whose scan template has Vulnerability checks enabled but have no enabled "
        "credentials configured. Without credentials, vuln scans fall back to remote checks "
        "only and silently degrade risk-score accuracy."
    )
    default_severity = "fail"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
        "https://docs.rapid7.com/insightvm/configuring-scan-credentials/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        for site in snapshot.sites():
            sites_examined += 1
            site_id = site.get("id")
            site_name = site.get("name", f"id={site_id}")
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not (tpl.get("vulnerabilityChecks") or {}).get("enabled"):
                continue
            if snapshot.site_asset_count(site_id) <= 0:
                continue
            if _site_has_credentials(snapshot, site_id):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{site_name}' uses vuln-check template '{tpl.get('name', tpl_id)}' "
                    f"but has no enabled credentials"
                ),
                details={"site_id": site_id, "template_id": tpl_id, "template_name": tpl.get("name")},
            ))
            sites_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Run tests, see them pass**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/rules/test_site_vuln_template_no_creds.py -v`
Expected: 6 passed.

- [ ] **Step 5: Run full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 85 + 6 = 91 passed.

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/site_vuln_template_no_creds.py tests/audit/rules/test_site_vuln_template_no_creds.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule site_vuln_template_no_creds"
```

---

## Task 8: Rule -- `policy_and_vuln_in_same_template` (cheap)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/policy_and_vuln_in_same_template.py`
- Create: `tests/audit/rules/test_policy_and_vuln_in_same_template.py`

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template import (
    PolicyAndVulnInSameTemplateRule,
)


def _site(site_id, name, tpl_id): return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_template_separates_concerns(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln Only",
                                                  "vulnerabilityChecks": {"enabled": True},
                                                  "policyEnabled": False})
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_template_has_both(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl-mixed"), _site(2, "B", "tpl-mixed")])
    fake_snapshot.set_scan_template("tpl-mixed", {"id": "tpl-mixed", "name": "Mixed",
                                                   "vulnerabilityChecks": {"enabled": True},
                                                   "policyEnabled": True})
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1  # one finding per offending TEMPLATE, not per site
    assert "Mixed" in r.findings[0].message
    assert sorted(r.findings[0].details["sites_using"]) == [1, 2]


def test_template_only_evaluated_when_in_use(fake_snapshot):
    # Even if a template would be a violation, if no site references it, no finding.
    fake_snapshot.set_sites([])
    r = PolicyAndVulnInSameTemplateRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.findings == []
```

- [ ] **Step 2: Run tests, see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/rules/test_policy_and_vuln_in_same_template.py -v`

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


@register
class PolicyAndVulnInSameTemplateRule:
    rule_id = "policy_and_vuln_in_same_template"
    rule_name = "Policy and Vulnerability in Same Template"
    description = (
        "Scan templates with both Policy checks and Vulnerability checks enabled. "
        "Rapid7 recommends separating these into distinct templates."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        # Map template_id -> [site_id] for templates currently in use
        in_use: dict[str, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if tpl_id:
                in_use[tpl_id].append(site["id"])

        findings: list[Finding] = []
        for tpl_id, site_ids in in_use.items():
            tpl = snapshot.scan_template(tpl_id)
            policy_on = bool(tpl.get("policyEnabled"))
            vuln_on = bool((tpl.get("vulnerabilityChecks") or {}).get("enabled"))
            if policy_on and vuln_on:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{tpl.get('name', tpl_id)}' has both Policy and Vulnerability "
                        f"checks enabled -- Rapid7 recommends separate templates"
                    ),
                    details={"template_id": tpl_id, "sites_using": site_ids},
                ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"templates_examined": len(in_use), "templates_flagged": len(findings)},
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Run tests, expect 3 passed**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/rules/test_policy_and_vuln_in_same_template.py -v`

- [ ] **Step 5: Run full suite, expect 91 + 3 = 94 passed**

Run: `.venv/Scripts/python.exe -m pytest -q`

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/policy_and_vuln_in_same_template.py tests/audit/rules/test_policy_and_vuln_in_same_template.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule policy_and_vuln_in_same_template"
```

---

## Task 9: Rule -- `store_invulnerable_results` (cheap)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/store_invulnerable_results.py`
- Create: `tests/audit/rules/test_store_invulnerable_results.py`

The v3 schema field name varies; the rule probes a small list of known field names and emits an info-level diagnostic finding if none are present.

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.store_invulnerable_results import StoreInvulnerableResultsRule


def _site(site_id, name, tpl_id): return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_setting_disabled(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "T",
                                               "enableScanLog": False})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert r.status == "pass"


def test_finding_when_setting_enabled_via_enable_scan_log(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "enableScanLog": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    # Info-severity findings don't escalate status above "pass"
    assert r.status == "pass"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "info"
    assert "Bloated" in r.findings[0].message


def test_finding_when_severity_overridden_to_warn(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "enableScanLog": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_alternate_field_name(fake_snapshot):
    # Tolerant of either common field name.
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Bloated",
                                               "storeInvulnerableResults": True})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    assert len(r.findings) == 1


def test_diagnostic_when_no_known_field_present(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", "tpl1")])
    fake_snapshot.set_scan_template("tpl1", {"id": "tpl1", "name": "Foo"})
    r = StoreInvulnerableResultsRule().run(fake_snapshot, "info", False, 500, {})
    # One info-level diagnostic finding noting the field couldn't be found.
    assert any("could not locate" in f.message.lower() for f in r.findings)
```

- [ ] **Step 2: Run tests, see them fail**

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding

_KNOWN_FIELDS = ("enableScanLog", "storeInvulnerableResults", "store_invulnerable_results")


def _read_setting(template: dict) -> bool | None:
    for f in _KNOWN_FIELDS:
        if f in template:
            return bool(template[f])
    return None


@register
class StoreInvulnerableResultsRule:
    rule_id = "store_invulnerable_results"
    rule_name = "Store Invulnerable Results Enabled"
    description = (
        "Scan templates with 'Store invulnerable results' enabled. Rapid7 recommends "
        "leaving this disabled unless explicitly required by a PCI auditor."
    )
    default_severity = "info"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        in_use: dict[str, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if tpl_id:
                in_use[tpl_id].append(site["id"])

        findings: list[Finding] = []
        diagnostics_emitted = False
        for tpl_id, site_ids in in_use.items():
            tpl = snapshot.scan_template(tpl_id)
            value = _read_setting(tpl)
            if value is None:
                if not diagnostics_emitted:
                    findings.append(Finding(
                        severity="info",
                        message=(
                            "Could not locate 'store invulnerable results' field in scan template "
                            f"schema (tried {list(_KNOWN_FIELDS)}); rule cannot evaluate."
                        ),
                        details={"template_id": tpl_id},
                    ))
                    diagnostics_emitted = True
                continue
            if value:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Template '{tpl.get('name', tpl_id)}' has 'Store invulnerable results' "
                        f"enabled -- Rapid7 recommends disabling unless required by PCI auditor"
                    ),
                    details={"template_id": tpl_id, "sites_using": site_ids},
                ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"templates_examined": len(in_use), "templates_flagged": sum(
                1 for f in findings if "Store invulnerable" in f.message
            )},
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Run tests, expect 5 passed**

- [ ] **Step 5: Run full suite, expect 99 passed**

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/store_invulnerable_results.py tests/audit/rules/test_store_invulnerable_results.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule store_invulnerable_results"
```

---

## Task 10: Rule -- `single_engine_overload` (cheap, configurable threshold)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/single_engine_overload.py`
- Create: `tests/audit/rules/test_single_engine_overload.py`

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.single_engine_overload import SingleEngineOverloadRule


def _site(site_id, name, engine_id): return {"id": site_id, "name": name, "scanEngineId": engine_id}


def test_pass_when_each_engine_serves_one_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 200)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}, {"id": 200, "name": "E2"}])
    fake_snapshot.set_site_asset_count(1, 5000)
    fake_snapshot.set_site_asset_count(2, 5000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_finding_when_one_engine_exceeds_threshold_across_sites(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 4000)
    fake_snapshot.set_site_asset_count(2, 3000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500,
                                        {"asset_count_threshold": 5000})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["total_assets"] == 7000
    assert sorted(r.findings[0].details["sites"]) == [1, 2]


def test_threshold_default_5000(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100), _site(2, "B", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 2000)
    fake_snapshot.set_site_asset_count(2, 2000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500, {})
    # 4000 < default 5000 → no finding
    assert r.status == "pass"


def test_engine_with_one_site_never_flagged(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A", 100)])
    fake_snapshot.set_scan_engines([{"id": 100, "name": "E1"}])
    fake_snapshot.set_site_asset_count(1, 100000)
    r = SingleEngineOverloadRule().run(fake_snapshot, "warn", False, 500,
                                        {"asset_count_threshold": 100})
    assert r.status == "pass"
```

- [ ] **Step 2: Fail; Step 3: Implement**

```python
from __future__ import annotations

from collections import defaultdict

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_DEFAULT_THRESHOLD = 5000


@register
class SingleEngineOverloadRule:
    rule_id = "single_engine_overload"
    rule_name = "Single Scan Engine Overloaded"
    description = (
        "Scan engines bound to multiple sites whose combined asset count exceeds "
        "the configured threshold. Indicates missing engine pool / capacity risk."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/security-console-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        threshold = int(rule_config.get("asset_count_threshold", _DEFAULT_THRESHOLD))
        engines_by_id = {e["id"]: e for e in snapshot.scan_engines()}
        sites_by_engine: dict[int, list[int]] = defaultdict(list)
        for site in snapshot.sites():
            engine_id = site.get("scanEngineId")
            if engine_id is not None:
                sites_by_engine[engine_id].append(site["id"])

        findings: list[Finding] = []
        engines_flagged = 0
        for engine_id, site_ids in sites_by_engine.items():
            if len(site_ids) < 2:
                continue
            total = sum(snapshot.site_asset_count(sid) for sid in site_ids)
            if total > threshold:
                engine_name = engines_by_id.get(engine_id, {}).get("name", f"id={engine_id}")
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Scan engine '{engine_name}' is bound to {len(site_ids)} sites "
                        f"totalling {total} assets (threshold {threshold})"
                    ),
                    details={"engine_id": engine_id, "sites": site_ids, "total_assets": total,
                             "threshold": threshold},
                ))
                engines_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"engines_examined": len(sites_by_engine), "engines_flagged": engines_flagged},
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Tests pass (4 new); Step 5: full suite 103; Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/single_engine_overload.py tests/audit/rules/test_single_engine_overload.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule single_engine_overload"
```

---

## Task 11: Rule -- `discovery_template_on_prod_site` (cheap, heuristic)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/discovery_template_on_prod_site.py`
- Create: `tests/audit/rules/test_discovery_template_on_prod_site.py`

- [ ] **Step 1: Tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.discovery_template_on_prod_site import (
    DiscoveryTemplateOnProdSiteRule,
)


def _site(site_id, name, tpl_id, importance="normal"):
    return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}, "importance": importance}


def test_pass_when_vuln_template_assigned(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Prod", "tpl-vuln", importance="high")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_discovery_template_on_high_importance(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Prod", "tpl-disc", importance="high")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_skip_low_importance_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Junk", "tpl-disc", importance="very_low")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 100)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_skip_small_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "Tiny", "tpl-disc", importance="normal")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_asset_count(1, 5)
    r = DiscoveryTemplateOnProdSiteRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
```

- [ ] **Step 2: Fail; Step 3: Implement**

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding


_PROD_IMPORTANCE = {"normal", "high", "very_high"}
_MIN_ASSETS = 10


@register
class DiscoveryTemplateOnProdSiteRule:
    rule_id = "discovery_template_on_prod_site"
    rule_name = "Discovery Template on Production Site"
    description = (
        "Sites with normal+ importance and >10 assets that use a Discovery-only template. "
        "Heuristic: the site looks like it should be running vulnerability assessment but isn't."
    )
    default_severity = "warn"
    expensive = False
    sources = ["https://docs.rapid7.com/insightvm/scan-template-best-practices/"]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        for site in snapshot.sites():
            site_id = site.get("id")
            importance = site.get("importance", "normal")
            if importance not in _PROD_IMPORTANCE:
                continue
            if snapshot.site_asset_count(site_id) <= _MIN_ASSETS:
                continue
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if (tpl.get("vulnerabilityChecks") or {}).get("enabled"):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Site '{site.get('name', site_id)}' (importance: {importance}, "
                    f"{snapshot.site_asset_count(site_id)} assets) uses Discovery-only template "
                    f"'{tpl.get('name', tpl_id)}' -- no vulnerabilities will be reported"
                ),
                details={"site_id": site_id, "template_id": tpl_id,
                         "importance": importance,
                         "asset_count": snapshot.site_asset_count(site_id)},
            ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_flagged": len(findings)},
            sources=list(self.sources),
        )
```

- [ ] **Step 4-6: Tests pass (4 new) → 107 total. Commit:**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/discovery_template_on_prod_site.py tests/audit/rules/test_discovery_template_on_prod_site.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule discovery_template_on_prod_site"
```

---

## Task 12: Rule -- `overlapping_scan_windows` (expensive)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/overlapping_scan_windows.py`
- Create: `tests/audit/rules/test_overlapping_scan_windows.py`

This rule has the most logic. Splitting helpers for time-window expansion + scope intersection keeps the rule readable.

- [ ] **Step 1: Tests**

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit.rules.overlapping_scan_windows import (
    OverlappingScanWindowsRule,
)


def _iso(dt: datetime) -> str: return dt.isoformat().replace("+00:00", "Z")


def test_pass_when_schedules_dont_overlap_in_time(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(hours=2)),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_time_and_scope_overlap(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base),
                                          "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base + timedelta(minutes=30)),
                                          "duration": "PT1H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.5"}])  # in 10.0.0.0/24
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert "10.0.0" in r.findings[0].message


def test_no_overlap_when_scope_disjoint(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.1.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_schedule_inside_blackout(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([{"id": 99, "enabled": True, "name": "Maint",
                                   "start": _iso(base - timedelta(minutes=30)),
                                   "duration": "PT3H"}])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert any("Maint" in f.message for f in r.findings)


def test_disabled_schedule_skipped(fake_snapshot):
    base = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    fake_snapshot.set_sites([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    fake_snapshot.set_site_schedules(1, [{"id": 10, "enabled": False,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_schedules(2, [{"id": 20, "enabled": True,
                                          "start": _iso(base), "duration": "PT2H", "repeat": None}])
    fake_snapshot.set_site_included_targets(1, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_site_included_targets(2, [{"address": "10.0.0.0/24"}])
    fake_snapshot.set_blackouts([])
    r = OverlappingScanWindowsRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
```

- [ ] **Step 2: Fail; Step 3: Implement**

```python
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from itertools import combinations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.checks import Finding

# ISO 8601 duration parser, minimal: PT[nH][nM][nS]
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_duration(value: str | None) -> timedelta:
    if not value:
        return timedelta(0)
    m = _DURATION_RE.match(value)
    if not m:
        return timedelta(0)
    h, mn, s = (int(x) if x else 0 for x in m.groups())
    return timedelta(hours=h, minutes=mn, seconds=s)


def _windows_intersect(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end


def _parse_scope(targets: list[dict]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for t in targets:
        addr = t.get("address") if isinstance(t, dict) else t
        if not addr:
            continue
        try:
            out.append(ipaddress.ip_network(addr, strict=False))
        except ValueError:
            continue
    return out


def _scopes_intersect(a, b) -> bool:
    for na in a:
        for nb in b:
            if na.overlaps(nb):
                return True
    return False


@register
class OverlappingScanWindowsRule:
    rule_id = "overlapping_scan_windows"
    rule_name = "Overlapping Scan Windows or Blackout Conflicts"
    description = (
        "Scheduled scans whose time windows overlap and target the same IP scope, "
        "or scans scheduled inside an enabled blackout."
    )
    default_severity = "warn"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/scan-blackouts",
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        sites = snapshot.sites()
        sampled = False
        sample_info = None
        if not full_scan and len(sites) > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {len(snapshot.sites())} sites"

        # Gather (site_id, site_name, schedule, window_start, window_end, scope)
        windows = []
        for site in sites:
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            scope = _parse_scope(snapshot.site_included_targets(sid))
            for sch in snapshot.site_schedules(sid):
                if not sch.get("enabled", False):
                    continue
                start = _parse_iso(sch.get("start"))
                if start is None:
                    continue
                duration = _parse_duration(sch.get("duration"))
                end = start + duration if duration > timedelta(0) else start + timedelta(hours=1)
                windows.append((sid, name, sch, start, end, scope))

        findings: list[Finding] = []

        # Check pairwise overlaps
        for (sid_a, name_a, sch_a, s_a, e_a, scope_a), (sid_b, name_b, sch_b, s_b, e_b, scope_b) in combinations(windows, 2):
            if sid_a == sid_b:
                continue
            if not _windows_intersect(s_a, e_a, s_b, e_b):
                continue
            if not _scopes_intersect(scope_a, scope_b):
                continue
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Sites '{name_a}' and '{name_b}' have schedules that overlap "
                    f"on {s_a.date().isoformat()} {s_a.strftime('%H:%M')} and target overlapping IP scope"
                ),
                details={
                    "site_a": sid_a, "site_b": sid_b,
                    "schedule_a": sch_a.get("id"), "schedule_b": sch_b.get("id"),
                    "overlap_start": max(s_a, s_b).isoformat(),
                    "overlap_end": min(e_a, e_b).isoformat(),
                },
            ))

        # Check blackout overlap
        for blackout in snapshot.blackouts():
            if not blackout.get("enabled", False):
                continue
            b_start = _parse_iso(blackout.get("start"))
            if b_start is None:
                continue
            b_end = b_start + _parse_duration(blackout.get("duration"))
            for sid, name, sch, s, e, _scope in windows:
                if _windows_intersect(s, e, b_start, b_end):
                    findings.append(Finding(
                        severity=severity,
                        message=(
                            f"Site '{name}' schedule overlaps blackout "
                            f"'{blackout.get('name', f'id={blackout.get(\"id\")}')}' on "
                            f"{s.date().isoformat()}"
                        ),
                        details={
                            "site_id": sid, "schedule_id": sch.get("id"),
                            "blackout_id": blackout.get("id"),
                        },
                    ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"windows_examined": len(windows), "findings_count": len(findings)},
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
```

- [ ] **Step 4-6: 5 new tests pass → 112 total. Commit:**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/overlapping_scan_windows.py tests/audit/rules/test_overlapping_scan_windows.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule overlapping_scan_windows"
```

---

## Task 13: Rule -- `credential_failure_in_recent_scans` (expensive)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/credential_failure_in_recent_scans.py`
- Create: `tests/audit/rules/test_credential_failure_in_recent_scans.py`

The v3 API surface for credential status is partial. The rule reads what's exposed on `/api/3/scans/{scan_id}` results (a `messages` field where credential statuses appear) and degrades to an info-level diagnostic when data isn't available.

- [ ] **Step 1: Tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.credential_failure_in_recent_scans import (
    CredentialFailureInRecentScansRule,
)


def test_pass_when_no_recent_credential_failures(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished", "messages": ["Credential Success on 10.0.0.5"]},
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_recent_scan_shows_credential_failure(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished",
         "messages": ["Credential Failure on 10.0.0.7", "Credential Success on 10.0.0.5"]},
        {"id": 99, "status": "finished",
         "messages": ["No Credentials Used on 10.0.0.7"]},
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_skip_sites_with_no_credentials(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "NoAuth"}])
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    # Rule 2 covers the no-creds case; this rule shouldn't flag.
    assert r.status == "pass"


def test_diagnostic_when_scan_messages_field_missing(fake_snapshot):
    fake_snapshot.set_sites([{"id": 1, "name": "Prod"}])
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_recent_scans(1, [
        {"id": 100, "status": "finished"},  # no `messages` field
    ])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 500, {})
    # Info-level diagnostic; no warn-level finding from this site.
    assert any(f.severity == "info" for f in r.findings)
    assert not any(f.severity == "warn" for f in r.findings)


def test_sampling_enforced(fake_snapshot):
    fake_snapshot.set_sites([{"id": i, "name": f"S{i}"} for i in range(10)])
    for i in range(10):
        fake_snapshot.set_site_credentials(i, [{"id": 1, "enabled": True}])
        fake_snapshot.set_site_recent_scans(i, [{"id": 100, "status": "finished",
                                                  "messages": ["Credential Success"]}])
    fake_snapshot.set_shared_credentials([])
    r = CredentialFailureInRecentScansRule().run(fake_snapshot, "warn", False, 3, {})
    assert r.sampled
    assert "checked 3" in r.sample_info
```

- [ ] **Step 2: Fail; Step 3: Implement**

```python
from __future__ import annotations

import re

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding

_FAIL_PATTERN = re.compile(
    r"(Credential Failure|Partial Credential Success|No Credentials Used|No Credentials Supplied)",
    re.IGNORECASE,
)


@register
class CredentialFailureInRecentScansRule:
    rule_id = "credential_failure_in_recent_scans"
    rule_name = "Credential Failure in Recent Scans"
    description = (
        "Sites that have credentials configured but whose recent scans report Credential "
        "Failure, Partial Credential Success, or No Credentials Used for some assets."
    )
    default_severity = "warn"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/configuring-site-specific-scan-credentials/",
        "https://docs.rapid7.com/insightvm/scan-template-best-practices/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        sites = snapshot.sites()
        sampled = False
        sample_info = None
        total_sites = len(sites)
        if not full_scan and total_sites > sample_size:
            sites = sites[:sample_size]
            sampled = True
            sample_info = f"checked {len(sites)} of {total_sites} sites"

        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        diagnostic_emitted = False

        for site in sites:
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            if not _site_has_credentials(snapshot, sid):
                continue
            sites_examined += 1
            scans = snapshot.site_recent_scans(sid)
            failure_count = 0
            messages_present = False
            for scan in scans:
                msgs = scan.get("messages")
                if msgs is None:
                    continue
                messages_present = True
                for m in msgs:
                    if _FAIL_PATTERN.search(m or ""):
                        failure_count += 1
                        break
            if not messages_present:
                if not diagnostic_emitted:
                    findings.append(Finding(
                        severity="info",
                        message=(
                            "Recent-scan results lack credential-status messages "
                            "(enable Scanning Diagnostics in the scan template for richer signal)."
                        ),
                        details={"site_id": sid},
                    ))
                    diagnostic_emitted = True
                continue
            if failure_count > 0:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' had {failure_count}/{len(scans)} recent scans with "
                        f"credential failures or partial success"
                    ),
                    details={"site_id": sid, "failed_scans": failure_count, "total_scans": len(scans)},
                ))
                sites_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
```

- [ ] **Step 4-6: 5 new tests pass → 117 total. Commit:**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/credential_failure_in_recent_scans.py tests/audit/rules/test_credential_failure_in_recent_scans.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule credential_failure_in_recent_scans"
```

---

## Task 14: Rule -- `agent_unauth_collision` (expensive, headline rule)

**Files:**
- Create: `rapid7_healthcheck/audit/rules/agent_unauth_collision.py`
- Create: `tests/audit/rules/test_agent_unauth_collision.py`

- [ ] **Step 1: Tests**

```python
from __future__ import annotations

from rapid7_healthcheck.audit.rules.agent_unauth_collision import (
    AgentUnauthCollisionRule,
)


def _site(site_id, tpl_id, name="S"):
    return {"id": site_id, "name": name, "scanTemplate": {"id": tpl_id}}


def test_pass_when_site_has_credentials(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [{"id": 5, "enabled": True}])
    fake_snapshot.set_shared_credentials([])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_pass_when_template_has_no_vuln_checks(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-disc")])
    fake_snapshot.set_scan_template("tpl-disc", {"id": "tpl-disc", "name": "Discovery",
                                                  "vulnerabilityChecks": {"enabled": False}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_fail_when_unauth_site_has_agent_assets(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdLinux")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}, {"id": 101}, {"id": 102}], total=3)
    fake_snapshot.set_asset_history(100, [{"type": "AGENT-IMPORT", "date": "..."}])
    fake_snapshot.set_asset_history(101, [{"type": "AGENT-IMPORT", "date": "..."}])
    fake_snapshot.set_asset_history(102, [{"type": "SCAN", "date": "..."}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    f = r.findings[0]
    assert "ProdLinux" in f.message
    assert f.details["agent_count"] == 2


def test_pass_when_no_agent_assets(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}], total=1)
    fake_snapshot.set_asset_history(100, [{"type": "SCAN"}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"


def test_sampling_recorded(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "tpl-vuln")])
    fake_snapshot.set_scan_template("tpl-vuln", {"id": "tpl-vuln", "name": "Vuln",
                                                  "vulnerabilityChecks": {"enabled": True}})
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_asset_sample(1, [{"id": 100}], total=4200)
    fake_snapshot.set_asset_history(100, [{"type": "AGENT-IMPORT"}])
    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.sampled
    assert "of 4200" in (r.sample_info or "")
```

- [ ] **Step 2: Fail; Step 3: Implement**

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding


def _has_agent_history(history: list[dict]) -> bool:
    return any((h.get("type") or "").upper() == "AGENT-IMPORT" for h in history)


@register
class AgentUnauthCollisionRule:
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that already have "
        "the Insight Agent installed. The agent produces strictly richer authenticated data; "
        "redundant unauth scans add load, cause asset-correlation drift, and (prior to console "
        "release 6.6.229) could degrade results."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/release-notes/insightvm/20231129/",
        "https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/",
        "https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        any_sampled = False
        site_samples: list[tuple[int, int]] = []

        for site in snapshot.sites():
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            tpl_id = (site.get("scanTemplate") or {}).get("id")
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not (tpl.get("vulnerabilityChecks") or {}).get("enabled"):
                continue
            if _site_has_credentials(snapshot, sid):
                continue

            sites_examined += 1
            assets, total = snapshot.asset_sample(sid)
            if total > len(assets):
                any_sampled = True
            site_samples.append((len(assets), total))

            agent_count = 0
            for asset in assets:
                if _has_agent_history(snapshot.asset_history(asset["id"])):
                    agent_count += 1

            if agent_count > 0:
                pct = (agent_count / max(len(assets), 1)) * 100
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' runs unauthenticated vuln scans, but {agent_count}/"
                        f"{len(assets)} sampled assets are Insight Agent-managed ({pct:.0f}%)"
                    ),
                    details={
                        "site_id": sid, "scan_template_id": tpl_id,
                        "agent_count": agent_count,
                        "sample_size": len(assets), "total_assets": total,
                    },
                ))
                sites_flagged += 1

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        sample_info = None
        if any_sampled:
            total_assets_examined = sum(s for s, _ in site_samples)
            total_assets = sum(t for _, t in site_samples)
            sample_info = (
                f"checked {total_assets_examined} of {total_assets} assets "
                f"across {sites_examined} sites"
            )

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={"sites_examined": sites_examined, "sites_flagged": sites_flagged},
            sampled=any_sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
```

- [ ] **Step 4-6: 5 new tests pass → 122 total. Commit:**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/audit/rules/agent_unauth_collision.py tests/audit/rules/test_agent_unauth_collision.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat(audit): add rule agent_unauth_collision"
```

---

## Task 15: `ConfigurationAuditCheck` integration tests

**Files:**
- Create: `tests/audit/test_audit_check.py`

This task verifies the registry, per-rule isolation, status rollup, and skipped-rule handling. With all 8 rules now registered, we can exercise the full check.

- [ ] **Step 1: Tests**

```python
from __future__ import annotations

from dataclasses import replace

import pytest

# Importing the rules package side-effect-registers all 8 rules.
from rapid7_healthcheck.audit import _RULE_REGISTRY, ConfigurationAuditCheck
import rapid7_healthcheck.audit.rules.agent_unauth_collision  # noqa: F401
import rapid7_healthcheck.audit.rules.site_vuln_template_no_creds  # noqa: F401
import rapid7_healthcheck.audit.rules.credential_failure_in_recent_scans  # noqa: F401
import rapid7_healthcheck.audit.rules.overlapping_scan_windows  # noqa: F401
import rapid7_healthcheck.audit.rules.single_engine_overload  # noqa: F401
import rapid7_healthcheck.audit.rules.discovery_template_on_prod_site  # noqa: F401
import rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template  # noqa: F401
import rapid7_healthcheck.audit.rules.store_invulnerable_results  # noqa: F401


def test_all_8_rules_registered():
    expected = {
        "agent_unauth_collision", "site_vuln_template_no_creds",
        "credential_failure_in_recent_scans", "overlapping_scan_windows",
        "single_engine_overload", "discovery_template_on_prod_site",
        "policy_and_vuln_in_same_template", "store_invulnerable_results",
    }
    assert set(_RULE_REGISTRY.keys()) == expected


def test_audit_skipped_when_audit_enabled_false(app_config, monkeypatch):
    cfg = replace(app_config, audit=replace(app_config.audit, enabled=False))
    # client unused since audit short-circuits
    result = ConfigurationAuditCheck().run(client=object(), config=cfg)
    assert result.status == "skipped"
    assert result.rule_results == []


def test_audit_skips_disabled_rules(app_config, fake_client, monkeypatch):
    # Disable all rules; provide stub data so any rule that runs would error.
    new_rules = {
        rid: replace(rc, enabled=False)
        for rid, rc in app_config.audit.rules.items()
    }
    cfg = replace(app_config, audit=replace(app_config.audit, rules=new_rules))
    # Provide minimal data so EnvSnapshot construction succeeds.
    fake_client.set_paginate("/api/3/sites", [])
    result = ConfigurationAuditCheck().run(fake_client, cfg)
    assert result.status == "pass"  # all skipped → no warn/fail
    assert all(rr.status == "skipped" for rr in result.rule_results)


def test_one_rule_raising_does_not_break_others(app_config, fake_client, monkeypatch):
    fake_client.set_paginate("/api/3/sites", [])  # zero sites
    # Force one rule to raise by monkeypatching its run method.
    from rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template import (
        PolicyAndVulnInSameTemplateRule,
    )
    def boom(self, *args, **kw): raise RuntimeError("simulated rule failure")
    monkeypatch.setattr(PolicyAndVulnInSameTemplateRule, "run", boom)
    fake_client.set_get("/api/3/scan_engines", {"resources": []})
    fake_client.set_get("/api/3/shared_credentials", {"resources": []})
    fake_client.set_get("/api/3/blackouts", {"resources": []})

    result = ConfigurationAuditCheck().run(fake_client, app_config)
    error_rules = [rr for rr in result.rule_results if rr.status == "error"]
    pass_rules = [rr for rr in result.rule_results if rr.status == "pass"]
    assert len(error_rules) == 1
    assert error_rules[0].rule_id == "policy_and_vuln_in_same_template"
    assert "simulated" in (error_rules[0].error or "")
    # Other rules (with empty data) all pass
    assert len(pass_rules) >= 1
```

- [ ] **Step 2-5: Run, confirm 4 new tests → 126 total**

Run: `.venv/Scripts/python.exe -m pytest tests/audit/test_audit_check.py -v`
Run: `.venv/Scripts/python.exe -m pytest -q`

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add tests/audit/test_audit_check.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "test(audit): integration tests for ConfigurationAuditCheck"
```

---

## Task 16: Wire into orchestrator + end-to-end test

**Files:**
- Modify: `rapid7_healthcheck/__main__.py`
- Modify: `tests/test_main.py`

- [ ] **Step 1: Add the audit check to the orchestrator registry**

In `rapid7_healthcheck/__main__.py`, add the import:

```python
from rapid7_healthcheck.audit import ConfigurationAuditCheck
# Side-effect imports: register all 8 rules.
import rapid7_healthcheck.audit.rules.agent_unauth_collision  # noqa: F401
import rapid7_healthcheck.audit.rules.site_vuln_template_no_creds  # noqa: F401
import rapid7_healthcheck.audit.rules.credential_failure_in_recent_scans  # noqa: F401
import rapid7_healthcheck.audit.rules.overlapping_scan_windows  # noqa: F401
import rapid7_healthcheck.audit.rules.single_engine_overload  # noqa: F401
import rapid7_healthcheck.audit.rules.discovery_template_on_prod_site  # noqa: F401
import rapid7_healthcheck.audit.rules.policy_and_vuln_in_same_template  # noqa: F401
import rapid7_healthcheck.audit.rules.store_invulnerable_results  # noqa: F401
```

Extend `_REGISTRY`:

```python
_REGISTRY: dict[str, type[Check]] = {
    "scan_engines": ScanEnginesCheck,
    "scan_activity": ScanActivityCheck,
    "asset_coverage": AssetCoverageCheck,
    "data_quality": DataQualityCheck,
    "configuration_audit": ConfigurationAuditCheck,
}
```

- [ ] **Step 2: Update existing test config helper**

In `tests/test_main.py`, the `_write_config` helper produces a YAML config. Append the audit block + the new `checks.configuration_audit: false` line. Modify `_write_config` to:

```python
def _write_config(tmp_path: Path, base_url: str = "https://us.api.insight.rapid7.com") -> Path:
    body = textwrap.dedent(f"""
        rapid7:
          base_url: {base_url}
          verify_tls: true
          request_timeout_seconds: 30
          max_retries: 3
        report:
          output_dir: {tmp_path / "reports"}
          filename_pattern: "rapid7-health-{{timestamp}}.html"
          title: "T"
        thresholds:
          scan_engines:
            last_contact_warn_hours: 2
            last_contact_fail_hours: 24
          scan_activity:
            recent_window_days: 7
            stuck_scan_hours: 24
            site_no_scan_days: 14
          asset_coverage:
            stale_asset_days: 30
            flag_unscanned_assets: true
          data_quality:
            flag_missing_os: true
            flag_empty_sites: true
        checks:
          scan_engines: false
          scan_activity: false
          asset_coverage: false
          data_quality: false
          configuration_audit: false
    """).strip()
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p
```

The audit block is omitted entirely → `audit.enabled` defaults to False per the loader's behaviour. All existing tests stay green.

- [ ] **Step 3: Add an end-to-end audit test**

Append to `tests/test_main.py`:

```python
def test_run_with_audit_enabled_writes_audit_report(tmp_path, monkeypatch):
    """End-to-end: enable audit + one rule, simulate a passing run, see the audit section appear."""
    body = textwrap.dedent(f"""
        rapid7:
          base_url: https://us.api.insight.rapid7.com
          verify_tls: true
          request_timeout_seconds: 30
          max_retries: 3
        report:
          output_dir: {tmp_path / "reports"}
          filename_pattern: "rapid7-health-{{timestamp}}.html"
          title: "T"
        thresholds:
          scan_engines:
            last_contact_warn_hours: 2
            last_contact_fail_hours: 24
          scan_activity:
            recent_window_days: 7
            stuck_scan_hours: 24
            site_no_scan_days: 14
          asset_coverage:
            stale_asset_days: 30
            flag_unscanned_assets: true
          data_quality:
            flag_missing_os: true
            flag_empty_sites: true
        checks:
          scan_engines: false
          scan_activity: false
          asset_coverage: false
          data_quality: false
          configuration_audit: true
        audit:
          enabled: true
          full_scan: false
          sample_size: 500
          rules:
            agent_unauth_collision:
              enabled: false
              severity: fail
            site_vuln_template_no_creds:
              enabled: true
              severity: fail
            credential_failure_in_recent_scans:
              enabled: false
              severity: warn
            overlapping_scan_windows:
              enabled: false
              severity: warn
            single_engine_overload:
              enabled: false
              severity: warn
            discovery_template_on_prod_site:
              enabled: false
              severity: warn
            policy_and_vuln_in_same_template:
              enabled: false
              severity: warn
            store_invulnerable_results:
              enabled: false
              severity: info
    """).strip()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("R7_API_KEY", "k")

    out_path = tmp_path / "out.html"
    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        instance = MockClient.return_value
        instance.connect.return_value = None
        # Empty environment: no sites → all rules pass.
        instance.paginate.side_effect = lambda path, **kw: iter([])
        instance.get.side_effect = lambda path, **kw: {"resources": [], "page": {"totalResources": 0}}
        code = run(["--config", str(cfg), "--output", str(out_path)])

    assert code == EXIT_HEALTHY
    html = out_path.read_text(encoding="utf-8")
    assert "Configuration Audit" in html
    # Rule ID should appear (skipped rules listed too)
    assert "Vulnerability Template Without Credentials" in html
```

- [ ] **Step 4: Run new tests, expect pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_main.py -v`
Expected: 11 existing + 1 new = 12 passed.

- [ ] **Step 5: Run full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 126 + 1 = 127 passed.

- [ ] **Step 6: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add rapid7_healthcheck/__main__.py tests/test_main.py
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "feat: wire ConfigurationAuditCheck into the orchestrator registry"
```

---

## Task 17: README + smoke verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the full suite for sanity**

Run: `.venv/Scripts/python.exe -m pytest -v`
Expected: 127 passed.

- [ ] **Step 2: Smoke-test CLI without API key**

Run: `.venv/Scripts/python.exe -m rapid7_healthcheck --config config.example.yaml`
Expected: exit code 3, stderr contains the missing-API-key message. No report written.

- [ ] **Step 3: Update README**

Open `README.md`. Add a new section after `## Exit codes` and before `## Scheduling`:

```markdown
## Configuration Audit

In addition to the four operational health checks, the tool runs a **Configuration Audit**: eight best-practice rules sourced from official Rapid7 documentation, each grounded in a public Rapid7 source URL.

Rules:

| Rule | Default severity | Source |
|------|-----------------:|--------|
| Insight Agent asset scanned without authentication | fail | docs.rapid7.com Console Best Practices, 6.6.229 release notes |
| Vulnerability template without credentials | fail | Scan Template Best Practices, Configuring Scan Credentials |
| Credential failure in recent scans | warn | Configuring Site-Specific Scan Credentials |
| Overlapping scan windows or blackout conflicts | warn | Scan Blackouts, Console Best Practices |
| Single scan engine overloaded | warn | Console Best Practices |
| Discovery template on production site | warn (heuristic) | Scan Template Best Practices |
| Policy and Vulnerability in same template | warn | Scan Template Best Practices |
| Store invulnerable results enabled | info | Scan Template Best Practices |

Per-rule severity and enable/disable live in the `audit:` block of `config.yaml`. Each finding in the report links back to the Rapid7 source documenting the rule.

**Sampling.** Some rules need to inspect every asset (or every schedule). To keep API load predictable on large environments, expensive rules sample up to `audit.sample_size` entities (default 500) per rule. The report explicitly notes which rules used sampling and how many entities were checked vs total. Set `audit.full_scan: true` to enumerate everything (slower, higher API load).

See `config.example.yaml` for the full audit configuration block.
```

Update the "What this tool does NOT do" section to reflect the new capability -- remove any wording that suggests configuration auditing is out of scope (none should exist; the existing wording about license/build version stays).

- [ ] **Step 4: Run final pytest + git status**

Run: `.venv/Scripts/python.exe -m pytest -q && git status`
Expected: 127 passed, working tree clean except for the README change.

- [ ] **Step 5: Commit**

```bash
git -c user.email=Philipp@bchwld.de -c user.name=Philipp add README.md
git -c user.email=Philipp@bchwld.de -c user.name=Philipp commit -m "docs: document Configuration Audit category and 8 rules"
```

- [ ] **Step 6: Final smoke test**

Run: `.venv/Scripts/python.exe -m rapid7_healthcheck --config config.example.yaml`
Expected: exit 3 (no API key set in env). Verifies the package still loads cleanly with the audit subsystem in place.

---

## Self-review

**1. Spec coverage:**

| Spec section | Implementing task |
|---|---|
| §3 inputs/outputs (audit:` block, `checks.configuration_audit`) | Task 1 |
| §4 module boundaries | Task 2 (audit primitives), Task 4 (snapshot), Tasks 7-14 (rules) |
| §5 config schema + validation | Task 1 |
| §6 EnvSnapshot | Task 4 |
| §7 Rule contract + ConfigurationAuditCheck | Task 2 (skeleton), Task 15 (integration tests) |
| §8 Report rendering with `rule_results` | Tasks 3 + 6 |
| §9.1 agent_unauth_collision | Task 14 |
| §9.2 site_vuln_template_no_creds | Task 7 |
| §9.3 credential_failure_in_recent_scans | Task 13 |
| §9.4 overlapping_scan_windows | Task 12 |
| §9.5 single_engine_overload | Task 10 |
| §9.6 discovery_template_on_prod_site | Task 11 |
| §9.7 policy_and_vuln_in_same_template | Task 8 |
| §9.8 store_invulnerable_results | Task 9 |
| §10 errors (per-rule isolation) | Task 2 (logic), Task 15 (test) |
| §11 logging | Task 2 (logger setup, info-level start/end) |
| §12 tests | Tasks 4, 5, 6, 7-14, 15, 16 |
| §13 project layout | Tasks 1-16 collectively |
| §14 dependencies (none new) | confirmed in Task 1 |
| §15 README | Task 17 |

**2. Placeholder scan:** No "TBD", no "implement later", no `Similar to Task N`, no "add appropriate error handling". Each rule task ships full code. The `tests/audit/test_snapshot.py` `_FakeClient` and `tests/audit/conftest.py` `FakeSnapshot` are different test doubles by design (one tests `EnvSnapshot` against a fake transport; the other tests rules against a fake snapshot).

**3. Type consistency:**
- `RuleResult` fields used in Task 2 match those used in Tasks 6, 15, 17 (renderer, integration test).
- `Severity` and `Status` literal aliases come from `rapid7_healthcheck.checks` and are imported wherever used.
- `_site_has_credentials` is defined in Task 7 and re-imported in Tasks 13, 14 (not redefined).
- `EnvSnapshot` public methods listed in Task 4 match the ones called in Tasks 7-14 (cross-checked: `sites`, `scan_template`, `site_credentials`, `shared_credentials`, `site_asset_count`, `site_recent_scans`, `site_schedules`, `site_included_targets`, `blackouts`, `scan_engines`, `asset_sample`, `asset_history`).
- `RuleConfig.knobs` is a dict in Task 1; rules in Tasks 10 (knob: `asset_count_threshold`) read from it correctly.

No issues found.
