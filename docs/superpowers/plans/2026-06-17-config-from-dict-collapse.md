# Config Validator Collapse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every config block through the introspective `_from_dict` validator so the dataclass is the single source of truth for schema + type, with per-block value rules (positive, non-negative, range, enum, cross-field, nullable) held in small composable `post_validate` hooks.

**Architecture:** Split `_check_scalar` into type-only checking; move all value-range semantics into `post_validate(obj) -> obj` hooks that `_from_dict` invokes after the generic schema+type pass. Migrate the five hand-written per-block builders (`audit`, `user_audit`, `template_audit`, `cloud_integration`, `report`) plus `rapid7` to the `_from_dict` + `post_validate` seam, and delete the two pop-validate-reattach workarounds in `_build_thresholds` that exist only because `_check_scalar` currently couples type and value.

**Tech Stack:** Python 3.11/3.12, dataclasses, `typing.get_type_hints`, pytest. No new dependencies.

## Global Constraints

- **Read-only contract (CLAUDE.md):** `config.py` feeds the HTTP client. This refactor adds NO HTTP calls and NO new verbs. After every task, the pre-commit grep `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` must return zero matches (it will — nothing here touches HTTP).
- **Behavior-preserving:** This is a pure refactor. Every config that validates today must still validate; every config rejected today must still be rejected, with a message that still satisfies the test suite's substring `match=` assertions. NO loosening or tightening of any validation rule. Specifically:
  - `rapid7.max_retries` and `cloud_integration.max_retries`: 0 is REJECTED today (positive-int). Keep rejecting 0.
  - `rapid7.request_timeout_seconds`, `cloud_integration.timeout_seconds`, `*.sample_size`, `agents_timeout_seconds`: positive-int (reject 0).
  - `rapid7.parallel_pages`, `cloud_integration.parallel_pages`: range [1,16].
  - `rapid7.page_size`: range [1,500].
  - `thresholds.asset_coverage.dead_groups_fallback_cap`, `thresholds.data_quality.duplicate_detection_max_assets`: non-negative (0 ALLOWED).
  - `report.delta_max_age_days`: non-negative int OR None (both allowed).
- **Error-wording fidelity:** Tests use substring `match=` (not byte-exact). The hand-written-only phrasing `"expected positive int"` is asserted nowhere. `_check_scalar`'s phrasing (`"expected int, got <type>"`, `"must be a positive integer, got N"`) already satisfies the matchers. Accept the wording shift to `_check_scalar`/`_from_dict` phrasing where it occurs; the test suite is the proof. Do NOT add message-override params to preserve dead strings.
- **Minimum Python 3.11.** No 3.12-only syntax.
- **Tests:** `pytest -v` must stay green (931 tests at plan time). Run the full `tests/test_config.py` after every task; run the whole suite before the final commit.

---

## File Structure

- **Modify:** `src/rapid7_healthcheck/config.py` — the only production file touched. All changes are internal to it; `load_config` and `AppConfig` public surface are unchanged.
- **Modify:** `tests/test_config.py` — add characterization tests up front (Task 1), then per-task assertions as builders migrate.

No new files. No public-interface changes — `load_config(path) -> AppConfig` and every dataclass keep their exact shape, so `__main__.py` and all callers are untouched.

---

## Task 1: Characterization safety net

Pin the current observable validation behavior BEFORE any refactor, so every later task proves behavior-preservation. These tests must pass against the CURRENT code unchanged.

**Files:**
- Test: `tests/test_config.py` (append a new `class TestConfigCharacterization` or module-level tests)

**Interfaces:**
- Consumes: `rapid7_healthcheck.config.load_config`, `ConfigError`, and a minimal valid config dict fixture (reuse the existing `app_config`/valid-config fixture in `tests/test_config.py` — locate it first; do not invent a new one if one exists).
- Produces: a frozen record of which int values each field accepts/rejects. Later tasks must keep these green.

- [ ] **Step 1: Locate the existing valid-config fixture**

Read `tests/test_config.py` and find the helper that builds a minimal valid config (look for a `_valid_config()` / `valid_config` fixture / `app_config` fixture). Use it verbatim. If none exists, build one from `docs/examples/config.yaml`.

- [ ] **Step 2: Write characterization tests for the zero/negative int boundaries**

```python
import pytest
from rapid7_healthcheck.config import _build_app_config, ConfigError


def _cfg(overrides: dict) -> dict:
    """Deep-merge overrides onto a minimal valid root config dict.
    Reuse the file's existing valid-config builder; this is illustrative."""
    base = _valid_root_config()  # <- replace with the located fixture
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}
        else:
            base[k] = v
    return base


@pytest.mark.parametrize("value,ok", [(1, True), (3, True), (0, False), (-1, False)])
def test_char_rapid7_max_retries_boundary(value, ok):
    cfg = _cfg({"rapid7": {"max_retries": value}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="max_retries"):
            _build_app_config(cfg)


@pytest.mark.parametrize("value,ok", [(1, True), (0, False), (-1, False)])
def test_char_audit_sample_size_boundary(value, ok):
    cfg = _cfg({"audit": {"enabled": True, "full_scan": False, "sample_size": value, "agents_timeout_seconds": 180}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="sample_size"):
            _build_app_config(cfg)


@pytest.mark.parametrize("value,ok", [(0, True), (5, True), (-1, False)])
def test_char_dead_groups_fallback_cap_allows_zero(value, ok):
    cfg = _cfg({"thresholds": {"asset_coverage": {"dead_groups_fallback_cap": value}}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="dead_groups_fallback_cap"):
            _build_app_config(cfg)


@pytest.mark.parametrize("value,ok", [(0, True), (5, True), (-1, False)])
def test_char_duplicate_detection_max_assets_allows_zero(value, ok):
    cfg = _cfg({"thresholds": {"data_quality": {"duplicate_detection_max_assets": value}}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="duplicate_detection_max_assets"):
            _build_app_config(cfg)


@pytest.mark.parametrize("value,ok", [(0, True), (30, True), (None, True), (-1, False)])
def test_char_delta_max_age_days_allows_zero_and_none(value, ok):
    cfg = _cfg({"report": {"delta_max_age_days": value}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="delta_max_age_days"):
            _build_app_config(cfg)


@pytest.mark.parametrize("value,ok", [(1, True), (16, True), (0, False), (17, False)])
def test_char_rapid7_parallel_pages_range(value, ok):
    cfg = _cfg({"rapid7": {"parallel_pages": value}})
    if ok:
        _build_app_config(cfg)
    else:
        with pytest.raises(ConfigError, match="parallel_pages"):
            _build_app_config(cfg)


def test_char_cloud_integration_enabled_requires_base_url():
    cfg = _cfg({"cloud_integration": {"enabled": True, "base_url": ""}})
    with pytest.raises(ConfigError, match="base_url"):
        _build_app_config(cfg)


def test_char_bool_rejected_for_int_field():
    cfg = _cfg({"audit": {"enabled": True, "full_scan": False, "sample_size": True, "agents_timeout_seconds": 180}})
    with pytest.raises(ConfigError, match="sample_size"):
        _build_app_config(cfg)
```

- [ ] **Step 3: Run the characterization tests against CURRENT (unmodified) code**

Run: `pytest tests/test_config.py -k char -v`
Expected: ALL PASS. If any fail, the test encodes a wrong assumption about current behavior — fix the test to match reality (read the relevant builder), not the code. This is the baseline; it must be green before touching `config.py`.

- [ ] **Step 4: Commit the safety net**

```bash
git add tests/test_config.py
git commit -m "test(config): characterize int-boundary validation before _from_dict collapse"
```

---

## Task 2: Split `_check_scalar` into type-only; add `post_validate` to `_from_dict`

Decouple type checking from value checking. `_check_scalar` keeps its current signature and behavior for callers that want the positive-int rule, but gain a `value_check` opt-out so `_from_dict` can do type-only. Then `_from_dict` gains an optional `post_validate` hook.

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:269-294` (`_check_scalar`)
- Modify: `src/rapid7_healthcheck/config.py:329-351` (`_from_dict`)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `_check_scalar(field_name: str, value: Any, expected: type, path: str, *, positive_int: bool = True) -> None` — when `expected is int` and `positive_int=False`, only type (int-not-bool) is checked; the `<= 0` rule is skipped. Default `True` preserves every current caller's behavior verbatim.
  - `_from_dict(cls, data, path, *, post_validate: Callable[[Any], Any] | None = None) -> Any` — does schema + TYPE-only checks (calls `_check_scalar(..., positive_int=False)` for int fields), constructs the dataclass, then returns `post_validate(obj)` if given (which may raise `ConfigError` or return a possibly-`replace`d object), else the object.

- [ ] **Step 1: Write the failing test for `_check_scalar` type-only mode**

```python
from rapid7_healthcheck.config import _check_scalar, ConfigError


def test_check_scalar_positive_int_false_allows_zero():
    # type-only: 0 is a valid int, must NOT raise
    _check_scalar("x", 0, int, "p", positive_int=False)
    _check_scalar("x", -5, int, "p", positive_int=False)


def test_check_scalar_positive_int_false_still_rejects_bool_and_nonint():
    with pytest.raises(ConfigError, match="expected int, got bool"):
        _check_scalar("x", True, int, "p", positive_int=False)
    with pytest.raises(ConfigError, match="expected int, got str"):
        _check_scalar("x", "5", int, "p", positive_int=False)


def test_check_scalar_default_still_positive():
    # default positive_int=True preserves current behavior
    with pytest.raises(ConfigError, match="must be a positive integer"):
        _check_scalar("x", 0, int, "p")
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_config.py -k check_scalar -v`
Expected: FAIL — `_check_scalar() got an unexpected keyword argument 'positive_int'`.

- [ ] **Step 3: Implement the `_check_scalar` split**

Replace the int branch in `_check_scalar` (lines 271-279):

```python
def _check_scalar(field_name: str, value: Any, expected: type, path: str, *, positive_int: bool = True) -> None:
    # bool is a subclass of int, so handle it carefully.
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"{path}.{field_name}: expected int, got {type(value).__name__}"
            )
        if positive_int and value <= 0:
            raise ConfigError(
                f"{path}.{field_name}: must be a positive integer, got {value}"
            )
    elif expected is bool:
        if not isinstance(value, bool):
            raise ConfigError(
                f"{path}.{field_name}: expected bool, got {type(value).__name__}"
            )
    elif expected is str:
        if not isinstance(value, str):
            raise ConfigError(
                f"{path}.{field_name}: expected str, got {type(value).__name__}"
            )
    else:
        raise ConfigError(
            f"{path}.{field_name}: unsupported declared type {expected!r}"
        )
```

- [ ] **Step 4: Run to verify `_check_scalar` tests pass**

Run: `pytest tests/test_config.py -k check_scalar -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `_from_dict` post_validate + type-only**

```python
from dataclasses import dataclass, replace
from rapid7_healthcheck.config import _from_dict, ConfigError


@dataclass(frozen=True)
class _Sample:
    n: int
    name: str = "x"


def test_from_dict_is_type_only_allows_zero():
    # _from_dict must NOT enforce positive-int; that is post_validate's job
    obj = _from_dict(_Sample, {"n": 0}, "s")
    assert obj.n == 0


def test_from_dict_still_rejects_wrong_type():
    with pytest.raises(ConfigError, match="expected int, got str"):
        _from_dict(_Sample, {"n": "5"}, "s")


def test_from_dict_runs_post_validate():
    def pv(obj):
        if obj.n < 0:
            raise ConfigError("s.n: must be non-negative")
        return obj
    assert _from_dict(_Sample, {"n": 3}, "s", post_validate=pv).n == 3
    with pytest.raises(ConfigError, match="must be non-negative"):
        _from_dict(_Sample, {"n": -1}, "s", post_validate=pv)


def test_from_dict_post_validate_can_replace():
    def pv(obj):
        return replace(obj, name=obj.name.strip())
    assert _from_dict(_Sample, {"n": 1, "name": "  y  "}, "s", post_validate=pv).name == "y"
```

- [ ] **Step 6: Run to verify it fails**

Run: `pytest tests/test_config.py -k from_dict -v`
Expected: FAIL — `_from_dict()` has no `post_validate` kwarg; `test_from_dict_is_type_only_allows_zero` fails because current `_from_dict` rejects 0.

- [ ] **Step 7: Implement `_from_dict` type-only + post_validate**

Replace `_from_dict` (lines 329-351). Add `from typing import Callable` to the imports if not present.

```python
def _from_dict(cls: type, data: Any, path: str, *, post_validate=None) -> Any:
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected mapping, got {type(data).__name__}")
    expected = {f.name for f in fields(cls)}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {sorted(unknown)}")
    required = {
        f.name
        for f in fields(cls)
        if f.default is MISSING and f.default_factory is MISSING  # type: ignore[misc]
    }
    missing = required - set(data.keys())
    if missing:
        raise ConfigError(f"{path}: missing required key(s): {sorted(missing)}")

    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name in data:
            _check_scalar(f.name, data[f.name], hints[f.name], path, positive_int=False)
            kwargs[f.name] = data[f.name]
    obj = cls(**kwargs)
    return post_validate(obj) if post_validate is not None else obj
```

- [ ] **Step 8: Run `_from_dict` tests + full config suite**

Run: `pytest tests/test_config.py -v`
Expected: The new `from_dict`/`check_scalar` tests PASS. **`_build_thresholds` tests may now FAIL** because `_from_dict` no longer enforces positive-int on threshold fields like `sample_size`-style positives — this is expected and fixed in Task 3. If ONLY threshold-positive-int tests fail, proceed. If characterization tests from Task 1 fail, STOP and reassess.

- [ ] **Step 9: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "refactor(config): split _check_scalar type/value; add _from_dict post_validate hook"
```

---

## Task 3: Migrate `_build_thresholds` value checks into `post_validate`; delete the pop-reattach workarounds

`_from_dict` is now type-only, so the threshold builders need their positive-int rules restored via `post_validate`. The reward: the two `dead_groups_fallback_cap` / `duplicate_detection_max_assets` pop-validate-reattach dances (lines 440-497) can be deleted — those existed only because `_check_scalar` coupled type and value.

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:429-504` (`_build_thresholds`)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `_from_dict(..., post_validate=...)` from Task 2.
- Produces: per-threshold `post_validate` functions enforcing the same rules the dataclasses imply. The four threshold dataclasses (`ScanEngineThresholds`, `ScanActivityThresholds`, `AssetCoverageThresholds`, `DataQualityThresholds`) define which fields are positive vs non-negative — read each dataclass to enumerate its int fields before writing the hook.

- [ ] **Step 1: Read the four threshold dataclasses**

Read `src/rapid7_healthcheck/config.py` lines ~140-240 (the `*Thresholds` dataclasses). Enumerate every int field and classify: positive-only vs non-negative. The two known non-negative fields are `AssetCoverageThresholds.dead_groups_fallback_cap` and `DataQualityThresholds.duplicate_detection_max_assets` (0 allowed). Treat all other int threshold fields as positive-only (current behavior — verify against existing threshold tests, do not assume).

- [ ] **Step 2: Write the failing test (zero allowed where it should be, rejected where it shouldn't)**

```python
def test_thresholds_dead_groups_cap_zero_ok_after_refactor():
    cfg = _cfg({"thresholds": {"asset_coverage": {"dead_groups_fallback_cap": 0}}})
    _build_app_config(cfg)  # must not raise


def test_thresholds_dup_detection_zero_ok_after_refactor():
    cfg = _cfg({"thresholds": {"data_quality": {"duplicate_detection_max_assets": 0}}})
    _build_app_config(cfg)  # must not raise


def test_thresholds_positive_field_rejects_zero():
    # last_contact_warn_hours is a positive-only int field (config.py:43).
    cfg = _cfg({"thresholds": {"scan_engines": {"last_contact_warn_hours": 0}}})
    with pytest.raises(ConfigError, match="last_contact_warn_hours"):
        _build_app_config(cfg)
```

- [ ] **Step 3: Run to verify state**

Run: `pytest tests/test_config.py -k thresholds -v`
Expected: the zero-ok tests likely PASS already (type-only `_from_dict`), the positive-field-rejects-zero test FAILS (no positive enforcement after Task 2). This failure is the bug Task 3 fixes.

- [ ] **Step 4: Rewrite `_build_thresholds` with `post_validate` hooks, deleting the pop-reattach dances**

```python
def _positive_int_fields(obj, path, field_names):
    """Raise ConfigError if any named int field on obj is <= 0."""
    for name in field_names:
        val = getattr(obj, name)
        if isinstance(val, int) and not isinstance(val, bool) and val <= 0:
            raise ConfigError(f"{path}.{name}: must be a positive integer, got {val}")
    return obj


def _non_negative_int_fields(obj, path, field_names):
    for name in field_names:
        val = getattr(obj, name)
        if isinstance(val, int) and not isinstance(val, bool) and val < 0:
            raise ConfigError(f"{path}.{name}: must be a non-negative integer, got {val}")
    return obj


def _build_thresholds(data: Any) -> Thresholds:
    if not isinstance(data, dict):
        raise ConfigError("thresholds: expected mapping")
    expected = set(_THRESHOLD_NESTED.keys())
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"thresholds: unknown key(s): {sorted(unknown)}")
    missing = expected - set(data.keys())
    if missing:
        raise ConfigError(f"thresholds: missing required key(s): {sorted(missing)}")

    # Field classification (confirmed against the dataclasses, config.py:41-73).
    # POS_* = positive-only int fields, NN_* = non-negative int fields.
    # bool fields are validated by _from_dict's _check_scalar(bool) and are NOT
    # listed here.
    POS_SCAN_ENGINES = ("last_contact_warn_hours", "last_contact_fail_hours")
    POS_SCAN_ACTIVITY = ("recent_window_days", "stuck_scan_hours", "site_no_scan_days")
    POS_ASSET_COVERAGE = ("stale_asset_days", "never_scanned_days")
    NN_ASSET_COVERAGE = ("dead_groups_fallback_cap",)
    POS_DATA_QUALITY = ("stale_asset_days",)
    NN_DATA_QUALITY = ("duplicate_detection_max_assets",)

    return Thresholds(
        scan_engines=_from_dict(
            ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines",
            post_validate=lambda o: _positive_int_fields(o, "thresholds.scan_engines", POS_SCAN_ENGINES),
        ),
        scan_activity=_from_dict(
            ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity",
            post_validate=lambda o: _positive_int_fields(o, "thresholds.scan_activity", POS_SCAN_ACTIVITY),
        ),
        asset_coverage=_from_dict(
            AssetCoverageThresholds, data["asset_coverage"], "thresholds.asset_coverage",
            post_validate=lambda o: _non_negative_int_fields(
                _positive_int_fields(o, "thresholds.asset_coverage", POS_ASSET_COVERAGE),
                "thresholds.asset_coverage", NN_ASSET_COVERAGE),
        ),
        data_quality=_from_dict(
            DataQualityThresholds, data["data_quality"], "thresholds.data_quality",
            post_validate=lambda o: _non_negative_int_fields(
                _positive_int_fields(o, "thresholds.data_quality", POS_DATA_QUALITY),
                "thresholds.data_quality", NN_DATA_QUALITY),
        ),
    )
```

Fill the `POS_*` tuples from the Step 1 reading. The pop-validate-reattach blocks (old lines 440-497) and the `replace` import use here are deleted.

- [ ] **Step 5: Run the full config suite**

Run: `pytest tests/test_config.py -v`
Expected: ALL PASS, including Task 1 characterization and the Task 3 boundary tests. If a threshold message changed wording in a way a test pins, reconcile the test's `match=` to the new (still-accurate) phrasing.

- [ ] **Step 6: Verify `replace` import is still needed elsewhere or remove it**

Run: `grep -n "replace(" src/rapid7_healthcheck/config.py`
If no matches remain, remove `replace` from the `from dataclasses import` line. If matches remain, leave it.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "refactor(config): thresholds value-checks via post_validate; delete pop-reattach workarounds"
```

---

## Task 4: Migrate the three audit blocks (`audit`, `user_audit`, `template_audit`)

These three share a shape: `None -> defaults`, schema (`enabled`/`full_scan`/`sample_size`[/`agents_timeout_seconds`]/`rules`), positive-int on `sample_size` (and `agents_timeout_seconds`), then the rules block via the existing `_validate_rules_block`. Route the schema+type through `_from_dict`; keep `None->default`, the positive-int rule, and the rules-block validation as the per-block tail.

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:173-187` (`AuditConfig`, `UserAuditConfig` dataclasses — make `rules` optional)
- Modify: `src/rapid7_healthcheck/config.py:226-235` (`CloudDriftConfig` dataclass — make `rules` optional, for Task 5 consistency)
- Modify: `src/rapid7_healthcheck/config.py:507-585` (`_build_audit_config`, `_build_user_audit_config`)
- Modify: `src/rapid7_healthcheck/config.py:672-706` (`_build_template_audit_config`)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `_from_dict(..., post_validate=...)`, `_registry_rule_ids()`, `_validate_rules_block(raw_rules, valid_rule_ids, path)`, the `_positive_int_fields` helper from Task 3.
- Produces: three migrated builders returning the same `AuditConfig` / `UserAuditConfig` / `TemplateAuditConfig` shapes.
- **Constraint 1 — `rules` is a required dict on `AuditConfig`/`UserAuditConfig` (config.py:178,187), but only `TemplateAuditConfig.rules` has a `default_factory` (config.py:249).** The migration pops `rules` before `_from_dict` and re-attaches via `replace`. For `replace` to work after popping, `_from_dict` must be able to construct the object WITHOUT `rules` — which requires `rules` to be optional. **Prerequisite step: give `AuditConfig.rules`, `UserAuditConfig.rules`, and `CloudDriftConfig.rules` a `default_factory=dict`** (matching `TemplateAuditConfig`). This is safe: every builder always supplies `rules` via `replace`, and the `_default_*` factory functions already pass `rules={}` explicitly, so no observable behavior changes. The `field` import is already present (used by `TemplateAuditConfig`).
- **Constraint 2 — the `dict` hint crash.** `_from_dict` calls `_check_scalar` only for int/bool/str hints; a `dict` hint hits the `else` branch and raises "unsupported declared type". After popping `rules` from the input data, `_from_dict` never sees it in `data`, so it never type-checks it — but `get_type_hints(cls)` still includes `rules: dict`. Confirm `_from_dict` only calls `_check_scalar` for fields **present in `data`** (it does — `if f.name in data:` at the current line 348). Since `rules` is popped from `data`, the dict hint is never checked. Safe. Do NOT extend `_check_scalar` to understand `dict`.

- [ ] **Step 0: Make `rules` optional on AuditConfig / UserAuditConfig / CloudDriftConfig**

```python
@dataclass(frozen=True)
class AuditConfig:
    enabled: bool
    full_scan: bool
    sample_size: int
    agents_timeout_seconds: int
    rules: dict = field(default_factory=dict)  # str -> RuleConfig


@dataclass(frozen=True)
class UserAuditConfig:
    """Sibling to AuditConfig, scoped to the User & Permission audit category."""
    enabled: bool
    full_scan: bool
    sample_size: int
    rules: dict = field(default_factory=dict)  # str -> RuleConfig
```

And in `CloudDriftConfig` (config.py:226-235), change `rules: dict` to `rules: dict = field(default_factory=dict)`.

Run: `pytest tests/test_config.py -v`
Expected: ALL PASS (no behavior change — builders always supply `rules`). If any test constructs these dataclasses positionally relying on `rules` being required, it still works (optional field with default is constructor-compatible). Commit this as its own step is unnecessary; fold into Task 4's final commit.

- [ ] **Step 1: Write the failing test (behavior parity for audit block)**

```python
def test_audit_block_via_from_dict_parity():
    cfg = _cfg({"audit": {"enabled": True, "full_scan": True, "sample_size": 250, "agents_timeout_seconds": 90, "rules": {}}})
    app = _build_app_config(cfg)
    assert app.audit.enabled is True
    assert app.audit.sample_size == 250
    assert app.audit.agents_timeout_seconds == 90


def test_audit_unknown_key_rejected():
    cfg = _cfg({"audit": {"enabled": True, "full_scan": False, "sample_size": 1, "agents_timeout_seconds": 1, "bogus": 1}})
    with pytest.raises(ConfigError, match="unknown"):
        _build_app_config(cfg)


def test_audit_sample_size_zero_rejected_after_migration():
    cfg = _cfg({"audit": {"enabled": True, "full_scan": False, "sample_size": 0, "agents_timeout_seconds": 1, "rules": {}}})
    with pytest.raises(ConfigError, match="sample_size"):
        _build_app_config(cfg)
```

- [ ] **Step 2: Run to verify current state (should PASS pre-migration — these pin behavior to preserve)**

Run: `pytest tests/test_config.py -k "audit_block or audit_unknown or audit_sample_size_zero" -v`
Expected: PASS against current code. These lock the behavior the migration must keep.

- [ ] **Step 3: Migrate `_build_audit_config`**

```python
def _build_audit_config(data: dict | None) -> AuditConfig:
    if data is None:
        return AuditConfig(enabled=False, full_scan=False, sample_size=500, agents_timeout_seconds=180, rules={})
    if not isinstance(data, dict):
        raise ConfigError("audit: expected mapping")
    raw = dict(data)
    raw_rules = raw.pop("rules", None) or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("audit.rules: expected mapping")

    def pv(obj: AuditConfig) -> AuditConfig:
        return _positive_int_fields(obj, "audit", ("sample_size", "agents_timeout_seconds"))

    # rules popped out so _from_dict sees only scalar fields. But the dataclass
    # still has a `rules` field with a default_factory, so it is optional and
    # _from_dict will not require it.
    obj = _from_dict(AuditConfig, raw, "audit", post_validate=pv)
    valid_audit_ids, _, _, _ = _registry_rule_ids()
    rules = _validate_rules_block(raw_rules, valid_rule_ids=valid_audit_ids, path="audit.rules")
    return replace(obj, rules=rules)
```

Note: `AuditConfig.rules` was made optional in Step 0, so popping it before `_from_dict` no longer trips the missing-key check. `replace` is used by `_build_thresholds` (Task 3) so the import is present; if Task 3's prune removed it, re-add `from dataclasses import replace`.

- [ ] **Step 4: Migrate `_build_user_audit_config` and `_build_template_audit_config` identically**

Same pattern, swapping the dataclass (`UserAuditConfig` / `TemplateAuditConfig`), the path string, the positive-int field tuple (`("sample_size",)` — neither has `agents_timeout_seconds`), and the registry slot (`_, valid_user_ids, _, _` / `_, _, _, valid_template_ids`).

```python
def _build_user_audit_config(data: dict | None) -> UserAuditConfig:
    if data is None:
        return UserAuditConfig(enabled=False, full_scan=False, sample_size=500, rules={})
    if not isinstance(data, dict):
        raise ConfigError("user_audit: expected mapping")
    raw = dict(data)
    raw_rules = raw.pop("rules", None) or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("user_audit.rules: expected mapping")
    obj = _from_dict(
        UserAuditConfig, raw, "user_audit",
        post_validate=lambda o: _positive_int_fields(o, "user_audit", ("sample_size",)),
    )
    _, valid_user_ids, _, _ = _registry_rule_ids()
    rules = _validate_rules_block(raw_rules, valid_rule_ids=valid_user_ids, path="user_audit.rules")
    return replace(obj, rules=rules)


def _build_template_audit_config(data: dict | None) -> TemplateAuditConfig:
    if data is None:
        return _default_template_audit()
    if not isinstance(data, dict):
        raise ConfigError("template_audit: expected mapping")
    raw = dict(data)
    raw_rules = raw.pop("rules", None) or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("template_audit.rules: expected mapping")
    obj = _from_dict(
        TemplateAuditConfig, raw, "template_audit",
        post_validate=lambda o: _positive_int_fields(o, "template_audit", ("sample_size",)),
    )
    _, _, _, valid_template_ids = _registry_rule_ids()
    rules = _validate_rules_block(raw_rules, valid_rule_ids=valid_template_ids, path="template_audit.rules")
    return replace(obj, rules=rules)
```

- [ ] **Step 5: Run the full config suite**

Run: `pytest tests/test_config.py -v`
Expected: ALL PASS. Watch for: (a) message-wording mismatches on `match=` (reconcile the test to the new accurate phrasing); (b) the `enabled`/`full_scan` bool checks — `_from_dict` now enforces them via `_check_scalar(bool)`, confirm the messages still satisfy `match=`.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "refactor(config): route audit/user_audit/template_audit blocks through _from_dict"
```

---

## Task 5: Migrate `cloud_drift` (rules-only) and decide `cloud_integration` / `report` / `rapid7`

`cloud_drift` is rules-only and migrates trivially. `cloud_integration`, `report`, and `rapid7` carry cross-field rules (`enabled->base_url required`, HTTPS prefix), enum membership (`log_format`, `auth_mode`), nullable (`delta_max_age_days`), and range checks (`parallel_pages`, `page_size`) — all expressible as `post_validate`. Migrate them; the value rules live in the hook.

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:647-669` (`_build_cloud_drift_config`)
- Modify: `src/rapid7_healthcheck/config.py:588-644` (`_build_cloud_integration_config`)
- Modify: `src/rapid7_healthcheck/config.py:709-750` (`_build_report_config`)
- Modify: `src/rapid7_healthcheck/config.py:362-426` (`_build_rapid7_config`)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `_from_dict(..., post_validate=...)`, `_positive_int_fields`, `_non_negative_int_fields`, `_registry_rule_ids`, `_validate_rules_block`, `_VALID_AUTH_MODES`.
- Produces: migrated builders, same return shapes.
- **Constraint:** `report.delta_max_age_days` is `int | None`. `_from_dict` calls `get_type_hints`, which resolves the hint to `Optional[int]` / `int | None` — `_check_scalar`'s `if expected is int` will NOT match `int | None`, hitting the `else` "unsupported declared type" branch and raising. So `delta_max_age_days` MUST be popped before `_from_dict` (like `rules`), validated by hand (non-negative-or-None), and re-attached via `replace`. Confirm the exact hint type by reading the `ReportConfig` dataclass first.

- [ ] **Step 1: Migrate `_build_cloud_drift_config` (trivial — rules-only)**

```python
def _build_cloud_drift_config(data: dict | None) -> CloudDriftConfig:
    if data is None:
        return _default_cloud_drift()
    if not isinstance(data, dict):
        raise ConfigError("cloud_drift: expected mapping")
    _validate_dict_schema(data, expected={"rules"}, required=set(), name="cloud_drift")
    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("cloud_drift.rules: expected mapping")
    _, _, valid_cloud_ids, _ = _registry_rule_ids()
    rules = _validate_rules_block(raw_rules, valid_rule_ids=valid_cloud_ids, path="cloud_drift.rules")
    return CloudDriftConfig(rules=rules)
```

Note: `cloud_drift` is a single-field (`rules: dict`) block. `_from_dict` cannot validate a dict field, and the only field IS the dict — so `_from_dict` adds nothing here. **Leave `_build_cloud_drift_config` essentially as-is** (it is already minimal). Document that it does not route through `_from_dict` because its sole field is the rules dict. This is a deliberate non-migration, not an oversight.

- [ ] **Step 2: Write failing tests for `cloud_integration` cross-field + range via post_validate**

```python
def test_cloud_integration_enabled_requires_https_base_url():
    cfg = _cfg({"cloud_integration": {"enabled": True, "base_url": "http://x"}})
    with pytest.raises(ConfigError, match="https"):
        _build_app_config(cfg)


def test_cloud_integration_parallel_pages_range():
    cfg = _cfg({"cloud_integration": {"enabled": True, "base_url": "https://x", "parallel_pages": 99}})
    with pytest.raises(ConfigError, match="parallel_pages"):
        _build_app_config(cfg)


def test_cloud_integration_max_retries_zero_rejected():
    cfg = _cfg({"cloud_integration": {"enabled": True, "base_url": "https://x", "max_retries": 0}})
    with pytest.raises(ConfigError, match="max_retries"):
        _build_app_config(cfg)
```

- [ ] **Step 3: Run to confirm these pass against current code (behavior to preserve)**

Run: `pytest tests/test_config.py -k cloud_integration -v`
Expected: PASS pre-migration.

- [ ] **Step 4: Migrate `_build_cloud_integration_config` with a post_validate hook**

```python
def _build_cloud_integration_config(data: dict | None) -> CloudIntegrationConfig:
    if data is None:
        return _default_cloud_integration()

    def pv(c: CloudIntegrationConfig) -> CloudIntegrationConfig:
        if c.enabled and not c.base_url:
            raise ConfigError("cloud_integration.base_url: required when enabled is true")
        if c.enabled and not c.base_url.startswith("https://"):
            raise ConfigError("cloud_integration.base_url must start with https://")
        if not c.api_key_env:
            raise ConfigError("cloud_integration.api_key_env: expected non-empty str")
        _positive_int_fields(c, "cloud_integration", ("timeout_seconds", "max_retries"))
        if not (1 <= c.parallel_pages <= 16):
            raise ConfigError(
                f"cloud_integration.parallel_pages must be in range [1, 16]; got {c.parallel_pages}"
            )
        return c

    return _from_dict(CloudIntegrationConfig, data, "cloud_integration", post_validate=pv)
```

**Caution:** Confirm `max_retries` is positive-only here (Step from Global Constraints says reject 0). If the current `_build_cloud_integration_config` used `_check_scalar(... int)` (default positive) for `max_retries`, then 0 was rejected — preserve that with `_positive_int_fields`. Verify against the characterization test.

- [ ] **Step 5: Migrate `_build_report_config` (pop the nullable field)**

```python
def _build_report_config(data: Any) -> ReportConfig:
    if not isinstance(data, dict):
        raise ConfigError(f"report: expected mapping, got {type(data).__name__}")
    raw = dict(data)
    # delta_max_age_days is int | None — _from_dict/_check_scalar can't type a
    # union, so validate and re-attach it by hand.
    delta = raw.pop("delta_max_age_days", 30)
    if delta is not None and (not isinstance(delta, int) or isinstance(delta, bool) or delta < 0):
        raise ConfigError("report.delta_max_age_days: expected non-negative int or null")

    def pv(c: ReportConfig) -> ReportConfig:
        if c.log_format not in ("plain", "cmtrace", "json"):
            raise ConfigError(
                f"report.log_format: invalid value {c.log_format!r}; must be one of: plain, cmtrace, json"
            )
        return c

    obj = _from_dict(ReportConfig, raw, "report", post_validate=pv)
    return replace(obj, delta_max_age_days=delta)
```

**Caution:** `_from_dict` requires non-default fields. Confirm `ReportConfig`: `output_dir`/`filename_pattern`/`title` are required (no default), `log_format` has a default, `delta_max_age_days` has a default. After popping `delta_max_age_days`, `_from_dict` won't see it; re-attaching via `replace` is correct because the dataclass default fills the constructed object first. Verify `ReportConfig` field defaults by reading the dataclass.

- [ ] **Step 6: Migrate `_build_rapid7_config` with a post_validate hook**

```python
def _build_rapid7_config(data: Any) -> Rapid7Config:
    def pv(c: Rapid7Config) -> Rapid7Config:
        if c.auth_mode not in _VALID_AUTH_MODES:
            raise ConfigError(
                f"rapid7.auth_mode: must be one of {list(_VALID_AUTH_MODES)}, got {c.auth_mode!r}"
            )
        _positive_int_fields(c, "rapid7", ("request_timeout_seconds", "max_retries"))
        if not (1 <= c.parallel_pages <= 16):
            raise ConfigError(f"rapid7.parallel_pages must be in range [1, 16]; got {c.parallel_pages}")
        if c.parallel_pages > 8:
            logger.warning(
                "rapid7.parallel_pages=%d exceeds the documented InsightVM "
                "8-parallel-request limit; proceed at your own risk", c.parallel_pages,
            )
        if not (1 <= c.page_size <= 500):
            raise ConfigError(f"rapid7.page_size must be in range [1, 500]; got {c.page_size}")
        return c

    return _from_dict(Rapid7Config, data, "rapid7", post_validate=pv)
```

**Caution:** Current `_build_rapid7_config` checks `max_retries` as positive-int via `_check_scalar` (rejects 0 — confirmed by characterization test). Preserve. The `base_url` HTTPS check lives in `_build_app_config` (line 786), NOT here — leave it there; do not duplicate.

- [ ] **Step 7: Run the full config suite**

Run: `pytest tests/test_config.py -v`
Expected: ALL PASS. Reconcile any `match=` wording drift to the new accurate phrasing.

- [ ] **Step 8: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "refactor(config): route cloud_integration/report/rapid7 through _from_dict + post_validate"
```

---

## Task 6: Prune dead code, full suite, read-only verification

**Files:**
- Modify: `src/rapid7_healthcheck/config.py` (remove now-unused helpers/imports)
- Verify: whole suite + read-only grep

- [ ] **Step 1: Find now-dead helpers**

Run: `grep -n "_validate_dict_schema\|replace(" src/rapid7_healthcheck/config.py`
`_validate_dict_schema` is still used only by `_build_cloud_drift_config` (Task 5 Step 1 kept it). If any other builder still references it, leave it. If it is now used by zero or one caller and the one caller is trivial, consider inlining — but only if it does not change wording. When unsure, leave it (YAGNI on deletion).

- [ ] **Step 2: Remove unused imports**

Run an AST unused-import check (no pyflakes available offline):

```bash
python - <<'PY'
import ast
src = open("src/rapid7_healthcheck/config.py", encoding="utf-8").read()
tree = ast.parse(src)
imported = {}
for n in ast.walk(tree):
    if isinstance(n, ast.ImportFrom):
        for a in n.names: imported[a.asname or a.name] = n.lineno
    elif isinstance(n, ast.Import):
        for a in n.names: imported[(a.asname or a.name).split(".")[0]] = n.lineno
used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
import re
for name, ln in imported.items():
    if name == "annotations": continue
    if len(re.findall(r"\b"+re.escape(name)+r"\b", src)) <= 1:
        print(f"line {ln}: possibly unused import '{name}'")
print("done")
PY
```

Remove anything flagged (e.g. `replace` if Tasks 3-5 left it unused — but they use it, so confirm).

- [ ] **Step 3: Run the FULL suite**

Run: `pytest -v`
Expected: ALL PASS (931+ tests). Paste the tail. Zero failures, zero warnings.

- [ ] **Step 4: Read-only contract verification**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches (exit 1). Config refactor adds no HTTP.

- [ ] **Step 5: Final commit**

```bash
git add src/rapid7_healthcheck/config.py
git commit -m "refactor(config): prune dead validation helpers after _from_dict collapse"
```

---

## Self-Review notes (resolved during planning)

- **Spec coverage:** All five hand-written builders with duplicated schema (`audit`, `user_audit`, `template_audit`, `cloud_integration`, `report`) plus `rapid7` are migrated (Tasks 4-5). `cloud_drift` is a documented deliberate non-migration (single dict field — `_from_dict` adds nothing). `_build_thresholds` migrated and its workarounds deleted (Task 3). The `_check_scalar` type/value split (the prerequisite enabling all of it) is Task 2.
- **The zero-int trap** (delta_max_age_days, max_retries, threshold caps) is handled explicitly: Task 1 pins the current boundaries, Task 2 makes `_from_dict` type-only, Tasks 3-5 restore the exact per-field value rules via `post_validate`. `max_retries=0` stays REJECTED (preserved, not "fixed").
- **Union/dict field hazard:** `rules` (dict) and `delta_max_age_days` (int|None) cannot pass through `_check_scalar` — both are popped before `_from_dict` and re-attached via `replace`. Flagged in Tasks 4 and 5.
- **Wording fidelity:** substring-compatible; reconcile `match=` to new accurate phrasing where it drifts. No message-override params (don't preserve dead strings).
- **Type consistency:** `post_validate` signature is `(obj) -> obj` everywhere; `_positive_int_fields`/`_non_negative_int_fields` helpers have a single definition used across Tasks 3-5.
- **Open verification for the implementer:** read each dataclass (`*Thresholds`, `AuditConfig`, `ReportConfig`, `Rapid7Config`, `CloudIntegrationConfig`) to confirm field defaults and the exact int-field classification before writing each `post_validate`. The plan names the known cases; the dataclass is the authority.
