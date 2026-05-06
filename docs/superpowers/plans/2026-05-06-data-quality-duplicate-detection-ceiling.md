# Data Quality: Skip Duplicate Detection on Large Inventories — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable size ceiling (`duplicate_detection_max_assets`, default 50000) above which Data Quality's duplicate-hostname/IP rules are skipped with a finding pointing to the Security Console UI — preventing 12+ hour scans on 500k-asset consoles where the v3 API has no group-by.

**Architecture:** Single new threshold on `DataQualityThresholds`. New helpers `_peek_total_assets` (one-shot `GET /api/3/assets?page=0&size=1`) and `_oversize_skip_rule` (build a `pass`-status `RuleResult` containing one `info` finding) live in `data_quality.py`. `DataQualityCheck.run` branches before `_collect_duplicate_groups` is called. No HTTP-client changes. Read-only contract preserved.

**Tech Stack:** Python 3.11+, dataclass-based config validation, pytest. The validator path follows the existing `dead_groups_fallback_cap` pattern (pull-out + manual int check) because `_check_scalar` rejects `<= 0`, but `0` is a valid sentinel here meaning "always skip".

**Spec:** [docs/superpowers/specs/2026-05-06-data-quality-duplicate-detection-ceiling-design.md](../specs/2026-05-06-data-quality-duplicate-detection-ceiling-design.md)

---

## File Map

| File | Change |
|---|---|
| `src/rapid7_healthcheck/config.py` | Add `duplicate_detection_max_assets: int = 50000` to `DataQualityThresholds`; extend `_build_thresholds` to validate it (allow `>= 0`). |
| `src/rapid7_healthcheck/checks/data_quality.py` | Add `_peek_total_assets`, `_oversize_skip_rule`; modify `DataQualityCheck.run` duplicate-detection branch. |
| `tests/conftest.py` | No change — default `_default_config` does not need to set the new field; the dataclass default of `50000` applies. |
| `tests/checks/test_data_quality.py` | New tests for skip path, run path, threshold-zero, peek failure, both-flags-off. |
| `tests/test_config.py` | Default value, negative rejected, non-int rejected, zero accepted. |
| `docs/examples/config.yaml` | Add the new key with explanatory comment under `thresholds.data_quality:`. |
| `README.md` | Add a row to the thresholds table; one-sentence note in the Data Quality section about the v3 API limitation. |
| `CHANGELOG.md` | Unreleased entry. |

---

## Task 1: Add `duplicate_detection_max_assets` to config dataclass + validator

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:64-71` (the `DataQualityThresholds` dataclass)
- Modify: `src/rapid7_healthcheck/config.py:310-355` (the `_build_thresholds` function)
- Test: `tests/test_config.py`

### Step 1: Write failing tests

- [ ] Add these tests to `tests/test_config.py` (or whichever existing test class covers `data_quality` thresholds — append at end of file if no class exists):

```python
def test_data_quality_default_duplicate_detection_max_assets(tmp_path):
    """Default value should be 50000 when key is absent from YAML."""
    cfg_text = _minimal_valid_config_yaml()  # existing helper; if absent, see Step 1b below
    p = tmp_path / "config.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    from rapid7_healthcheck.config import load_config
    cfg = load_config(p)
    assert cfg.thresholds.data_quality.duplicate_detection_max_assets == 50000


def test_data_quality_duplicate_detection_max_assets_zero_accepted(tmp_path):
    """Zero is the 'always skip' sentinel and must be accepted."""
    from rapid7_healthcheck.config import load_config
    cfg_text = _minimal_valid_config_yaml(
        data_quality_extra="    duplicate_detection_max_assets: 0\n"
    )
    p = tmp_path / "config.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.thresholds.data_quality.duplicate_detection_max_assets == 0


def test_data_quality_duplicate_detection_max_assets_negative_rejected(tmp_path):
    """Negative values must be rejected with a clear error."""
    from rapid7_healthcheck.config import ConfigError, load_config
    cfg_text = _minimal_valid_config_yaml(
        data_quality_extra="    duplicate_detection_max_assets: -1\n"
    )
    p = tmp_path / "config.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate_detection_max_assets"):
        load_config(p)


def test_data_quality_duplicate_detection_max_assets_non_int_rejected(tmp_path):
    """A string value must be rejected."""
    from rapid7_healthcheck.config import ConfigError, load_config
    cfg_text = _minimal_valid_config_yaml(
        data_quality_extra='    duplicate_detection_max_assets: "fifty thousand"\n'
    )
    p = tmp_path / "config.yaml"
    p.write_text(cfg_text, encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate_detection_max_assets"):
        load_config(p)
```

### Step 1b: If `_minimal_valid_config_yaml` does not exist, add this helper at the top of `tests/test_config.py`

- [ ] Look in `tests/test_config.py` for an existing helper. If none, paste the helper below near the top:

```python
def _minimal_valid_config_yaml(*, data_quality_extra: str = "") -> str:
    """Build a minimal valid YAML body. data_quality_extra is appended verbatim
    inside the data_quality block."""
    return f"""
rapid7:
  base_url: https://api.example.com
  verify_tls: true
  request_timeout_seconds: 30
  max_retries: 3
report:
  output_dir: ./reports
  filename_pattern: r-{{timestamp}}.html
  title: Test
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
    never_scanned_days: 90
  data_quality:
    flag_missing_os: true
    flag_empty_sites: true
{data_quality_extra}checks:
  scan_engines: true
  scan_activity: true
  asset_coverage: true
  data_quality: true
"""
```

(If `tests/test_config.py` already has a different helper for the same job, use that one and adapt the new tests to match — do not duplicate.)

### Step 2: Run tests to verify they fail

- [ ] Run: `pytest tests/test_config.py -v -k duplicate_detection`
- [ ] Expected: 4 FAIL — `AttributeError: 'DataQualityThresholds' object has no attribute 'duplicate_detection_max_assets'` (default test) or `ConfigError: ... unknown key(s): ['duplicate_detection_max_assets']` (other tests).

### Step 3: Add the field to `DataQualityThresholds`

- [ ] In `src/rapid7_healthcheck/config.py`, locate the `DataQualityThresholds` dataclass (lines 64-71 currently):

```python
@dataclass(frozen=True)
class DataQualityThresholds:
    flag_missing_os: bool
    flag_empty_sites: bool
    flag_stale_assets: bool = True
    stale_asset_days: int = 180
    flag_duplicate_hostnames: bool = True
    flag_duplicate_ips: bool = True
```

Add the new field at the end:

```python
@dataclass(frozen=True)
class DataQualityThresholds:
    flag_missing_os: bool
    flag_empty_sites: bool
    flag_stale_assets: bool = True
    stale_asset_days: int = 180
    flag_duplicate_hostnames: bool = True
    flag_duplicate_ips: bool = True
    duplicate_detection_max_assets: int = 50000
```

### Step 4: Extend `_build_thresholds` to validate the new field

- [ ] In `src/rapid7_healthcheck/config.py`, locate `_build_thresholds` (around lines 310-355). Extend it to pull `duplicate_detection_max_assets` out of the `data_quality` block before passing to `_from_dict`, mirroring the `dead_groups_fallback_cap` pattern (lines 322-348). Replace the final `return Thresholds(...)` block of `_build_thresholds` with this:

```python
    # data_quality.duplicate_detection_max_assets accepts 0 (= always skip),
    # which the generic _check_scalar (>0) rejects. Pull it out, build the
    # rest via the normal path, then re-attach the validated value. Mirrors
    # the asset_coverage.dead_groups_fallback_cap handling above.
    dq_raw = data["data_quality"]
    if not isinstance(dq_raw, dict):
        raise ConfigError(
            f"thresholds.data_quality: expected mapping, got {type(dq_raw).__name__}"
        )
    dq_data = dict(dq_raw)
    dup_cap: int | None = None
    if "duplicate_detection_max_assets" in dq_data:
        dup_cap = dq_data.pop("duplicate_detection_max_assets")
        if isinstance(dup_cap, bool) or not isinstance(dup_cap, int):
            raise ConfigError(
                f"thresholds.data_quality.duplicate_detection_max_assets: "
                f"expected int, got {type(dup_cap).__name__}"
            )
        if dup_cap < 0:
            raise ConfigError(
                f"thresholds.data_quality.duplicate_detection_max_assets: "
                f"must be a non-negative integer, got {dup_cap}"
            )

    data_quality = _from_dict(
        DataQualityThresholds, dq_data, "thresholds.data_quality"
    )
    if dup_cap is not None:
        data_quality = replace(data_quality, duplicate_detection_max_assets=dup_cap)

    return Thresholds(
        scan_engines=_from_dict(ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines"),
        scan_activity=_from_dict(ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity"),
        asset_coverage=asset_coverage,
        data_quality=data_quality,
    )
```

- [ ] Verify `replace` is already imported at the top of `config.py` (it is — line 5 imports `replace` from `dataclasses`). No new import needed.

### Step 5: Run tests to verify they pass

- [ ] Run: `pytest tests/test_config.py -v -k duplicate_detection`
- [ ] Expected: 4 PASS.

### Step 6: Run full config test suite to check for regressions

- [ ] Run: `pytest tests/test_config.py -v`
- [ ] Expected: All tests PASS (no regressions in unrelated config tests).

### Step 7: Commit

- [ ] Stage and commit:

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "feat(config): add data_quality.duplicate_detection_max_assets threshold"
```

---

## Task 2: Add `_peek_total_assets` and `_oversize_skip_rule` helpers + modify `DataQualityCheck.run`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/data_quality.py` (add helpers near top, modify `run` method's duplicate-detection block)
- Test: `tests/checks/test_data_quality.py`

### Step 1: Write failing tests

- [ ] Append these tests to `tests/checks/test_data_quality.py`. The file already imports `DataQualityCheck` and `DataQualityThresholds` and defines `_all_off_except` and `_rule` helpers — reuse them.

```python
def test_duplicate_detection_skipped_when_total_exceeds_threshold(fake_client, app_config):
    """Above threshold: both rules emit pass+info findings; paginate is NOT called."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    # Peek call returns a total above the threshold.
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 100000, "size": 1}},
    )
    # Intentionally do NOT register /api/3/assets paginate; if invoked it raises.

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "pass"
    assert ip.status == "pass"
    assert len(host.findings) == 1
    assert host.findings[0].severity == "info"
    assert "100,000" in host.findings[0].message
    assert "50,000" in host.findings[0].message
    assert host.findings[0].details["total_assets"] == 100000
    assert host.findings[0].details["threshold"] == 50000
    # Confirm paginate was never called.
    assert not any(c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls)


def test_duplicate_detection_runs_when_under_threshold(fake_client, app_config):
    """Below threshold: paginate IS called and rules report duplicates normally."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [{"id": 1}], "page": {"totalResources": 1000, "size": 1}},
    )
    fake_client.set_paginate("/api/3/assets", [
        {"id": 1, "hostName": "dup", "ip": "10.0.0.1"},
        {"id": 2, "hostName": "dup", "ip": "10.0.0.1"},
    ])

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "warn"
    assert ip.status == "warn"
    assert host.summary["duplicate_hostname_groups"] == 1
    # Paginate was called.
    assert any(c[0] == "paginate" and c[1] == "/api/3/assets" for c in fake_client.calls)


def test_duplicate_detection_threshold_zero_always_skips(fake_client, app_config):
    """Threshold=0 means always skip, regardless of total."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=0,
    )
    fake_client.set_get(
        "/api/3/assets",
        {"resources": [], "page": {"totalResources": 5, "size": 1}},
    )
    # No paginate registered — would raise if called.

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    assert host.status == "pass"
    assert "disabled" in host.findings[0].message
    assert not any(c[0] == "paginate" for c in fake_client.calls)


def test_duplicate_detection_peek_failure_emits_error_rules(fake_client, app_config):
    """If the peek GET raises, both duplicate rules surface as error_rule;
    the other three Data Quality rules are unaffected."""
    cfg = _all_off_except(
        app_config,
        flag_missing_os=True,
        flag_empty_sites=True,
        flag_stale_assets=True,
        flag_duplicate_hostnames=True,
        flag_duplicate_ips=True,
        duplicate_detection_max_assets=50000,
    )
    # The other three rules need their own data sources happy.
    fake_client.set_post_one(
        "/api/3/assets/search",
        {"resources": [], "page": {"totalResources": 0, "size": 10}},
    )
    fake_client.set_paginate("/api/3/sites", [])  # empty_sites: no sites
    # The peek raises.
    fake_client.set_get_raises(
        "/api/3/assets",
        RuntimeError("simulated 500"),
    )

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "error"
    assert ip.status == "error"
    # The other three are unaffected.
    missing = _rule(result, "op.data_quality.missing_os")
    assert missing.status == "pass"


def test_duplicate_detection_skipped_when_both_flags_off_does_not_peek(fake_client, app_config):
    """Both flags off: peek is NOT called (no wasted API request); both rules emit skipped."""
    cfg = _all_off_except(
        app_config,
        flag_duplicate_hostnames=False,
        flag_duplicate_ips=False,
        duplicate_detection_max_assets=50000,
    )
    # No GET /api/3/assets registered — if called, fake_client raises.

    result = DataQualityCheck().run(fake_client, cfg)

    host = _rule(result, "op.data_quality.duplicate_hostnames")
    ip = _rule(result, "op.data_quality.duplicate_ips")
    assert host.status == "skipped"
    assert ip.status == "skipped"
    assert not any(c[0] == "get" and c[1] == "/api/3/assets" for c in fake_client.calls)
```

- [ ] Note on `_all_off_except`: it currently builds `DataQualityThresholds(**base)` with a fixed key set. After Task 1, the dataclass has the new `duplicate_detection_max_assets` field with default `50000`. The helper still works without modification because the new field has a default. **However**, the new tests pass `duplicate_detection_max_assets=...` as a kwarg — this requires `_all_off_except` to forward it through `base.update(kwargs)`. Since `_all_off_except` already does `base.update(kwargs)` and then `DataQualityThresholds(**base)`, the new kwarg is forwarded transparently and the dataclass accepts it. **No change to `_all_off_except` is needed.**

### Step 2: Run tests to verify they fail

- [ ] Run: `pytest tests/checks/test_data_quality.py -v -k "duplicate_detection"`
- [ ] Expected: 5 FAIL — most likely `AssertionError: unexpected GET /api/3/assets` (production code doesn't call the peek yet) or assertions on `pass`+info-finding shape that current code doesn't produce.

### Step 3: Add the two helpers near the top of `data_quality.py`

- [ ] In `src/rapid7_healthcheck/checks/data_quality.py`, after `_example_hostnames` (around line 32), add:

```python
def _peek_total_assets(client: Any) -> int:
    """One-shot GET /api/3/assets?page=0&size=1 to read page.totalResources cheaply.

    Used by DataQualityCheck.run to decide whether duplicate detection is
    feasible at this inventory size before walking the full asset list. The
    v3 API has no group-by, so duplicate detection requires paginating every
    asset; on large consoles (~500k assets, ~45s/page) that is infeasible.
    """
    body = client.get("/api/3/assets", params={"page": 0, "size": 1})
    return int(body.get("page", {}).get("totalResources", 0))


def _oversize_skip_rule(rule, total_assets: int, threshold: int, *, kind: str) -> RuleResult:
    """Build a pass-status RuleResult with a single info finding explaining
    why duplicate detection was skipped at this inventory size.

    `rule` is a DuplicateHostnamesRule or DuplicateIpsRule instance — used only
    to read RULE_ID / RULE_NAME / DESCRIPTION / SOURCES. `kind` is "hostname"
    or "ip" and is interpolated into the user-visible message.
    """
    if threshold == 0:
        msg = (
            f"Duplicate {kind} detection disabled "
            f"(duplicate_detection_max_assets=0). "
            f"Review duplicate {kind}s in Security Console -> Assets."
        )
    else:
        msg = (
            f"Skipped: {total_assets:,} assets exceed threshold "
            f"({threshold:,}). Walking the full inventory would take too long "
            f"on this console (v3 API has no group-by). Review duplicate "
            f"{kind}s in Security Console -> Assets, or raise "
            f"duplicate_detection_max_assets to override."
        )
    return make_rule_result(
        rule_id=rule.RULE_ID,
        rule_name=rule.RULE_NAME,
        description=rule.DESCRIPTION,
        findings=[Finding(
            severity="info",
            message=msg,
            details={"total_assets": total_assets, "threshold": threshold},
        )],
        sources=rule.SOURCES,
        summary={f"{kind}_detection_skipped": True, "total_assets": total_assets},
    )
```

### Step 4: Modify `DataQualityCheck.run`'s duplicate-detection branch

- [ ] In `src/rapid7_healthcheck/checks/data_quality.py`, locate `DataQualityCheck.run` (around lines 310-360). Find the existing block starting at the comment `# Duplicate detection — single paginate, two rules.` (around line 326). Replace the whole block from that comment through the end of the `try/except/else` (down to `rule_results.append(safe_run_rule(ip_rule, lambda: ip_rule.run(ip_groups, t)))`) with this:

```python
        # Duplicate detection — single paginate, two rules. On large consoles
        # the paginate is infeasible (v3 has no group-by, ~45s/page on 500k
        # assets), so peek totalResources first and skip with a Console-UI
        # pointer above the configured ceiling.
        host_rule = DuplicateHostnamesRule()
        ip_rule = DuplicateIpsRule()

        if not (t.flag_duplicate_hostnames or t.flag_duplicate_ips):
            # Both flags off: take the existing skipped path. Do NOT peek
            # (avoid a wasted API request when the user has explicitly
            # disabled both rules).
            rule_results.append(safe_run_rule(host_rule, lambda: host_rule.run([], t)))
            rule_results.append(safe_run_rule(ip_rule, lambda: ip_rule.run([], t)))
        else:
            try:
                total_assets = _peek_total_assets(client)
            except Exception as e:
                logger.exception("data_quality._peek_total_assets raised")
                rule_results.append(error_rule(
                    rule_id=host_rule.RULE_ID,
                    rule_name=host_rule.RULE_NAME,
                    description=host_rule.DESCRIPTION,
                    sources=host_rule.SOURCES,
                    error=e,
                ))
                rule_results.append(error_rule(
                    rule_id=ip_rule.RULE_ID,
                    rule_name=ip_rule.RULE_NAME,
                    description=ip_rule.DESCRIPTION,
                    sources=ip_rule.SOURCES,
                    error=e,
                ))
            else:
                cap = t.duplicate_detection_max_assets
                if cap == 0 or total_assets > cap:
                    rule_results.append(_oversize_skip_rule(host_rule, total_assets, cap, kind="hostname"))
                    rule_results.append(_oversize_skip_rule(ip_rule, total_assets, cap, kind="ip"))
                else:
                    try:
                        host_groups, ip_groups = _collect_duplicate_groups(client, t)
                    except Exception as e:
                        logger.exception("data_quality._collect_duplicate_groups raised")
                        rule_results.append(error_rule(
                            rule_id=host_rule.RULE_ID,
                            rule_name=host_rule.RULE_NAME,
                            description=host_rule.DESCRIPTION,
                            sources=host_rule.SOURCES,
                            error=e,
                        ))
                        rule_results.append(error_rule(
                            rule_id=ip_rule.RULE_ID,
                            rule_name=ip_rule.RULE_NAME,
                            description=ip_rule.DESCRIPTION,
                            sources=ip_rule.SOURCES,
                            error=e,
                        ))
                    else:
                        rule_results.append(safe_run_rule(host_rule, lambda: host_rule.run(host_groups, t)))
                        rule_results.append(safe_run_rule(ip_rule, lambda: ip_rule.run(ip_groups, t)))
```

### Step 5: Run new tests to verify they pass

- [ ] Run: `pytest tests/checks/test_data_quality.py -v -k "duplicate_detection"`
- [ ] Expected: 5 PASS.

### Step 6: Run full data_quality test suite for regressions

- [ ] Run: `pytest tests/checks/test_data_quality.py -v`
- [ ] Expected: All tests PASS. The pre-existing tests like `test_all_quality_good` and `test_missing_os_warns` should be unaffected because:
  - They register `set_paginate("/api/3/assets", ...)` so the peek-then-paginate path can complete (peek will return `totalResources: 0` from the default fake response if `set_get` wasn't called for `/api/3/assets`).
- [ ] **Important regression risk:** the FakeRapid7Client raises on unregistered GETs. Pre-existing tests that exercise duplicate detection with `flag_duplicate_*=True` will now also need `set_get("/api/3/assets", ...)` to satisfy the peek. Run the full suite first to identify which ones break, then fix each by adding `fake_client.set_get("/api/3/assets", {"resources": [], "page": {"totalResources": <small_number>, "size": 1}})`.
- [ ] If `test_all_quality_good`, `test_duplicate_hostnames_*`, or `test_duplicate_ips_*` (or similar) fail with `unexpected GET /api/3/assets`, add the `set_get` call to each. Pick `totalResources` to be the actual size of the `set_paginate` list passed in the same test so the peek + paginate stay consistent.

### Step 7: Run full project test suite

- [ ] Run: `pytest -v`
- [ ] Expected: All tests PASS.

### Step 8: Commit

- [ ] Stage and commit:

```bash
git add src/rapid7_healthcheck/checks/data_quality.py tests/checks/test_data_quality.py
git commit -m "feat(data_quality): skip duplicate detection above duplicate_detection_max_assets"
```

---

## Task 3: Update example config + README + CHANGELOG

**Files:**
- Modify: `docs/examples/config.yaml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

### Step 1: Update `docs/examples/config.yaml`

- [ ] Open `docs/examples/config.yaml`. Locate the `data_quality:` block under `thresholds:`. After the `flag_duplicate_ips: true` line, add:

```yaml
    # Skip duplicate hostname/IP detection when total assets exceed this
    # ceiling. The v3 API has no group-by, so duplicate detection requires
    # walking every asset; on large consoles (~500k assets, ~45s/page) that
    # is infeasible. Above this size, the rules emit an info finding pointing
    # to Security Console -> Assets instead. Set to 0 to always skip
    # duplicate detection.
    duplicate_detection_max_assets: 50000
```

### Step 2: Update `README.md` thresholds table

- [ ] Find the thresholds table in `README.md` (search for `duplicate_hostname` or `data_quality` rows). Add a new row after the `flag_duplicate_ips` row:

```markdown
| `data_quality.duplicate_detection_max_assets` | `50000` | Skip duplicate hostname/IP detection when total assets exceed this. The v3 API has no group-by; on large consoles (500k+ assets, ~45s/page) full pagination is infeasible. Above the ceiling, both rules emit an info finding pointing to Security Console → Assets. Set to `0` to always skip. |
```

(Match the exact column count and formatting of the table — if the table has a different shape, adapt the row to match.)

### Step 3: Update `README.md` Data Quality section

- [ ] Find the section describing the Data Quality check (search for "Data Quality" as a section heading). At the end of the description, add this sentence:

```markdown
At inventory sizes above `data_quality.duplicate_detection_max_assets` (default 50,000), the duplicate-hostname and duplicate-IP rules are skipped because the v3 API has no group-by operator and full pagination becomes infeasible on large consoles. The rule cards in the report point users to the Security Console UI for manual review.
```

### Step 4: Update `CHANGELOG.md`

- [ ] Open `CHANGELOG.md`. Add an Unreleased section if one doesn't exist; otherwise append to it:

```markdown
## [Unreleased]

### Changed
- **Data Quality:** added `thresholds.data_quality.duplicate_detection_max_assets` (default `50000`). When the total asset inventory exceeds this ceiling, the duplicate-hostname and duplicate-IP rules are skipped and emit an info finding pointing to the Security Console UI. The v3 API has no group-by operator, so duplicate detection requires paginating every asset; on large consoles (~500k assets, ~45s/page) this is infeasible. Set the threshold to `0` to always skip; raise it to override the default behavior on consoles where pagination is fast enough.
```

### Step 5: Verify the example config still loads

- [ ] Run a quick sanity check that the updated example config parses:

```bash
python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); print('OK:', c.thresholds.data_quality.duplicate_detection_max_assets)"
```

- [ ] Expected output: `OK: 50000`

### Step 6: Run the full test suite once more

- [ ] Run: `pytest -v`
- [ ] Expected: All tests PASS.

### Step 7: Commit

- [ ] Stage and commit:

```bash
git add docs/examples/config.yaml README.md CHANGELOG.md
git commit -m "docs: document data_quality.duplicate_detection_max_assets threshold"
```

---

## Verification (manual)

- [ ] On the user's 500k-asset console, run the tool with `duplicate_detection_max_assets: 50000` (default). Expected: Data Quality check completes in under ~5 minutes; both duplicate-detection rule cards in the report show an info finding with the message *"Skipped: 500,000 assets exceed threshold (50,000)..."* and a link to Security Console → Assets.
- [ ] Set `duplicate_detection_max_assets: 0` and re-run. Expected: same skip path, message reads *"Duplicate hostname detection disabled..."*.
- [ ] On a small test console (well under 50k), confirm the duplicate-detection rules still run and report any actual duplicates as before.

## Self-Review Notes

**Spec coverage:**
- ✅ New threshold `duplicate_detection_max_assets` (default 50000) — Task 1.
- ✅ `0` as "always skip" sentinel — Task 1 + Task 2 + Task 3.
- ✅ Negative rejected — Task 1.
- ✅ `_peek_total_assets` helper — Task 2 Step 3.
- ✅ `_oversize_skip_rule` helper, both threshold>0 and threshold=0 messages — Task 2 Step 3.
- ✅ Branch order in `run`: both flags off → existing skip; peek raises → error rules; total > cap or cap == 0 → oversize skip; else → existing path — Task 2 Step 4.
- ✅ Pass status with info finding (not skipped status) — Task 2 helper uses `make_rule_result` which derives `pass` from a single `info` finding.
- ✅ Read-only safety: only adds a `GET` call. — Task 2.
- ✅ Tests for all five branches — Task 2 Step 1.
- ✅ Config validator tests (default, zero, negative, non-int) — Task 1 Step 1.
- ✅ Example config + README + CHANGELOG — Task 3.

**Type consistency:**
- `cap` (local in `run`) is `int` (from `t.duplicate_detection_max_assets`).
- `_peek_total_assets` returns `int`.
- `_oversize_skip_rule(rule, total_assets, threshold, *, kind)` matches the call sites.
- `kind="hostname"` and `kind="ip"` match the strings used in the message (`f"duplicate {kind}s"` reads "duplicate hostnames" / "duplicate ips").
- All field names (`duplicate_detection_max_assets`) consistent across config dataclass, validator, example YAML, README row, and tests.

**No placeholders, no TBDs.** Every step has actual code or an exact command.

**Frequent commits:** three commits across three tasks, each at a natural completion boundary.
