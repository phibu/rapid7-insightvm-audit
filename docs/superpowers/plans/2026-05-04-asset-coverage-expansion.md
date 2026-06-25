# Asset Coverage Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `AssetCoverageCheck` from 2 rules to 6 by adding 4 new coverage rules (dead asset groups, unauthenticated-only assets, no-services-detected assets, and agent-only assets outside scan scope), preserving the read-only contract and the existing `Check` Protocol.

**Architecture:** Add 4 private rule methods to the existing `AssetCoverageCheck`. Thread `EnvSnapshot` (today owned by the audit subsystem) through an additive optional `snapshot=None` kwarg on `Check.run`, built once in `__main__.py` and shared with both audit and op-checks. Two of the four new rules need snapshot data (`asset_groups`, `agent_asset_ids` + new `all_included_targets` accessor); two reuse the existing `client.paginate_post("/api/3/assets/search", ...)` pattern. The 4th rule (`agent_only_assets`) is gated behind `audit.full_scan` due to per-asset GET cost.

**Tech Stack:** Python 3.11+, pytest, `requests` (already wrapped by `client.py` with verb allowlist), `ipaddress` (stdlib) for CIDR/IP-range matching, no new dependencies.

**Read-only safety:** No new POST paths. No `client.py` changes. The only new HTTP calls are `GET /api/3/assets/{id}` (R4) -- `GET` is already in `_ALLOWED_VERBS`. `POST /api/3/assets/search` (R2, R3) is already on `_ALLOWED_POST_PATHS`. Per-task verification commands are included.

**Spec:** [docs/superpowers/specs/2026-05-04-asset-coverage-expansion-design.md](../specs/2026-05-04-asset-coverage-expansion-design.md)

---

## File Structure

| File | Responsibility | Change type |
|---|---|---|
| `src/rapid7_healthcheck/checks/__init__.py` | `Check` Protocol -- add optional `snapshot=None` kwarg | modify |
| `src/rapid7_healthcheck/audit/snapshot.py` | Add `all_included_targets()` lazy accessor + `IncludedTargets` helper dataclass | modify |
| `src/rapid7_healthcheck/config.py` | Extend `AssetCoverageThresholds` with 4 new boolean fields (defaulted) | modify |
| `src/rapid7_healthcheck/checks/asset_coverage.py` | Add 4 private rule methods + thread `snapshot` kwarg | modify |
| `src/rapid7_healthcheck/__main__.py` | Build `EnvSnapshot` once, pass to checks that accept it | modify |
| `docs/examples/config.yaml` | Document the 4 new toggle keys with comments | modify |
| `tests/checks/test_asset_coverage.py` | Add per-rule tests + integration-shape tests | modify |
| `tests/audit/test_snapshot.py` (if absent: `tests/audit/test_snapshot_targets.py`) | Test the new `all_included_targets()` accessor in isolation | create or modify |
| `README.md` | Extend Asset Coverage rule table with R1-R4 | modify |
| `CHANGELOG.md` | Add Unreleased entry noting 2→6 rules + config additions | modify |

---

## Task 1: Extend `Check` Protocol with optional `snapshot` kwarg

**Files:**
- Modify: `src/rapid7_healthcheck/checks/__init__.py:43-47`
- Test: covered indirectly by Task 8's backwards-compat test

**Why first:** every later task assumes `Check.run(client, config, *, snapshot=None)` is callable. Doing this first prevents downstream tasks from hitting type-hint friction.

- [ ] **Step 1: Read current Protocol definition**

```bash
sed -n '43,47p' src/rapid7_healthcheck/checks/__init__.py
```

Expected output:
```
class Check(Protocol):
    name: str
    description: str

    def run(self, client: Any, config: AppConfig) -> CheckResult: ...
```

- [ ] **Step 2: Add the optional snapshot kwarg**

Replace the protocol body to:

```python
class Check(Protocol):
    name: str
    description: str

    def run(
        self,
        client: Any,
        config: AppConfig,
        *,
        snapshot: Any = None,
    ) -> CheckResult: ...
```

The `Any` type avoids importing `EnvSnapshot` (which lives in `audit.snapshot` and would create a circular import via `audit/__init__.py` → `checks/__init__.py`). `Any` is consistent with how `client` is already typed.

- [ ] **Step 3: Verify nothing imports break**

```bash
python -c "from rapid7_healthcheck.checks import Check, CheckResult, Finding, rollup_status; print('ok')"
```

Expected: `ok`

- [ ] **Step 4: Run existing test suite to confirm no regressions**

```bash
pytest -v --tb=short 2>&1 | tail -20
```

Expected: same pass/fail counts as before this task. (Existing checks pass `(client, config)` positionally; the new kwarg is optional with a default, so they continue to work.)

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/checks/__init__.py
git commit -m "feat(checks): add optional snapshot kwarg to Check protocol

Additive change -- existing checks continue to satisfy the protocol.
Threading EnvSnapshot through op-checks lets future rules reuse the
audit subsystem's lazy-loaded API reads (sites, asset_groups, agents)
without duplicating fetches in __main__.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 2: Add `IncludedTargets` helper + `all_included_targets()` snapshot accessor

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py`
- Test: `tests/audit/test_snapshot_targets.py` (create)

**Why now:** R4 (`agent_only_assets`) needs to test "is this IP inside any site's scan target ranges?" Building this as a standalone snapshot accessor (rather than inline in the rule) makes it cacheable across runs and unit-testable in isolation.

- [ ] **Step 1: Write the failing test**

Create `tests/audit/test_snapshot_targets.py`:

```python
"""Tests for EnvSnapshot.all_included_targets() -- used by op.asset_coverage.agent_only_assets."""
from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from rapid7_healthcheck.audit.snapshot import EnvSnapshot


class _FakeClient:
    """Minimal fake satisfying the snapshot's client surface for sites + targets."""

    def __init__(self, sites: list[dict], targets_by_site: dict[int, list[str]]):
        self._sites = sites
        self._targets = targets_by_site
        self.calls: list[str] = []

    def paginate(self, path: str, params: dict | None = None):
        self.calls.append(f"paginate {path}")
        if path == "/api/3/sites":
            yield from self._sites
        else:
            raise AssertionError(f"unexpected paginate path: {path}")

    def get(self, path: str, params: dict | None = None) -> dict:
        self.calls.append(f"get {path}")
        if path.endswith("/included_targets"):
            site_id = int(path.split("/")[-2])
            return {"addresses": self._targets.get(site_id, [])}
        raise AssertionError(f"unexpected get path: {path}")


def _snap(sites, targets):
    return EnvSnapshot(_FakeClient(sites, targets), full_scan=True, sample_size=500)


def test_all_included_targets_empty_when_no_sites():
    snap = _snap([], {})
    targets = snap.all_included_targets()
    assert targets.networks == []
    assert targets.literals == set()


def test_all_included_targets_collects_cidrs_and_literals():
    sites = [{"id": 1}, {"id": 2}]
    targets = {1: ["10.0.0.0/24", "192.168.1.5"], 2: ["10.0.1.0/24"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    assert ip_network("10.0.0.0/24") in result.networks
    assert ip_network("10.0.1.0/24") in result.networks
    assert "192.168.1.5" in result.literals


def test_all_included_targets_handles_ip_ranges():
    """Rapid7 supports range syntax like '10.0.0.1-10.0.0.10'."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.1-10.0.0.10"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    # Range is normalized to a list of IPs in the literals set.
    assert "10.0.0.1" in result.literals
    assert "10.0.0.10" in result.literals
    assert "10.0.0.5" in result.literals


def test_all_included_targets_skips_invalid_entries():
    """Malformed targets must not crash the rule -- log and skip."""
    sites = [{"id": 1}]
    targets = {1: ["not-an-ip", "10.0.0.0/24"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    assert ip_network("10.0.0.0/24") in result.networks
    assert "not-an-ip" not in result.literals


def test_all_included_targets_is_cached():
    """Second call should not re-issue HTTP."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.0/24"]}
    client = _FakeClient(sites, targets)
    snap = EnvSnapshot(client, full_scan=True, sample_size=500)
    snap.all_included_targets()
    call_count_after_first = len(client.calls)
    snap.all_included_targets()
    assert len(client.calls) == call_count_after_first


def test_all_included_targets_contains_helper():
    """The returned object provides a `contains(ip_str)` convenience."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.0/24", "192.168.1.5"]}
    snap = _snap(sites, targets)
    t = snap.all_included_targets()
    assert t.contains("10.0.0.99") is True
    assert t.contains("192.168.1.5") is True
    assert t.contains("172.16.0.1") is False
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/audit/test_snapshot_targets.py -v 2>&1 | tail -15
```

Expected: every test fails with `AttributeError: 'EnvSnapshot' object has no attribute 'all_included_targets'`.

- [ ] **Step 3: Add the helper dataclass + accessor**

Add to the **top** of `src/rapid7_healthcheck/audit/snapshot.py` (just below the existing imports):

```python
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Iterator
```

Add this dataclass **above** `class EnvSnapshot`:

```python
@dataclass
class IncludedTargets:
    """Normalized union of every site's included scan targets.

    `networks` holds CIDR blocks; `literals` holds individual IPs (including
    those expanded from range syntax like '10.0.0.1-10.0.0.10'). Use
    `contains(ip_str)` to test membership without having to know which bucket
    the address lives in.
    """
    networks: list = field(default_factory=list)
    literals: set = field(default_factory=set)

    def contains(self, ip_str: str) -> bool:
        if ip_str in self.literals:
            return True
        try:
            addr = ip_address(ip_str)
        except (ValueError, TypeError):
            return False
        return any(addr in net for net in self.networks)


def _expand_target(entry: str, *, range_cap: int = 1024) -> tuple[list, set]:
    """Parse a single included-targets entry into (networks, literals).

    Accepts CIDR blocks ('10.0.0.0/24'), single IPs ('10.0.0.5'), and
    Rapid7-style ranges ('10.0.0.1-10.0.0.10'). Ranges are expanded into
    literal IPs up to `range_cap` addresses; oversized ranges fall back to
    being treated as the bounding /CIDR network so we don't blow up memory.
    Invalid entries return ([], set()) -- caller logs and skips.
    """
    networks: list = []
    literals: set = set()
    entry = entry.strip()
    if not entry:
        return networks, literals
    # Range syntax (a-b)
    if "-" in entry and entry.count(".") >= 6:
        try:
            lo_str, hi_str = entry.split("-", 1)
            lo = ip_address(lo_str.strip())
            hi = ip_address(hi_str.strip())
            if int(hi) < int(lo):
                return networks, literals
            span = int(hi) - int(lo) + 1
            if span <= range_cap:
                cls = IPv4Address if isinstance(lo, IPv4Address) else IPv6Address
                for i in range(span):
                    literals.add(str(cls(int(lo) + i)))
                return networks, literals
            # Oversized range -- fall back to the broadest covering network.
            # Conservative: include both endpoints as literals so callers don't lose them.
            literals.add(str(lo))
            literals.add(str(hi))
            return networks, literals
        except (ValueError, TypeError):
            return networks, literals
    # CIDR or single IP
    try:
        if "/" in entry:
            networks.append(ip_network(entry, strict=False))
        else:
            ip_address(entry)  # validate
            literals.add(entry)
    except (ValueError, TypeError):
        return [], set()
    return networks, literals
```

Add this method to `EnvSnapshot` (just below the existing `site_included_targets` accessor):

```python
def all_included_targets(self) -> IncludedTargets:
    """Build the normalized union of every site's included scan targets.

    Walks every site once via `sites()` (which is itself cached), then calls
    `site_included_targets(site_id)` per site (also cached). Result cached on
    first call.
    """
    if not hasattr(self, "_all_included_targets_cache"):
        self._all_included_targets_cache: IncludedTargets | None = None
    if self._all_included_targets_cache is not None:
        return self._all_included_targets_cache

    networks: list = []
    literals: set = set()
    for site in self.sites():
        site_id = site.get("id")
        if site_id is None:
            continue
        try:
            entries = self.site_included_targets(int(site_id))
        except Rapid7ClientError as e:
            logger.warning("included_targets fetch failed for site %s: %s", site_id, e)
            continue
        for entry in entries:
            # Rapid7 returns either bare strings or {"address": "..."} dicts depending on endpoint version.
            value = entry if isinstance(entry, str) else entry.get("address") or entry.get("ip")
            if not value:
                continue
            n, l = _expand_target(str(value))
            networks.extend(n)
            literals |= l

    self._all_included_targets_cache = IncludedTargets(networks=networks, literals=literals)
    return self._all_included_targets_cache
```

Also initialize the cache slot in `__init__` for explicitness -- add this line alongside the other `self._*_cache: ... = None` lines in `EnvSnapshot.__init__`:

```python
self._all_included_targets_cache: IncludedTargets | None = None
```

…and remove the `if not hasattr(...)` block from `all_included_targets` since the slot is always initialized.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/audit/test_snapshot_targets.py -v 2>&1 | tail -20
```

Expected: all 6 tests pass.

- [ ] **Step 5: Run full suite to confirm no regressions**

```bash
pytest -v 2>&1 | tail -10
```

Expected: same pass count as before plus 6 new passes; no failures.

- [ ] **Step 6: Verify read-only contract still holds**

```bash
grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/rapid7_healthcheck/audit/snapshot.py
```

Expected: zero matches.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot_targets.py
git commit -m "feat(snapshot): add all_included_targets accessor

Normalizes every site's included scan targets into CIDR networks and
literal IPs with a contains(ip_str) helper. Used by the upcoming
op.asset_coverage.agent_only_assets rule to detect agent-managed
assets outside any scheduled scan's scope.

Range syntax (a-b) is expanded up to a 1024-address cap; oversized
ranges fall back to recording just the endpoints as literals to
bound memory.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 3: Extend `AssetCoverageThresholds` with 4 new boolean toggles

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:49-52` (the dataclass)
- Modify: `docs/examples/config.yaml:32-35` (the example block)
- Test: `tests/test_config.py` (add toggles test)

**Why now:** rule methods in later tasks read `t.flag_dead_asset_groups` etc. They have to exist as dataclass fields with defaults before the rule code can reference them.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py` (or create a new test if the file doesn't have a config-loading test pattern):

```python
def test_asset_coverage_thresholds_have_new_toggles_with_defaults(tmp_path):
    """The 4 new asset-coverage toggles are optional with sensible defaults."""
    import yaml
    from rapid7_healthcheck.config import load_config

    cfg_path = tmp_path / "config.yaml"
    # Minimal valid config -- omit the new toggles entirely.
    cfg_path.write_text(yaml.safe_dump({
        "rapid7": {
            "base_url": "https://example.com",
            "verify_tls": True,
            "request_timeout_seconds": 30,
            "max_retries": 3,
        },
        "thresholds": {
            "scan_engines": {"max_consecutive_failures": 3, "min_engines": 1, "stale_contact_minutes": 60},
            "scan_activity": {"recent_window_days": 7, "stuck_scan_hours": 48, "site_no_scan_days": 30},
            "asset_coverage": {"stale_asset_days": 30, "flag_unscanned_assets": True, "never_scanned_days": 90},
            "data_quality": {"flag_missing_os": True, "flag_empty_sites": True},
        },
        "checks": {"asset_coverage": True},
        "report": {"output_dir": str(tmp_path), "filename_pattern": "report.html"},
    }))
    cfg = load_config(str(cfg_path))
    ac = cfg.thresholds.asset_coverage
    assert ac.flag_dead_asset_groups is True
    assert ac.flag_unauth_only_assets is True
    assert ac.flag_no_services_detected is True
    assert ac.flag_agent_only_assets is False  # default OFF
```

If `tests/test_config.py` doesn't exist, search for the existing config-loading test:

```bash
grep -rn "load_config\|AssetCoverageThresholds" tests/ | head -5
```

…and append the test there instead. **Do not** create a new test file just for this one test if a sibling already exists.

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest -k "asset_coverage_thresholds_have_new_toggles" -v 2>&1 | tail -10
```

Expected: fails with `AttributeError: 'AssetCoverageThresholds' object has no attribute 'flag_dead_asset_groups'`.

- [ ] **Step 3: Add the 4 toggle fields to the dataclass**

In `src/rapid7_healthcheck/config.py`, replace the existing dataclass:

```python
@dataclass(frozen=True)
class AssetCoverageThresholds:
    stale_asset_days: int
    flag_unscanned_assets: bool
    never_scanned_days: int
    flag_dead_asset_groups: bool = True
    flag_unauth_only_assets: bool = True
    flag_no_services_detected: bool = True
    flag_agent_only_assets: bool = False
```

The 3 original fields remain required (no default) to preserve the existing config-loading semantics; the 4 new fields have defaults so existing user `config.yaml` files keep loading without modification.

- [ ] **Step 4: Run the new test plus the existing config tests**

```bash
pytest tests/test_config.py -v 2>&1 | tail -15
```

Expected: new test passes; existing config tests still pass.

- [ ] **Step 5: Update the example config**

In `docs/examples/config.yaml`, replace the `asset_coverage:` block (currently lines 32-35):

```yaml
  asset_coverage:
    stale_asset_days: 30
    flag_unscanned_assets: true
    never_scanned_days: 90
    # New in 0.2.7 -- see README "Asset Coverage" section.
    # Flag asset groups whose membership criteria match zero assets
    # (orphaned RBAC/report scopes).
    flag_dead_asset_groups: true
    # Flag assets where the most recent scan was unauthenticated
    # (vulnerability-assessed=false) -- surface-level visibility only.
    flag_unauth_only_assets: true
    # Flag assets recently scanned but with zero detected services --
    # usually a firewall blocking the scan engine or a scope misconfig.
    flag_no_services_detected: true
    # Flag Insight Agent-managed assets that fall outside every site's
    # configured scan target ranges -- they only get opportunistic agent
    # data, never scheduled scans. REQUIRES audit.full_scan: true to
    # actually run (per-asset GETs are too expensive for the fast path).
    flag_agent_only_assets: false
```

- [ ] **Step 6: Run the example-config-loads test (if one exists)**

```bash
grep -rn "docs/examples/config.yaml\|examples_config" tests/ | head -3
```

If a test loads the example config, run it:

```bash
pytest -k "example" -v 2>&1 | tail -10
```

Expected: passes. (If no such test exists, skip -- the validator will run against this YAML at app startup and would have caught a typo.)

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/config.py docs/examples/config.yaml tests/test_config.py
git commit -m "feat(config): add 4 asset-coverage toggle fields

flag_dead_asset_groups, flag_unauth_only_assets, flag_no_services_detected
default to true. flag_agent_only_assets defaults to false (it's gated on
audit.full_scan and would be a no-op in fast mode anyway).

All four are optional with defaults so existing config.yaml files keep
loading unchanged.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 4: Implement R1 -- `op.asset_coverage.dead_asset_groups`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/checks/test_asset_coverage.py`:

```python
# ----- R1: dead_asset_groups -----

class _FakeSnapshot:
    """Minimal fake EnvSnapshot for op-check tests.

    Only implements the methods the asset_coverage rules touch. Add a method
    here when a new rule needs new snapshot data.
    """

    def __init__(
        self,
        *,
        sites: list[dict] | None = None,
        asset_groups: list[dict] | None = None,
        agent_asset_ids: set[int] | None = None,
        agents_unavailable: bool = False,
        included_targets=None,
        full_scan: bool = False,
        sample_size: int = 500,
    ):
        self._sites = sites or []
        self._asset_groups = asset_groups or []
        self._agent_asset_ids = agent_asset_ids or set()
        self._agents_unavailable = agents_unavailable
        self._included_targets = included_targets
        self.full_scan = full_scan
        self.sample_size = sample_size

    def sites(self): return self._sites
    def asset_groups(self): return self._asset_groups
    def agent_asset_ids(self): return self._agent_asset_ids
    def is_agents_unavailable(self): return self._agents_unavailable
    def all_included_targets(self): return self._included_targets


def test_r1_dead_asset_groups_all_populated(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[
        {"id": 1, "name": "Prod Servers", "type": "dynamic", "assets": 250},
        {"id": 2, "name": "Workstations", "type": "static", "assets": 50},
    ])
    fake_client.set_paginate_post("/api/3/assets/search", [])  # other rules
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "pass"
    assert rule.summary["dead_groups_count"] == 0


def test_r1_dead_asset_groups_some_empty(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[
        {"id": 1, "name": "Prod Servers", "type": "dynamic", "assets": 250},
        {"id": 2, "name": "Decommissioned", "type": "static", "assets": 0},
        {"id": 3, "name": "Old Pilot", "type": "dynamic", "assets": 0},
    ])
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "warn"
    assert rule.summary["dead_groups_count"] == 2
    finding = rule.findings[0]
    examples = finding.details["examples"]
    assert len(examples) == 2
    names = {e["group_name"] for e in examples}
    assert names == {"Decommissioned", "Old Pilot"}


def test_r1_dead_asset_groups_no_groups(fake_client, app_config):
    snap = _FakeSnapshot(asset_groups=[])
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "pass"
    assert rule.summary["dead_groups_count"] == 0


def test_r1_dead_asset_groups_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_dead_asset_groups=False,
            ),
        ),
    )
    snap = _FakeSnapshot(asset_groups=[{"id": 1, "name": "g", "type": "static", "assets": 0}])
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "skipped"


def test_r1_dead_asset_groups_errors_when_snapshot_missing(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    rule = _rule(result, "op.asset_coverage.dead_asset_groups")
    assert rule.status == "error"
    assert "snapshot" in (rule.findings[0].message if rule.findings else "")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/checks/test_asset_coverage.py -k "r1_" -v 2>&1 | tail -20
```

Expected: all 5 R1 tests fail (rule doesn't exist yet, `_rule` lookup raises `StopIteration`).

- [ ] **Step 3: Modify `AssetCoverageCheck.run` to accept `snapshot` and append the new rule**

Edit `src/rapid7_healthcheck/checks/asset_coverage.py`. Add this constant near the top with the existing `_SRC_FILTERED_SEARCH`:

```python
_SRC_ASSET_GROUPS = "https://docs.rapid7.com/insightvm/asset-groups/"
```

Replace the `run` method:

```python
def run(self, client: Any, config: AppConfig, *, snapshot: Any = None) -> CheckResult:
    start = time.monotonic()
    t = config.thresholds.asset_coverage
    rule_results: list[RuleResult] = [
        self._stale_assets(client, t),
        self._never_scanned_assets(client, t),
        self._dead_asset_groups(snapshot, t),
    ]

    return CheckResult(
        name=self.name,
        description=self.description,
        status=rollup_check_status(rule_results),
        findings=flatten_findings(rule_results),
        summary=rule_summary(rule_results),
        duration_ms=int((time.monotonic() - start) * 1000),
        rule_results=rule_results,
    )
```

Add the new private method below `_never_scanned_assets`:

```python
def _dead_asset_groups(self, snapshot: Any, t) -> RuleResult:
    rid = "op.asset_coverage.dead_asset_groups"
    name = "Asset groups with zero members"
    desc = (
        "Asset groups whose membership criteria match no assets -- orphaned "
        "RBAC/report scopes that were probably created for a project that "
        "ended or for assets that have since been removed."
    )
    sources = [_SRC_ASSET_GROUPS]

    if not t.flag_dead_asset_groups:
        return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

    if snapshot is None:
        return make_rule_result(
            rule_id=rid,
            rule_name=name,
            description=desc,
            findings=[Finding(
                severity="warn",
                message="snapshot required but not provided to check",
            )],
            sources=sources,
            summary={"dead_groups_count": 0, "error": "snapshot required"},
        )

    rule_start = time.monotonic()
    groups = snapshot.asset_groups()
    dead = [g for g in groups if int(g.get("assets") or 0) == 0]
    findings: list[Finding] = []
    if dead:
        findings.append(Finding(
            severity="warn",
            message=f"{len(dead)} asset group(s) have zero members",
            details={
                "total": len(dead),
                "examples": [
                    {
                        "group_id": g.get("id"),
                        "group_name": g.get("name", f"id={g.get('id')}"),
                        "type": g.get("type"),
                    }
                    for g in dead[:_EXAMPLES_LIMIT]
                ],
            },
        ))
    return make_rule_result(
        rule_id=rid,
        rule_name=name,
        description=desc,
        findings=findings,
        sources=sources,
        summary={"dead_groups_count": len(dead), "total_groups": len(groups)},
        duration_ms=int((time.monotonic() - rule_start) * 1000),
    )
```

> **Note on the snapshot-missing case:** the spec says "RuleResult(status="error")". Easiest way to produce status="error" via `make_rule_result` is to emit a `Finding(severity="warn"...)` (which would yield status="warn"), but the test asserts `status == "error"`. So instead we construct the `RuleResult` directly when snapshot is missing -- but the helper takes findings list. Look at the existing `make_rule_result` carefully: it derives status from finding severity via `fail > warn > pass`. There's no "error" severity. So to produce status="error" we must construct `RuleResult` directly. **Refactor:** replace the `if snapshot is None` block above with:

```python
if snapshot is None:
    return RuleResult(
        rule_id=rid,
        rule_name=name,
        description=desc,
        severity="warn",
        status="error",
        findings=[Finding(severity="warn", message="snapshot required but not provided to check")],
        summary={"dead_groups_count": 0, "error": "snapshot required"},
        sources=sources,
    )
```

Add the import at the top of `asset_coverage.py` if not already present:

```python
from rapid7_healthcheck.audit import RuleResult
```

(It's already imported -- confirm before duplicating.)

- [ ] **Step 4: Run R1 tests to verify they pass**

```bash
pytest tests/checks/test_asset_coverage.py -k "r1_" -v 2>&1 | tail -20
```

Expected: all 5 R1 tests pass.

- [ ] **Step 5: Run the full asset_coverage test file to confirm no regressions**

```bash
pytest tests/checks/test_asset_coverage.py -v 2>&1 | tail -20
```

Expected: all existing tests still pass; 5 new R1 tests pass.

- [ ] **Step 6: Verify read-only contract**

```bash
grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/rapid7_healthcheck/checks/asset_coverage.py
```

Expected: zero matches.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "feat(asset_coverage): add R1 dead_asset_groups rule

Detects asset groups whose membership criteria match zero assets.
Reads the per-group 'assets' count already present in the
/api/3/asset_groups response -- zero extra API calls.

Run signature gains an optional snapshot kwarg; no-snapshot path
returns status='error' with a clear message rather than crashing.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 5: Implement R2 -- `op.asset_coverage.unauth_only_assets`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/checks/test_asset_coverage.py`:

```python
# ----- R2: unauth_only_assets -----

def test_r2_unauth_only_assets_pass_when_empty(fake_client, app_config):
    """No assets match the vulnerability-assessed=false filter → pass."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []  # empty for every call

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "pass"
    assert rule.summary["unauth_only_count"] == 0


def test_r2_unauth_only_assets_fail_with_examples(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    unauth = [_asset(f"unauth-{i}", i) for i in range(15)]

    def paginate_post(path, json_body, params=None, page_size=500):
        # R2 is the only rule whose filter is vulnerability-assessed=False.
        text = str(json_body)
        if "vulnerability-assessed" in text:
            yield from unauth
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "fail"
    assert rule.summary["unauth_only_count"] == 15
    assert len(rule.findings[0].details["examples"]) == 10  # capped at _EXAMPLES_LIMIT


def test_r2_unauth_only_assets_uses_correct_filter_body(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    AssetCoverageCheck().run(fc, app_config, snapshot=snap)

    unauth_bodies = [b for b in captured if any(
        f.get("field") == "vulnerability-assessed" for f in b.get("filters", [])
    )]
    assert len(unauth_bodies) == 1
    body = unauth_bodies[0]
    assert body["match"] == "all"
    f = body["filters"][0]
    assert f == {"field": "vulnerability-assessed", "operator": "is", "value": False}


def test_r2_unauth_only_assets_handles_400_filter_unsupported(fake_client, app_config):
    """If the console rejects the filter (older API version), report as error
    via status_code branching -- never substring-match the message."""
    from tests.conftest import FakeRapid7Client
    from rapid7_healthcheck.client import Rapid7ClientError
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "vulnerability-assessed" in text:
            err = Rapid7ClientError("400 Bad Request: filter field not supported")
            err.status_code = 400
            raise err
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "error"
    # Other rules still completed
    assert _rule(result, "op.asset_coverage.stale_assets").status in ("pass", "warn", "fail")


def test_r2_unauth_only_assets_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_unauth_only_assets=False,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.unauth_only_assets")
    assert rule.status == "skipped"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/checks/test_asset_coverage.py -k "r2_" -v 2>&1 | tail -20
```

Expected: 5 R2 tests fail with `StopIteration` (rule not registered).

- [ ] **Step 3: Add the rule method**

In `src/rapid7_healthcheck/checks/asset_coverage.py`, append `_unauth_only_assets` to the `run` method's rule list (after `_dead_asset_groups`):

```python
        rule_results: list[RuleResult] = [
            self._stale_assets(client, t),
            self._never_scanned_assets(client, t),
            self._dead_asset_groups(snapshot, t),
            self._unauth_only_assets(client, t),
        ]
```

Add the method:

```python
def _unauth_only_assets(self, client: Any, t) -> RuleResult:
    rid = "op.asset_coverage.unauth_only_assets"
    name = "Assets scanned but not authenticated"
    desc = (
        "Assets where vulnerability-assessed=false -- they were discovered "
        "and possibly port-scanned but never assessed for vulnerabilities. "
        "Surface-level visibility only; masks real risk."
    )
    sources = [_SRC_FILTERED_SEARCH]

    if not t.flag_unauth_only_assets:
        return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

    rule_start = time.monotonic()
    body = {
        "filters": [
            {"field": "vulnerability-assessed", "operator": "is", "value": False},
        ],
        "match": "all",
    }
    try:
        unauth = list(client.paginate_post("/api/3/assets/search", json_body=body))
    except Rapid7ClientError as e:
        msg = (
            "filter not supported by this console version"
            if getattr(e, "status_code", None) == 400
            else str(e)[:200]
        )
        return RuleResult(
            rule_id=rid,
            rule_name=name,
            description=desc,
            severity="fail",
            status="error",
            findings=[Finding(severity="warn", message=msg)],
            summary={"unauth_only_count": 0, "error": msg},
            sources=sources,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    findings: list[Finding] = []
    if unauth:
        findings.append(Finding(
            severity="fail",
            message=f"{len(unauth)} asset(s) scanned but never authenticated",
            details={"total": len(unauth), "examples": _example_hostnames(unauth)},
        ))
    return make_rule_result(
        rule_id=rid,
        rule_name=name,
        description=desc,
        findings=findings,
        sources=sources,
        summary={"unauth_only_count": len(unauth)},
        duration_ms=int((time.monotonic() - rule_start) * 1000),
        default_severity="fail",
    )
```

Add the import at the top if not already present:

```python
from rapid7_healthcheck.client import Rapid7ClientError
```

- [ ] **Step 4: Run R2 tests to verify they pass**

```bash
pytest tests/checks/test_asset_coverage.py -k "r2_" -v 2>&1 | tail -20
```

Expected: all 5 R2 tests pass.

- [ ] **Step 5: Run full asset_coverage tests**

```bash
pytest tests/checks/test_asset_coverage.py -v 2>&1 | tail -30
```

Expected: all R1 + R2 + existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "feat(asset_coverage): add R2 unauth_only_assets rule

Filters /api/3/assets/search by vulnerability-assessed=false to detect
assets that were discovered and port-scanned but never authenticated.
Surface-level visibility only -- these assets mask real risk.

Severity: fail (per spec -- this is the most valuable depth-coverage signal).

Per-rule isolation: 400 responses (filter not supported on this console
version) are caught and reported as status='error' via status_code
branching -- never substring-match per CLAUDE.md.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 6: Implement R3 -- `op.asset_coverage.no_services_detected`

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/checks/test_asset_coverage.py`:

```python
# ----- R3: no_services_detected -----

def test_r3_no_services_detected_pass_when_empty(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "pass"
    assert rule.summary["no_services_count"] == 0


def test_r3_no_services_detected_warn_with_results(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    silent_assets = [_asset(f"silent-{i}", i) for i in range(7)]

    def paginate_post(path, json_body, params=None, page_size=500):
        # R3 is the rule whose body has BOTH service-count AND last-scan-date filters.
        fields = [f.get("field") for f in json_body.get("filters", [])]
        if "service-count" in fields and "last-scan-date" in fields:
            yield from silent_assets
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "warn"
    assert rule.summary["no_services_count"] == 7


def test_r3_no_services_detected_uses_two_filter_body(fake_client, app_config):
    """Body must combine service-count==0 AND last-scan-date is-within stale_asset_days."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    captured: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        captured.append(json_body)
        yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    AssetCoverageCheck().run(fc, app_config, snapshot=snap)

    r3_bodies = [
        b for b in captured
        if {"service-count", "last-scan-date"} <= {f.get("field") for f in b.get("filters", [])}
    ]
    assert len(r3_bodies) == 1
    body = r3_bodies[0]
    assert body["match"] == "all"
    assert len(body["filters"]) == 2
    sc_filter = next(f for f in body["filters"] if f["field"] == "service-count")
    assert sc_filter == {"field": "service-count", "operator": "is", "value": 0}
    ls_filter = next(f for f in body["filters"] if f["field"] == "last-scan-date")
    assert ls_filter["operator"] == "is-within-the-last"
    # Default fixture has stale_asset_days=30
    assert ls_filter["value"] == app_config.thresholds.asset_coverage.stale_asset_days


def test_r3_no_services_detected_skipped_when_disabled(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_no_services_detected=False,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.no_services_detected")
    assert rule.status == "skipped"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/checks/test_asset_coverage.py -k "r3_" -v 2>&1 | tail -20
```

Expected: 4 R3 tests fail.

- [ ] **Step 3: Add the rule method**

In `asset_coverage.py`, append `_no_services_detected` to the `run` method's rule list:

```python
        rule_results: list[RuleResult] = [
            self._stale_assets(client, t),
            self._never_scanned_assets(client, t),
            self._dead_asset_groups(snapshot, t),
            self._unauth_only_assets(client, t),
            self._no_services_detected(client, t),
        ]
```

Add the method:

```python
def _no_services_detected(self, client: Any, t) -> RuleResult:
    rid = "op.asset_coverage.no_services_detected"
    name = "Recently scanned assets with zero services detected"
    desc = (
        "Assets scanned within the stale-asset window but where the scan "
        "found zero services. Usually a firewall blocking the scan engine "
        "or a misconfigured site scope. Excludes already-stale assets to "
        "avoid double-counting with the stale_assets rule."
    )
    sources = [_SRC_FILTERED_SEARCH]

    if not t.flag_no_services_detected:
        return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

    rule_start = time.monotonic()
    body = {
        "filters": [
            {"field": "service-count", "operator": "is", "value": 0},
            {"field": "last-scan-date", "operator": "is-within-the-last", "value": t.stale_asset_days},
        ],
        "match": "all",
    }
    try:
        silent = list(client.paginate_post("/api/3/assets/search", json_body=body))
    except Rapid7ClientError as e:
        msg = (
            "filter not supported by this console version"
            if getattr(e, "status_code", None) == 400
            else str(e)[:200]
        )
        return RuleResult(
            rule_id=rid,
            rule_name=name,
            description=desc,
            severity="warn",
            status="error",
            findings=[Finding(severity="warn", message=msg)],
            summary={"no_services_count": 0, "error": msg},
            sources=sources,
            duration_ms=int((time.monotonic() - rule_start) * 1000),
        )

    findings: list[Finding] = []
    if silent:
        findings.append(Finding(
            severity="warn",
            message=f"{len(silent)} recently-scanned asset(s) with zero services detected",
            details={"total": len(silent), "examples": _example_hostnames(silent)},
        ))
    return make_rule_result(
        rule_id=rid,
        rule_name=name,
        description=desc,
        findings=findings,
        sources=sources,
        summary={"no_services_count": len(silent), "stale_asset_days": t.stale_asset_days},
        duration_ms=int((time.monotonic() - rule_start) * 1000),
    )
```

- [ ] **Step 4: Run R3 tests to verify they pass**

```bash
pytest tests/checks/test_asset_coverage.py -k "r3_" -v 2>&1 | tail -15
```

Expected: all 4 R3 tests pass.

- [ ] **Step 5: Run full file**

```bash
pytest tests/checks/test_asset_coverage.py -v 2>&1 | tail -30
```

Expected: R1 + R2 + R3 + existing tests all pass.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "feat(asset_coverage): add R3 no_services_detected rule

Combines service-count=0 AND last-scan-date is-within stale_asset_days
filters to surface assets that were recently scanned but where the scan
returned zero services -- typically a firewall blocking the engine or a
misconfigured site scope. The recency filter excludes already-stale
assets so we don't double-count with the stale_assets rule.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 7: Implement R4 -- `op.asset_coverage.agent_only_assets` (the gated, expensive one)

**Files:**
- Modify: `src/rapid7_healthcheck/checks/asset_coverage.py`
- Test: `tests/checks/test_asset_coverage.py`

**Why last among rules:** highest complexity (sampling, snapshot dependency, full_scan gate, per-asset GETs). All scaffolding is in place by now.

- [ ] **Step 1: Write the failing tests**

Append to `tests/checks/test_asset_coverage.py`:

```python
# ----- R4: agent_only_assets -----

def _enable_r4_via_full_scan(app_config):
    """Helper: flip the toggle on AND set audit.full_scan=True."""
    from dataclasses import replace
    return replace(
        app_config,
        audit=replace(app_config.audit, full_scan=True),
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_agent_only_assets=True,
            ),
        ),
    )


def test_r4_skipped_by_default(fake_client, app_config):
    """Default config has flag_agent_only_assets=false -- rule must be skipped."""
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_skipped_when_full_scan_off_even_if_toggle_on(fake_client, app_config):
    from dataclasses import replace
    cfg = replace(
        app_config,
        audit=replace(app_config.audit, full_scan=False),
        thresholds=replace(
            app_config.thresholds,
            asset_coverage=replace(
                app_config.thresholds.asset_coverage,
                flag_agent_only_assets=True,
            ),
        ),
    )
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[], agent_asset_ids={1, 2, 3})
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_skipped_when_agents_endpoint_unavailable(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[], agents_unavailable=True)
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "skipped"


def test_r4_pass_when_no_agents(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids=set(),
        included_targets=IncludedTargets(),
    )
    result = AssetCoverageCheck().run(fake_client, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "pass"
    assert rule.summary["agent_only_count"] == 0


def test_r4_pass_when_all_agents_inside_targets(fake_client, app_config):
    from ipaddress import ip_network
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    cfg = _enable_r4_via_full_scan(app_config)

    asset_details = {
        100: {"id": 100, "ip": "10.0.0.5", "hostName": "agent-a"},
        101: {"id": 101, "ip": "10.0.0.6", "hostName": "agent-b"},
    }

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def get(path, params=None):
        if path.startswith("/api/3/assets/"):
            aid = int(path.split("/")[-1])
            return asset_details[aid]
        raise AssertionError(f"unexpected GET: {path}")

    fc.get = get  # type: ignore[assignment]
    fc.set_paginate_post("/api/3/assets/search", [])

    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids={100, 101},
        included_targets=IncludedTargets(networks=[ip_network("10.0.0.0/24")], literals=set()),
    )
    result = AssetCoverageCheck().run(fc, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "pass"
    assert rule.summary["agent_only_count"] == 0


def test_r4_warn_when_agents_outside_targets(fake_client, app_config):
    from ipaddress import ip_network
    from rapid7_healthcheck.audit.snapshot import IncludedTargets
    cfg = _enable_r4_via_full_scan(app_config)

    asset_details = {
        200: {"id": 200, "ip": "172.16.0.1", "hostName": "outside-1"},
        201: {"id": 201, "ip": "172.16.0.2", "hostName": "outside-2"},
        202: {"id": 202, "ip": "10.0.0.5", "hostName": "inside"},
    }

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def get(path, params=None):
        if path.startswith("/api/3/assets/"):
            aid = int(path.split("/")[-1])
            return asset_details[aid]
        raise AssertionError(f"unexpected GET: {path}")

    fc.get = get  # type: ignore[assignment]
    fc.set_paginate_post("/api/3/assets/search", [])

    snap = _FakeSnapshot(
        asset_groups=[],
        agent_asset_ids={200, 201, 202},
        included_targets=IncludedTargets(networks=[ip_network("10.0.0.0/24")], literals=set()),
    )
    result = AssetCoverageCheck().run(fc, cfg, snapshot=snap)
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "warn"
    assert rule.summary["agent_only_count"] == 2
    examples = rule.findings[0].details["examples"]
    hostnames = {e["hostname"] for e in examples}
    assert hostnames == {"outside-1", "outside-2"}


def test_r4_errors_when_snapshot_missing(fake_client, app_config):
    cfg = _enable_r4_via_full_scan(app_config)
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, cfg)  # no snapshot
    rule = _rule(result, "op.asset_coverage.agent_only_assets")
    assert rule.status == "error"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/checks/test_asset_coverage.py -k "r4_" -v 2>&1 | tail -20
```

Expected: 7 R4 tests fail.

- [ ] **Step 3: Add the rule method + constant**

In `asset_coverage.py`, add the source constant near the top:

```python
_SRC_INSIGHT_AGENT = "https://docs.rapid7.com/insightvm/insight-agent-overview/"
```

Append to the rule list in `run`:

```python
        rule_results: list[RuleResult] = [
            self._stale_assets(client, t),
            self._never_scanned_assets(client, t),
            self._dead_asset_groups(snapshot, t),
            self._unauth_only_assets(client, t),
            self._no_services_detected(client, t),
            self._agent_only_assets(snapshot, client, t, config.audit),
        ]
```

Add the method:

```python
def _agent_only_assets(self, snapshot: Any, client: Any, t, audit_cfg) -> RuleResult:
    rid = "op.asset_coverage.agent_only_assets"
    name = "Insight Agent assets outside scheduled scan scope"
    desc = (
        "Assets reporting via Insight Agent whose IP falls outside every "
        "site's configured included_targets. These assets only get "
        "opportunistic agent data; they're never reached by scheduled scans."
    )
    sources = [_SRC_INSIGHT_AGENT]

    if not t.flag_agent_only_assets:
        return skipped_rule(rule_id=rid, rule_name=name, description=desc, sources=sources)

    if snapshot is None:
        return RuleResult(
            rule_id=rid,
            rule_name=name,
            description=desc,
            severity="warn",
            status="error",
            findings=[Finding(severity="warn", message="snapshot required but not provided to check")],
            summary={"agent_only_count": 0, "error": "snapshot required"},
            sources=sources,
        )

    if not audit_cfg.full_scan:
        return skipped_rule(
            rule_id=rid,
            rule_name=name,
            description=desc + " (Requires audit.full_scan=true to run.)",
            sources=sources,
        )

    if snapshot.is_agents_unavailable():
        return skipped_rule(
            rule_id=rid,
            rule_name=f"{name} (agents endpoint unavailable on this console)",
            description=desc,
            sources=sources,
        )

    rule_start = time.monotonic()
    agent_ids = snapshot.agent_asset_ids()
    targets = snapshot.all_included_targets()

    outsiders: list[dict] = []
    fetched_count = 0
    for aid in agent_ids:
        try:
            asset = client.get(f"/api/3/assets/{aid}")
        except Rapid7ClientError as e:
            logger.warning("agent_only_assets: skipping asset %s due to error: %s", aid, e)
            continue
        fetched_count += 1
        ip_str = asset.get("ip")
        if not ip_str:
            continue
        if not targets.contains(str(ip_str)):
            outsiders.append({
                "asset_id": aid,
                "ip": str(ip_str),
                "hostname": asset.get("hostName"),
            })

    findings: list[Finding] = []
    if outsiders:
        findings.append(Finding(
            severity="warn",
            message=f"{len(outsiders)} agent-managed asset(s) outside every site's scan scope",
            details={
                "total": len(outsiders),
                "examples": outsiders[:_EXAMPLES_LIMIT],
            },
        ))
    return make_rule_result(
        rule_id=rid,
        rule_name=name,
        description=desc,
        findings=findings,
        sources=sources,
        summary={
            "agent_only_count": len(outsiders),
            "total_agents_checked": fetched_count,
            "total_agents": len(agent_ids),
        },
        duration_ms=int((time.monotonic() - rule_start) * 1000),
    )
```

Add at the top of the file (only if not already present -- check first):

```python
import logging
logger = logging.getLogger(__name__)
```

- [ ] **Step 4: Run R4 tests to verify they pass**

```bash
pytest tests/checks/test_asset_coverage.py -k "r4_" -v 2>&1 | tail -25
```

Expected: all 7 R4 tests pass.

- [ ] **Step 5: Verify read-only contract one more time**

```bash
grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/rapid7_healthcheck/checks/asset_coverage.py
```

Expected: zero matches. (The new code uses `client.get(...)` which is GET -- verb-allowlisted.)

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "feat(asset_coverage): add R4 agent_only_assets rule (full_scan-gated)

Cross-references snapshot.agent_asset_ids() against
snapshot.all_included_targets() to surface Insight Agent-managed
assets that fall outside every site's configured scan scope. These
assets only get opportunistic agent data, never scheduled scans.

Defaults OFF (flag_agent_only_assets=false). Even when enabled,
short-circuits with skipped status when audit.full_scan=false (the
per-asset GET cost makes it inappropriate for the fast path) or
when the agents endpoint is unavailable on the target console.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 8: Wire `EnvSnapshot` through `__main__.py` to op-checks

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py` (the `_run_checks` function and its caller)
- Test: `tests/checks/test_asset_coverage.py` (integration-shape tests)

**Why now:** rules are implemented and tested in isolation. Now we close the loop so they actually receive a populated snapshot in production.

- [ ] **Step 1: Read the current `_run_checks` function**

```bash
grep -n -A 30 'def _run_checks' src/rapid7_healthcheck/__main__.py
```

Identify:
- where the snapshot is currently constructed (it's inside `ConfigurationAuditCheck.run` today -- needs to move out, or be passed in)
- the call site `instance.run(...)` where we'll thread `snapshot=...`

- [ ] **Step 2: Modify `_run_checks` to build the snapshot once**

Find this block in `__main__.py` (the per-check loop):

```python
def _run_checks(client: Any, cfg: AppConfig, progress: "ProgressReporter | None" = None) -> list[CheckResult]:
    results: list[CheckResult] = []
    total = len(_REGISTRY)
    for idx, (name, check_cls) in enumerate(_REGISTRY.items(), start=1):
        ...
```

Add snapshot construction **before** the loop:

```python
def _run_checks(client: Any, cfg: AppConfig, progress: "ProgressReporter | None" = None) -> list[CheckResult]:
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    # Single snapshot shared across audit and op-checks. Lazy-loads on first
    # access; methods cache. Built here (not per-check) so op-checks and audit
    # rules don't re-fetch /sites, /asset_groups, etc.
    snapshot = EnvSnapshot(
        client,
        full_scan=cfg.audit.full_scan,
        sample_size=cfg.audit.sample_size,
    )

    results: list[CheckResult] = []
    total = len(_REGISTRY)
    for idx, (name, check_cls) in enumerate(_REGISTRY.items(), start=1):
        ...
```

Then, **at the call site** where the check is invoked, pass `snapshot=snapshot`. The current logic branches on whether the check accepts `progress`:

```python
        try:
            # Audit orchestrators accept progress; operational checks don't.
            if name in ("configuration_audit", "user_permission_audit"):
                result = instance.run(client, cfg, progress=progress)
            else:
                result = instance.run(client, cfg)
```

Replace with:

```python
        try:
            # Audit orchestrators accept progress AND a snapshot; op-checks
            # accept the snapshot as an optional kwarg (only asset_coverage
            # uses it today, but signature is uniform).
            if name in ("configuration_audit", "user_permission_audit"):
                result = instance.run(client, cfg, progress=progress, snapshot=snapshot)
            else:
                result = instance.run(client, cfg, snapshot=snapshot)
```

> **Compatibility check:** `ConfigurationAuditCheck.run` and `UserPermissionAuditCheck.run` today build their own snapshot internally. Threading one in from `__main__` requires either:
> (a) updating both audit checks to accept (and prefer) an externally provided snapshot, or
> (b) leaving the audit checks alone and only threading snapshot into op-checks.
>
> **Recommendation: (b)** to keep this PR scoped. The duplicate snapshot construction in audit checks costs nothing (snapshot lazy-loads only what's accessed; the audit one and the op-check one will fetch the same data twice, but only on a real run, and only the bits each one accesses). Acceptable trade-off.
>
> **Revised replacement:**

```python
        try:
            if name in ("configuration_audit", "user_permission_audit"):
                # These checks build their own snapshot internally today.
                # Threading the shared one is a future cleanup (see backlog).
                result = instance.run(client, cfg, progress=progress)
            else:
                # Op-checks accept an optional snapshot; only asset_coverage
                # uses it currently.
                result = instance.run(client, cfg, snapshot=snapshot)
```

After this edit, append to `backlog.md` (gitignored) under a `0.2.8` or `someday` heading:

```markdown
## 0.2.8 / cleanup

- [cleanup] `__main__._run_checks` builds an `EnvSnapshot` for op-checks but the audit checks (`configuration_audit`, `user_permission_audit`) still build their own internally. Thread the shared one through and delete the duplicate construction. Saves one full snapshot's worth of repeated `/sites`, `/asset_groups`, `/agents` fetches per run.
```

(If `backlog.md` doesn't exist yet, create it.)

- [ ] **Step 3: Add integration-shape tests**

Append to `tests/checks/test_asset_coverage.py`:

```python
# ----- integration: shape, rollup, backwards-compat -----

def test_run_returns_six_rule_results(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert len(result.rule_results) == 6
    rule_ids = [r.rule_id for r in result.rule_results]
    assert rule_ids == [
        "op.asset_coverage.stale_assets",
        "op.asset_coverage.never_scanned_assets",
        "op.asset_coverage.dead_asset_groups",
        "op.asset_coverage.unauth_only_assets",
        "op.asset_coverage.no_services_detected",
        "op.asset_coverage.agent_only_assets",
    ]


def test_check_status_rolls_up_to_fail_when_any_rule_fails(fake_client, app_config):
    """One fail rule (R2 unauth_only) drives the check to fail."""
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    def paginate_post(path, json_body, params=None, page_size=500):
        if "vulnerability-assessed" in str(json_body):
            yield from [_asset(f"unauth-{i}", i) for i in range(3)]
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fc, app_config, snapshot=snap)
    assert result.status == "fail"


def test_check_status_pass_when_all_rules_pass(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    snap = _FakeSnapshot(asset_groups=[])
    result = AssetCoverageCheck().run(fake_client, app_config, snapshot=snap)
    assert result.status == "pass"


def test_optional_snapshot_kwarg_is_backwards_compatible(fake_client, app_config):
    """Calling without snapshot still works for client-only rules; snapshot-needing rules return error."""
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = AssetCoverageCheck().run(fake_client, app_config)  # no snapshot
    # Client-only rules complete normally
    assert _rule(result, "op.asset_coverage.stale_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.never_scanned_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.unauth_only_assets").status == "pass"
    assert _rule(result, "op.asset_coverage.no_services_detected").status == "pass"
    # Snapshot-dependent rules error cleanly (don't crash)
    assert _rule(result, "op.asset_coverage.dead_asset_groups").status == "error"
    # R4 is skipped because flag_agent_only_assets=False by default -- snapshot check never runs
    assert _rule(result, "op.asset_coverage.agent_only_assets").status == "skipped"
```

- [ ] **Step 4: Run integration tests**

```bash
pytest tests/checks/test_asset_coverage.py -v 2>&1 | tail -40
```

Expected: every test passes. The new integration tests + all R1-R4 tests + the original 4 tests = ~25 tests passing.

- [ ] **Step 5: Run the full suite**

```bash
pytest -v 2>&1 | tail -15
```

Expected: every test passes. Also confirm the count went up by ~25 from the baseline.

- [ ] **Step 6: Final read-only contract sweep**

```bash
grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/
```

Expected: zero matches in any file under `src/`.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py tests/checks/test_asset_coverage.py
git commit -m "feat(main): build EnvSnapshot once, pass to op-checks

Op-checks now receive an optional snapshot kwarg with a populated
EnvSnapshot, so AssetCoverageCheck's R1 (dead_asset_groups) and R4
(agent_only_assets) rules can read /asset_groups and /agents data
that the audit subsystem already lazy-loads.

Audit checks still build their own snapshot internally -- threading the
shared one through them is a deferred cleanup tracked in backlog.md.

Adds integration-shape tests confirming:
- Six rules in stable order
- Check-level status rolls up correctly
- Calling without a snapshot still works for the 4 client-only rules

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 9: README + CHANGELOG

**Files:**
- Modify: `README.md` (Asset Coverage section)
- Modify: `CHANGELOG.md` (Unreleased entry)

- [ ] **Step 1: Find the existing Asset Coverage rule table in README**

```bash
grep -n -A 10 'Asset Coverage' README.md | head -30
```

Identify the rule listing (likely a markdown table or bullet list). The exact format varies -- match the existing style.

- [ ] **Step 2: Extend the table/list with R1-R4**

Add (using the existing format):

| Rule ID | Description | Default severity | Source |
|---|---|---|---|
| `op.asset_coverage.stale_assets` | (existing) | warn | Filtered Asset Search |
| `op.asset_coverage.never_scanned_assets` | (existing) | fail | Filtered Asset Search |
| `op.asset_coverage.dead_asset_groups` | Asset groups whose criteria match zero members. Orphaned RBAC/report scopes. | warn | [Asset Groups](https://docs.rapid7.com/insightvm/asset-groups/) |
| `op.asset_coverage.unauth_only_assets` | Assets where vulnerability-assessed=false -- discovered but never authenticated. Surface-level visibility only. | **fail** | [Filtered Asset Search](https://docs.rapid7.com/insightvm/filtered-asset-search) |
| `op.asset_coverage.no_services_detected` | Assets recently scanned but with zero services detected. Usually firewall/scope misconfiguration. | warn | [Filtered Asset Search](https://docs.rapid7.com/insightvm/filtered-asset-search) |
| `op.asset_coverage.agent_only_assets` | Insight Agent-managed assets whose IP falls outside every site's scan scope. Default off; requires `audit.full_scan: true`. | warn | [Insight Agent Overview](https://docs.rapid7.com/insightvm/insight-agent-overview/) |

Adjust to match the exact existing format. **Don't** introduce a new table style if the README uses bullets.

- [ ] **Step 3: Add the CHANGELOG entry**

Find the `## [Unreleased]` heading in `CHANGELOG.md` (or create one above the most recent released version). Add:

```markdown
## [Unreleased]

### Added
- **Asset Coverage check expanded from 2 to 6 rules.** Adds:
  - `op.asset_coverage.dead_asset_groups` (warn) -- asset groups with zero members.
  - `op.asset_coverage.unauth_only_assets` (fail) -- assets discovered but never authenticated.
  - `op.asset_coverage.no_services_detected` (warn) -- recently scanned assets with zero services.
  - `op.asset_coverage.agent_only_assets` (warn, default off) -- Insight Agent assets outside scheduled scan scope. Requires `audit.full_scan: true`.
- New `AssetCoverageThresholds` toggles: `flag_dead_asset_groups`, `flag_unauth_only_assets`, `flag_no_services_detected`, `flag_agent_only_assets`. All default to `true` except the last (default `false`).
- `EnvSnapshot.all_included_targets()` accessor -- normalizes every site's included scan targets into CIDR networks + literal IPs with a `contains(ip_str)` helper. Used by the new `agent_only_assets` rule.

### Changed
- `Check` Protocol gains an optional `snapshot=None` kwarg. Existing checks continue to satisfy the protocol unchanged. `__main__._run_checks` now builds a single `EnvSnapshot` and passes it to checks that accept it.

### Read-only contract
- No new POST paths. No `client.py` changes. Verified via `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` → zero matches.
```

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document asset_coverage expansion (R1-R4)

- README: extend Asset Coverage rule table with the 4 new rules.
- CHANGELOG: Unreleased entry covering the rule additions, new
  config toggles, the new snapshot accessor, and the additive
  Check Protocol change. Notes the preserved read-only contract.

Refs spec 2026-05-04-asset-coverage-expansion."
```

---

## Task 10: Final verification

**No new files, no commits unless something fails.** This is a smoke-test pass.

- [ ] **Step 1: Run the entire test suite, verbose**

```bash
pytest -v 2>&1 | tail -30
```

Expected: every test passes. Compare the count against the pre-PR baseline -- should be up by approximately:
- 6 from `test_snapshot_targets.py`
- 5 from R1
- 5 from R2
- 4 from R3
- 7 from R4
- 4 integration-shape tests
- 1 config dataclass test
- = **~32 new tests**

- [ ] **Step 2: Run the read-only verification one final time**

```bash
grep -rnE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/
```

Expected: zero matches.

- [ ] **Step 3: Confirm `_ALLOWED_VERBS` and `_ALLOWED_POST_PATHS` were not changed**

```bash
grep -n '_ALLOWED_VERBS\|_ALLOWED_POST_PATHS' src/rapid7_healthcheck/client.py
```

Expected: same definitions as before this PR (`{"GET", "POST"}` and `{"/api/3/assets/search"}`).

- [ ] **Step 4: Confirm the example config still loads**

```bash
python -c "from rapid7_healthcheck.config import load_config; cfg = load_config('docs/examples/config.yaml'); print('loaded ok'); print('toggles:', cfg.thresholds.asset_coverage)"
```

Expected: prints `loaded ok` and the dataclass shows all 7 fields with the right defaults.

- [ ] **Step 5: Optional smoke test against a real console (if `R7_API_KEY` is set)**

```bash
python -m rapid7_healthcheck --config docs/examples/config.yaml --output /tmp/asset-coverage-smoke.html --verbose 2>&1 | tail -20
```

Expected: report renders, all 6 asset-coverage rules appear in the output, no stack traces. (Skip if no test environment is available.)

- [ ] **Step 6: Verify the design doc is committed**

```bash
git log --oneline -- docs/superpowers/specs/2026-05-04-asset-coverage-expansion-design.md
```

Expected: at least one commit shows up. If empty, commit the spec now:

```bash
git add docs/superpowers/specs/2026-05-04-asset-coverage-expansion-design.md
git commit -m "docs: add asset coverage expansion design spec"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Plan task |
|---|---|
| Goal: 4 new rules | Tasks 4-7 (one per rule) |
| Architecture: optional `snapshot` kwarg on `Check.run` | Task 1 |
| Snapshot threading via `__main__` | Task 8 |
| `AssetCoverageThresholds` 4 new toggles | Task 3 |
| R1 `dead_asset_groups` contract | Task 4 |
| R2 `unauth_only_assets` contract + 400-branching | Task 5 |
| R3 `no_services_detected` contract + two-filter body assertion | Task 6 |
| R4 `agent_only_assets` contract + full_scan gate + sampling | Task 7 |
| `all_included_targets()` accessor | Task 2 |
| Per-rule isolation, snapshot=None → status="error" | Tasks 4 (test), 7 (test), 8 (integration test) |
| Test plan (per-rule + integration) | Tasks 4-8 |
| Documentation impact (README, CHANGELOG, example config) | Tasks 3 + 9 |
| Acceptance criteria: 6 rule_results in order | Task 8 (integration test) |
| Acceptance: read-only contract preserved | Task 10 (final sweep) |

No spec requirements left without a task.

**Placeholder scan:** searched plan body for "TBD", "TODO", "implement later", "appropriate error handling" -- zero matches. (One legitimate "(if not already present)" hedge in Task 5/7 imports -- those are import deduplication checks, not placeholders.)

**Type consistency:**
- `IncludedTargets` defined in Task 2 (`networks: list`, `literals: set`, `contains(ip_str: str) -> bool`) -- referenced consistently in Task 7 tests and rule code.
- `_FakeSnapshot` defined in Task 4 -- extended (not re-defined) in Tasks 5-8 by adding constructor kwargs as needed.
- Rule IDs (`op.asset_coverage.dead_asset_groups`, etc.) used identically in tests, source code, README, and CHANGELOG.
- `flag_dead_asset_groups`, `flag_unauth_only_assets`, `flag_no_services_detected`, `flag_agent_only_assets` -- same names in dataclass (Task 3), rule code (Tasks 4-7), example YAML (Task 3), and tests (Tasks 4-7).
- `summary["dead_groups_count"]`, `["unauth_only_count"]`, `["no_services_count"]`, `["agent_only_count"]` -- used consistently across rule implementations and test assertions.

No type/name drift.
