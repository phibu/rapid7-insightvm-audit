# Rule Speedups: Per-Rule Credential Prefetch + Fleet-Coverage Fetch Drop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Speed up two confirmed-slow areas without changing any rule's output: (1) drop a wasted full-fleet fetch in the `insight_agent_deployed` rule; (2) collapse the per-site `site_credentials` N+1 in four credential rules (two Template-audit, two Configuration-audit) into one concurrent prefetch fan-out.

**Architecture:** Two independent optimizations, no API-client changes, read-only contract untouched.
1. **Fleet coverage:** `insight_agent_deployed` calls `snapshot.agents()` (fetches up to `sample_size` agent bodies, or the *entire fleet* under `full_scan`) but only uses the total count. Swap to `snapshot.agent_count()` — a `size=1` head-probe that reads `page.totalResources` only. Same output, same unavailable-skip path, zero bodies.
2. **Credential prefetch:** add one snapshot accessor `prefetch_site_credentials(site_ids)` mirroring the existing `prefetch_site_schedules` / `prefetch_site_included_targets`. Each of the four credential rules calls it at the top of its own `run()`, prefetching exactly the slice of site ids it is about to iterate. The shared `_prefetch_per_site` helper fans out across `client.parallel_pages` workers; the cache is shared within a category and idempotent, so rules with overlapping slices warm-then-reuse. This is the **per-rule prefetch** pattern (CONTEXT.md), the same technique `overlapping_scan_windows` already uses.

**Tech Stack:** Python 3.11+, pytest. No new dependencies. No HTTP-client changes (verb/path allowlist untouched).

## Global Constraints

- **Read-only contract (CLAUDE.md):** every API call must be `GET` or the lone allowlisted `POST /api/3/assets/search`. This plan adds only `GET` calls through the existing `_prefetch_per_site` → `client.get` path. Before each commit that touches `snapshot.py` or a rule file, the pre-commit check `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` must return zero matches.
- **Python floor:** 3.11. No 3.12-only syntax.
- **No behavior change:** every task preserves each rule's findings, summary, status, and error semantics exactly. Prefetch is a pure warm-up; the fleet-coverage swap reads the same count from the same endpoint family.
- **Per-rule prefetch is scoped to the rule, never the runner** (CONTEXT.md "Per-rule prefetch"): do NOT add prefetch to `AuditRunner` or `AuditCategory.prime`.
- **Cross-check before API use (CLAUDE.md):** `/api/3/sites/{id}/site_credentials` and `/api/3/agents` are both already used read-only in `snapshot.py`; no new endpoint is introduced.
- **Test-double parity:** `FakeSnapshot` (tests/audit/conftest.py) raises `AssertionError` on unregistered accessor calls. Any new `snapshot.prefetch_*` a rule calls must have a no-op on `FakeSnapshot` or existing rule tests break.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/rapid7_healthcheck/audit/snapshot.py` | The lazy data container; owns all per-site accessors + prefetch helpers | **Add** `prefetch_site_credentials(site_ids)` after `prefetch_site_included_targets` (line ~379) |
| `tests/audit/test_snapshot.py` | Snapshot accessor + prefetch unit tests | **Add** prefetch-credentials tests mirroring the schedules tests |
| `tests/audit/conftest.py` | `FakeSnapshot` test double | **Add** `prefetch_site_credentials` no-op (after line 173) |
| `src/rapid7_healthcheck/audit/rules/insight_agent_deployed.py` | Fleet-coverage rule | **Modify** line 29: `agents()` → `agent_count()` |
| `tests/audit/rules/test_insight_agent_deployed.py` | Fleet-coverage rule tests | **Add** a test proving no agent bodies are fetched |
| `src/rapid7_healthcheck/audit/template/rules/database_targets_no_db_credentials.py` | Template DB-cred rule | **Modify** `run()`: prefetch bound sites' credentials |
| `src/rapid7_healthcheck/audit/template/rules/web_spider_credentials_missing.py` | Template web-cred rule | **Modify** `run()`: prefetch bound sites' credentials |
| `src/rapid7_healthcheck/audit/rules/site_credential_centralization_candidates.py` | Config-audit centralization rule | **Modify** `run()`: prefetch all sites' credentials |
| `src/rapid7_healthcheck/audit/rules/duplicate_credential_clusters.py` | Config-audit duplicate-cluster rule | **Modify** `run()`: prefetch the (possibly sampled) scanned slice |
| `CHANGELOG.md` | Release notes | **Add** Unreleased entries |

**Decomposition rationale:** Task 1 (snapshot helper + its tests + the fake no-op) is the foundation every credential-rule task consumes. Tasks 2–5 are the four credential rules, each independently testable and reviewable — a reviewer could accept the Template pair and reject a Config rule (or vice-versa) without breaking the others. Task 6 (fleet coverage) is fully independent of the prefetch work and could even go first; it is ordered last only to keep the prefetch arc contiguous. Task 7 is docs.

---

## Task 1: Add `prefetch_site_credentials` snapshot accessor

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py` (add method after `prefetch_site_included_targets`, currently ending at line 379)
- Modify: `tests/audit/conftest.py` (add no-op to `FakeSnapshot` after line 173)
- Test: `tests/audit/test_snapshot.py`

**Interfaces:**
- Consumes: the existing private `EnvSnapshot._prefetch_per_site(site_ids, cache, fetch_one)` (snapshot.py:311) and the `self._site_credentials: dict[int, list[dict]]` cache (snapshot.py:178).
- Produces: `EnvSnapshot.prefetch_site_credentials(site_ids: list[int]) -> None` — concurrently warms `self._site_credentials` for each id in `site_ids` not already cached, by `GET /api/3/sites/{sid}/site_credentials` and storing `body.get("resources", [])`. Idempotent. After it returns, `site_credentials(sid)` is a cache hit for every prefetched `sid`. Tasks 2–5 call this.

- [ ] **Step 1: Write the failing tests**

Append to `tests/audit/test_snapshot.py`. These mirror the existing `test_prefetch_site_schedules_*` tests (test_snapshot.py:172) and reuse the in-file `_ConcurrentFakeClient` and `EnvSnapshot` already imported there.

```python
def test_prefetch_site_credentials_warms_cache_no_further_http():
    """After prefetch, site_credentials(sid) is a cache hit -- the per-site GET
    happens during prefetch, not on the accessor call."""
    c = _ConcurrentFakeClient(parallel_pages=4)
    for sid in (1, 2, 3):
        c.set_get(f"/api/3/sites/{sid}/site_credentials",
                  {"resources": [{"id": sid * 10, "name": f"cred-{sid}"}]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_credentials([1, 2, 3])
    calls_after_prefetch = len(c.get_calls)
    assert calls_after_prefetch == 3
    # Accessor calls now hit the warm cache -- no new HTTP.
    assert s.site_credentials(2) == [{"id": 20, "name": "cred-2"}]
    assert len(c.get_calls) == calls_after_prefetch


def test_prefetch_site_credentials_skips_already_cached_sites():
    """A site already in the credential cache is not re-fetched."""
    c = _ConcurrentFakeClient(parallel_pages=4)
    c.set_get("/api/3/sites/1/site_credentials", {"resources": [{"id": 11}]})
    c.set_get("/api/3/sites/2/site_credentials", {"resources": [{"id": 22}]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    # Warm site 1 via the accessor first.
    assert s.site_credentials(1) == [{"id": 11}]
    before = len(c.get_calls)
    s.prefetch_site_credentials([1, 2])  # only site 2 should be fetched
    assert len(c.get_calls) == before + 1


def test_prefetch_site_credentials_runs_concurrently_when_parallel_pages_gt_1():
    """With parallel_pages > 1, prefetch fans out rather than looping."""
    c = _ConcurrentFakeClient(parallel_pages=4, get_delay=0.02)
    for sid in range(1, 9):
        c.set_get(f"/api/3/sites/{sid}/site_credentials", {"resources": []})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_credentials(list(range(1, 9)))
    assert c.max_in_flight > 1


def test_prefetch_site_credentials_swallows_per_site_error_leaves_site_uncached():
    """A Rapid7ClientError on one site is swallowed; that site stays uncached
    so the later sequential accessor retries and surfaces the error in context."""
    from rapid7_healthcheck.client import Rapid7ClientError
    c = _ConcurrentFakeClient(parallel_pages=4)
    c.set_get("/api/3/sites/1/site_credentials", {"resources": [{"id": 11}]})
    c.set_get_raises("/api/3/sites/2/site_credentials",
                     Rapid7ClientError("boom", status_code=500))
    c.set_get("/api/3/sites/3/site_credentials", {"resources": [{"id": 33}]})
    s = EnvSnapshot(c, full_scan=False, sample_size=500)
    s.prefetch_site_credentials([1, 2, 3])
    # Sites 1 and 3 cached; site 2 was swallowed and is NOT cached.
    assert s.site_credentials(1) == [{"id": 11}]
    assert s.site_credentials(3) == [{"id": 33}]
    # Re-fetching site 2 now raises (the error surfaces in the accessor).
    import pytest
    with pytest.raises(Rapid7ClientError):
        s.site_credentials(2)
```

> **Note on `set_get_raises`:** the `_ConcurrentFakeClient` in `test_snapshot.py` already supports an error-injecting setter used by `test_prefetch_swallows_per_site_error_leaves_site_uncached` (test_snapshot.py:234). Confirm the method name in that file before running — if it is spelled differently (e.g. `set_get_error`), use that spelling in the test above. Do NOT invent a new fake; reuse the one the schedules error-test already uses.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/audit/test_snapshot.py -v -k prefetch_site_credentials`
Expected: 4 FAIL — `AttributeError: 'EnvSnapshot' object has no attribute 'prefetch_site_credentials'`.

- [ ] **Step 3: Add the accessor**

In `src/rapid7_healthcheck/audit/snapshot.py`, immediately after the `prefetch_site_included_targets` method (the method body ends at line 379 with `self._prefetch_per_site(site_ids, self._site_included_targets, _fetch)`), add:

```python
    def prefetch_site_credentials(self, site_ids: list[int]) -> None:
        """Concurrently warm the `site_credentials` cache for many sites.

        Peer of `prefetch_site_schedules` / `prefetch_site_included_targets`
        for `GET /api/3/sites/{id}/site_credentials`. After this returns,
        `site_credentials(sid)` is a cache hit for every prefetched site.
        Idempotent -- already-cached sites are skipped. The per-rule prefetch
        pattern (see CONTEXT.md): a credential rule calls this at the top of
        its `run()` with the exact slice of site ids it is about to iterate,
        collapsing an N+1 of per-site GETs into one `parallel_pages`-wide
        fan-out. A `Rapid7ClientError` on one site is swallowed and that site
        stays uncached, so the later sequential `site_credentials(sid)` retries
        it and surfaces the error in context.
        """
        def _fetch(sid: int) -> list[dict]:
            body = self._client.get(f"/api/3/sites/{sid}/site_credentials")
            return list(body.get("resources", []))

        self._prefetch_per_site(site_ids, self._site_credentials, _fetch)
```

- [ ] **Step 4: Add the `FakeSnapshot` no-op**

In `tests/audit/conftest.py`, immediately after the `prefetch_site_included_targets` no-op (line 171–173), add:

```python
    def prefetch_site_credentials(self, site_ids: list[int]) -> None:
        """No-op in tests -- see prefetch_site_schedules. FakeSnapshot
        credentials are pre-registered via set_site_credentials, so the cache
        the real prefetch warms is already populated."""
        return None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/audit/test_snapshot.py -v -k prefetch_site_credentials`
Expected: 4 PASS.

- [ ] **Step 6: Run the full snapshot + audit-conftest-dependent suite for regressions**

Run: `pytest tests/audit/ -v`
Expected: all PASS (the new `FakeSnapshot` no-op is additive; no existing test calls `prefetch_site_credentials` yet).

- [ ] **Step 7: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/test_snapshot.py tests/audit/conftest.py
git commit -m "feat(snapshot): add prefetch_site_credentials concurrent accessor"
```

---

## Task 2: Prefetch in `database_targets_no_db_credentials` (Template audit)

**Files:**
- Modify: `src/rapid7_healthcheck/audit/template/rules/database_targets_no_db_credentials.py` (inside `run()`, after the `template_to_sites` map is built, before the per-site credential loop)
- Test: `tests/audit/template/rules/test_database_targets_no_db_credentials.py`

**Interfaces:**
- Consumes: `snapshot.prefetch_site_credentials(site_ids: list[int])` from Task 1.
- Produces: nothing new (same `RuleResult`); behavior identical, only the credential GETs are now prefetched concurrently.

**Context:** `run()` currently builds `db_templates`, then `template_to_sites` (template_id → list of bound site dicts), then loops bound sites calling `snapshot.site_credentials(sid)` with a `break` on the first DB credential (database_targets_no_db_credentials.py:75–97). The prefetch must warm the **union of all bound site ids** before that loop, because the `break` means a sequential loop would otherwise fetch them one at a time.

- [ ] **Step 1: Write the failing test**

Append to `tests/audit/template/rules/test_database_targets_no_db_credentials.py`. This asserts the rule calls `prefetch_site_credentials` with the bound site ids before iterating. Use a spy `FakeSnapshot` subclass local to the test.

```python
def test_database_targets_prefetches_bound_site_credentials(monkeypatch):
    """The rule warms site_credentials for the union of DB-template-bound
    sites via one prefetch call before the per-site loop."""
    from rapid7_healthcheck.audit.template.rules.database_targets_no_db_credentials import (
        DatabaseTargetsNoDbCredentialsRule,
    )
    from tests.audit.conftest import FakeSnapshot  # adjust import to match the file's existing snapshot import

    snap = FakeSnapshot()
    # One template with a postgres DB target, bound to sites 1 and 2.
    snap.set_templates_full([
        {"id": "tpl-db", "name": "DB Audit", "database": {"postgres": "prod"}},
    ])
    snap.set_sites([
        {"id": 1, "name": "site-1", "scanTemplate": "tpl-db"},
        {"id": 2, "name": "site-2", "scanTemplate": "tpl-db"},
    ])
    snap.set_site_credentials(1, [])   # no DB cred
    snap.set_site_credentials(2, [])   # no DB cred

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    def _spy(site_ids):
        prefetched.append(list(site_ids))
        return orig(site_ids)
    snap.prefetch_site_credentials = _spy

    rule = DatabaseTargetsNoDbCredentialsRule()
    result = rule.run(snap, "warn", True, 500, {})

    # Prefetch was called once with both bound site ids.
    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2]
    # Behavior unchanged: the template is flagged (no DB creds on either site).
    assert result.summary["templates_flagged"] == 1
```

> **Note:** match the helper names (`set_templates_full`, `set_sites`, `set_site_credentials`) to the actual `FakeSnapshot` setters in `tests/audit/conftest.py`. If the test file uses a different snapshot fixture, follow that file's existing pattern — read the file's first existing test to copy its setup verbatim, then add the spy.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/audit/template/rules/test_database_targets_no_db_credentials.py -v -k prefetches`
Expected: FAIL — `assert len(prefetched) == 1` fails with `0 == 1` (the rule does not call prefetch yet).

- [ ] **Step 3: Add the prefetch call**

In `src/rapid7_healthcheck/audit/template/rules/database_targets_no_db_credentials.py`, locate the end of the `template_to_sites` construction loop (database_targets_no_db_credentials.py:75–80) and the line `findings: list[Finding] = []` that follows (line 82). Insert the prefetch between them:

```python
        template_to_sites: dict[str, list[dict]] = {}
        for site in snapshot.sites():
            tpl_id = EnvSnapshot.site_scan_template_id(site)
            if not tpl_id or tpl_id not in db_templates:
                continue
            template_to_sites.setdefault(tpl_id, []).append(site)

        # Per-rule prefetch (CONTEXT.md): warm the credential cache for every
        # bound site in one concurrent fan-out before the per-site loop below,
        # which otherwise issues N sequential GETs (the break-on-first-match
        # does not help when no site has a DB cred -- the worst case).
        bound_site_ids = [
            s.get("id")
            for sites in template_to_sites.values()
            for s in sites
            if s.get("id") is not None
        ]
        snapshot.prefetch_site_credentials(bound_site_ids)

        findings: list[Finding] = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/audit/template/rules/test_database_targets_no_db_credentials.py -v -k prefetches`
Expected: PASS.

- [ ] **Step 5: Run the full rule test file for regressions**

Run: `pytest tests/audit/template/rules/test_database_targets_no_db_credentials.py -v`
Expected: all PASS (the prefetch is transparent — `FakeSnapshot.prefetch_site_credentials` is a no-op and the pre-registered creds satisfy the loop unchanged).

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/template/rules/database_targets_no_db_credentials.py tests/audit/template/rules/test_database_targets_no_db_credentials.py
git commit -m "perf(template-audit): prefetch bound-site credentials in database_targets_no_db_credentials"
```

---

## Task 3: Prefetch in `web_spider_credentials_missing` (Template audit)

**Files:**
- Modify: `src/rapid7_healthcheck/audit/template/rules/web_spider_credentials_missing.py` (inside `run()`, after `template_to_sites` is built, before the per-site loop)
- Test: `tests/audit/template/rules/test_web_spider_credentials_missing.py`

**Interfaces:**
- Consumes: `snapshot.prefetch_site_credentials(site_ids)` from Task 1.
- Produces: nothing new (same `RuleResult`).

**Context:** Structurally identical to Task 2 — `run()` builds `web_enabled` templates, maps `template_to_sites` (web_spider_credentials_missing.py:46–51), then loops bound sites calling `snapshot.site_credentials(sid)` with `break` on first web-auth credential (lines 62–69). Same prefetch insertion.

- [ ] **Step 1: Write the failing test**

Append to `tests/audit/template/rules/test_web_spider_credentials_missing.py`:

```python
def test_web_spider_prefetches_bound_site_credentials():
    """The rule warms site_credentials for the union of web-enabled-bound
    sites via one prefetch call before the per-site loop."""
    from rapid7_healthcheck.audit.template.rules.web_spider_credentials_missing import (
        WebSpiderCredentialsMissingRule,
    )
    from tests.audit.conftest import FakeSnapshot  # adjust to the file's existing snapshot import

    snap = FakeSnapshot()
    snap.set_templates_full([
        {"id": "tpl-web", "name": "Web Audit", "webEnabled": True},
    ])
    snap.set_sites([
        {"id": 7, "name": "site-7", "scanTemplate": "tpl-web"},
        {"id": 8, "name": "site-8", "scanTemplate": "tpl-web"},
    ])
    snap.set_site_credentials(7, [])
    snap.set_site_credentials(8, [])

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    snap.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    rule = WebSpiderCredentialsMissingRule()
    result = rule.run(snap, "warn", True, 500, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [7, 8]
    assert result.summary["templates_flagged"] == 1
```

> Match `set_templates_full` / `set_sites` / `set_site_credentials` to the actual `FakeSnapshot` setters; copy the existing test's setup if the fixture differs.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/audit/template/rules/test_web_spider_credentials_missing.py -v -k prefetches`
Expected: FAIL — `0 == 1`.

- [ ] **Step 3: Add the prefetch call**

In `src/rapid7_healthcheck/audit/template/rules/web_spider_credentials_missing.py`, after the `template_to_sites` loop (web_spider_credentials_missing.py:46–51) and before `findings: list[Finding] = []` (line 53), insert:

```python
        # Per-rule prefetch (CONTEXT.md): warm the credential cache for every
        # web-enabled-bound site in one concurrent fan-out before the per-site
        # loop below.
        bound_site_ids = [
            s.get("id")
            for sites in template_to_sites.values()
            for s in sites
            if s.get("id") is not None
        ]
        snapshot.prefetch_site_credentials(bound_site_ids)

        findings: list[Finding] = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/audit/template/rules/test_web_spider_credentials_missing.py -v -k prefetches`
Expected: PASS.

- [ ] **Step 5: Run the full rule test file for regressions**

Run: `pytest tests/audit/template/rules/test_web_spider_credentials_missing.py -v`
Expected: all PASS.

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/template/rules/web_spider_credentials_missing.py tests/audit/template/rules/test_web_spider_credentials_missing.py
git commit -m "perf(template-audit): prefetch bound-site credentials in web_spider_credentials_missing"
```

---

## Task 4: Prefetch in `site_credential_centralization_candidates` (Configuration audit)

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/site_credential_centralization_candidates.py` (inside `run()`, after `sites = snapshot.sites()`, before the per-site loop)
- Test: `tests/audit/rules/test_site_credential_centralization_candidates.py`

**Interfaces:**
- Consumes: `snapshot.prefetch_site_credentials(site_ids)` from Task 1.
- Produces: nothing new (same `RuleResult`).

**Context:** This rule iterates `snapshot.site_credentials(sid)` over **every** site unconditionally (site_credential_centralization_candidates.py:59–61) — the largest `site_credentials` N+1 in the tool. Prefetch the full site-id list. Note the rule is `expensive = True` but does NOT sample (it always walks all sites), so the prefetch slice is always "all sites."

- [ ] **Step 1: Write the failing test**

Append to `tests/audit/rules/test_site_credential_centralization_candidates.py`:

```python
def test_centralization_prefetches_all_site_credentials():
    """The rule warms site_credentials for every site via one prefetch call
    before the per-site loop."""
    from rapid7_healthcheck.audit.rules.site_credential_centralization_candidates import (
        SiteCredentialCentralizationCandidatesRule,
    )
    from tests.audit.conftest import FakeSnapshot  # adjust to the file's existing snapshot import

    snap = FakeSnapshot()
    snap.set_sites([
        {"id": 1, "name": "a"},
        {"id": 2, "name": "b"},
        {"id": 3, "name": "c"},
    ])
    for sid in (1, 2, 3):
        snap.set_site_credentials(sid, [])
    snap.set_shared_credentials([])

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    snap.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    rule = SiteCredentialCentralizationCandidatesRule()
    rule.run(snap, "info", True, 500, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2, 3]
```

> Match `set_sites` / `set_site_credentials` / `set_shared_credentials` to the actual `FakeSnapshot` setters; copy the existing test's setup if it differs.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/audit/rules/test_site_credential_centralization_candidates.py -v -k prefetches`
Expected: FAIL — `0 == 1`.

- [ ] **Step 3: Add the prefetch call**

In `src/rapid7_healthcheck/audit/rules/site_credential_centralization_candidates.py`, the loop starts at line 59 (`for site in sites:`). Insert the prefetch immediately after `sites = snapshot.sites()` (line 53) and the two cache dicts are declared (lines 56–57), i.e. right before the `site_creds_examined = 0` line (line 58):

```python
        local_pattern = compile_local_pattern(rule_config)
        sites = snapshot.sites()

        # site_id -> set of credential keys, plus per-key the sites it appears in
        sites_by_key: dict[tuple, set] = defaultdict(set)
        examples_by_key: dict[tuple, dict] = {}

        # Per-rule prefetch (CONTEXT.md): this rule reads every site's
        # credentials, so warm the whole population in one concurrent fan-out
        # before the loop -- the single largest site_credentials N+1 in the tool.
        snapshot.prefetch_site_credentials(
            [s.get("id") for s in sites if s.get("id") is not None]
        )

        site_creds_examined = 0
        for site in sites:
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/audit/rules/test_site_credential_centralization_candidates.py -v -k prefetches`
Expected: PASS.

- [ ] **Step 5: Run the full rule test file for regressions**

Run: `pytest tests/audit/rules/test_site_credential_centralization_candidates.py -v`
Expected: all PASS.

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/rules/site_credential_centralization_candidates.py tests/audit/rules/test_site_credential_centralization_candidates.py
git commit -m "perf(config-audit): prefetch all site credentials in site_credential_centralization_candidates"
```

---

## Task 5: Prefetch in `duplicate_credential_clusters` (Configuration audit)

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/duplicate_credential_clusters.py` (inside `run()`, after `sites_to_scan` is computed, before the per-site loop)
- Test: `tests/audit/rules/test_duplicate_credential_clusters.py`

**Interfaces:**
- Consumes: `snapshot.prefetch_site_credentials(site_ids)` from Task 1.
- Produces: nothing new (same `RuleResult`).

**Context:** This rule **samples** in fast mode: `sites_to_scan = sites if site_cap is None else sites[:site_cap]` (duplicate_credential_clusters.py:43–44), then loops `snapshot.site_credentials(sid)` over `sites_to_scan` (lines 50–53). The prefetch slice must be **`sites_to_scan`, not all sites** — prefetching beyond the sampled slice would issue GETs the rule never uses, defeating the sample. This is the sampling-respect requirement from the per-rule-prefetch definition.

- [ ] **Step 1: Write the failing tests** (two: full-scan prefetches all; fast-mode prefetches only the sampled slice)

Append to `tests/audit/rules/test_duplicate_credential_clusters.py`:

```python
def test_duplicate_clusters_prefetches_scanned_slice_full_scan():
    """full_scan=True: prefetch covers every site."""
    from rapid7_healthcheck.audit.rules.duplicate_credential_clusters import (
        DuplicateCredentialClustersRule,
    )
    from tests.audit.conftest import FakeSnapshot  # adjust to the file's existing snapshot import

    snap = FakeSnapshot()
    snap.set_sites([{"id": i, "name": f"s{i}"} for i in (1, 2, 3, 4)])
    for sid in (1, 2, 3, 4):
        snap.set_site_credentials(sid, [])
    snap.set_shared_credentials([])

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    snap.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    DuplicateCredentialClustersRule().run(snap, "info", True, 500, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2, 3, 4]


def test_duplicate_clusters_prefetches_only_sampled_slice_fast_mode():
    """full_scan=False with sample_size=2: prefetch covers only the first 2
    sites -- it must NOT fetch credentials the sampled loop never reads."""
    from rapid7_healthcheck.audit.rules.duplicate_credential_clusters import (
        DuplicateCredentialClustersRule,
    )
    from tests.audit.conftest import FakeSnapshot

    snap = FakeSnapshot()
    snap.set_sites([{"id": i, "name": f"s{i}"} for i in (1, 2, 3, 4)])
    # Only register creds for the two sampled sites; if the rule prefetched
    # sites 3/4 it would call site_credentials on them -- but prefetch swallows
    # errors, so instead we assert on the prefetch slice directly.
    for sid in (1, 2):
        snap.set_site_credentials(sid, [])
    snap.set_shared_credentials([])

    prefetched: list[list[int]] = []
    orig = snap.prefetch_site_credentials
    snap.prefetch_site_credentials = lambda ids: (prefetched.append(list(ids)), orig(ids))[1]

    DuplicateCredentialClustersRule().run(snap, "info", False, 2, {})

    assert len(prefetched) == 1
    assert sorted(prefetched[0]) == [1, 2]
```

> Match the `FakeSnapshot` setters to the file's actual API; copy the existing test's setup if it differs.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/audit/rules/test_duplicate_credential_clusters.py -v -k prefetches`
Expected: 2 FAIL — `0 == 1`.

- [ ] **Step 3: Add the prefetch call**

In `src/rapid7_healthcheck/audit/rules/duplicate_credential_clusters.py`, after `sites_truncated` is computed (duplicate_credential_clusters.py:45) and before `members_by_key` is declared (line 48), insert:

```python
        # In fast mode, bound how many sites we enumerate; disclose truncation.
        site_cap = None if full_scan else sample_size
        sites_to_scan = sites if site_cap is None else sites[:site_cap]
        sites_truncated = 0 if site_cap is None else max(0, len(sites) - len(sites_to_scan))

        # Per-rule prefetch (CONTEXT.md): warm credentials for exactly the
        # slice this run will iterate -- sites_to_scan, NOT all sites -- so
        # fast-mode sampling is respected (no GET the loop never reads).
        snapshot.prefetch_site_credentials(
            [s.get("id") for s in sites_to_scan if s.get("id") is not None]
        )

        # key -> list of {source, name}
        members_by_key: dict[tuple, list[dict]] = defaultdict(list)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/audit/rules/test_duplicate_credential_clusters.py -v -k prefetches`
Expected: 2 PASS.

- [ ] **Step 5: Run the full rule test file for regressions**

Run: `pytest tests/audit/rules/test_duplicate_credential_clusters.py -v`
Expected: all PASS.

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/rules/duplicate_credential_clusters.py tests/audit/rules/test_duplicate_credential_clusters.py
git commit -m "perf(config-audit): prefetch sampled-slice credentials in duplicate_credential_clusters"
```

---

## Task 6: Drop the wasted fleet fetch in `insight_agent_deployed`

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/insight_agent_deployed.py:29`
- Test: `tests/audit/rules/test_insight_agent_deployed.py`

**Interfaces:**
- Consumes: `snapshot.agent_count() -> int` (snapshot.py:765) — the `size=1` head-probe that reads `page.totalResources` and sets `is_agents_unavailable()` on 404/502/503/504/timeout, identically to `agents()`.
- Produces: nothing new (same `RuleResult`); the rule no longer fetches agent record bodies.

**Context:** The rule currently does `agents, agents_total = snapshot.agents()` (insight_agent_deployed.py:29) and only ever uses `agents_total`; the `agents` list is discarded. Under `full_scan: true`, `snapshot.agents()` paginates the **entire** `/api/3/agents` fleet into memory — wasted work. `snapshot.agent_count()` returns the same total from a single `size=1` GET and primes the same `_agents_unavailable` flag, so the `is_agents_unavailable()` skip branch (insight_agent_deployed.py:31) is unaffected.

- [ ] **Step 1: Write the failing test**

Append to `tests/audit/rules/test_insight_agent_deployed.py`. The goal is to prove the rule reads the count without paginating agent bodies. Use the file's existing snapshot fake; if it distinguishes `agent_count()` from `agents()` call-tracking, assert `agents()` is never called. If the fake is a `FakeSnapshot` with an `agents()` that records calls, the cleanest assertion is a spy:

```python
def test_fleet_coverage_uses_count_not_body_fetch():
    """insight_agent_deployed reads agent_count() and never fetches agent
    bodies via agents()."""
    from rapid7_healthcheck.audit.rules.insight_agent_deployed import (
        InsightAgentDeployedRule,
    )
    from tests.audit.conftest import FakeSnapshot  # adjust to the file's existing snapshot import

    snap = FakeSnapshot()
    # set_agents([], total=40) sets the count agent_count() returns WITHOUT a
    # body sample (FakeSnapshot has no set_agent_count; agent_count() reads
    # _agents_total, which set_agents populates). is_agents_unavailable() stays
    # False (unavailable defaults to False).
    snap.set_agents([], total=40)
    snap.set_total_asset_count(100)   # for coverage math

    called = {"agents": 0, "agent_count": 0}
    orig_count = snap.agent_count
    snap.agent_count = lambda: (called.__setitem__("agent_count", called["agent_count"] + 1), orig_count())[1]
    def _boom():
        called["agents"] += 1
        raise AssertionError("agents() must not be called by fleet-coverage rule")
    snap.agents = _boom

    rule = InsightAgentDeployedRule()
    result = rule.run(snap, "info", True, 500, {})

    assert called["agents"] == 0
    assert called["agent_count"] >= 1
    # Coverage math unchanged: 40/100 = 40% -> below default 70% threshold -> one warn finding.
    assert result.summary["agents_total"] == 40
    assert result.summary["coverage_percent"] == 40.0
```

> **Adapt to the actual fake:** read the top existing test in `test_insight_agent_deployed.py` first. If `FakeSnapshot` has no `set_agent_count` / `set_total_asset_count`, use whatever setters it exposes for the agent total and asset total (the rule needs `agent_count()` and `total_asset_count()` to return numbers, and `is_agents_unavailable()` to be False). The spy on `agents`/`agent_count` is the portable part.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/audit/rules/test_insight_agent_deployed.py -v -k uses_count_not_body`
Expected: FAIL — `AssertionError: agents() must not be called` (current code calls `agents()` at line 29).

- [ ] **Step 3: Make the swap**

In `src/rapid7_healthcheck/audit/rules/insight_agent_deployed.py`, replace line 29:

```python
        agents, agents_total = snapshot.agents()
```

with:

```python
        # Read the fleet total from the cheap size=1 head-probe -- this rule
        # only needs the count, never the agent bodies. agent_count() primes
        # the same is_agents_unavailable() flag agents() did, so the skip
        # branch below is unaffected; under full_scan this drops a full-fleet
        # pagination to a single GET.
        agents_total = snapshot.agent_count()
```

> The variable `agents` (the discarded list) is removed. Confirm no later line in `run()` references `agents` — it does not (only `agents_total` is used, at lines 56–69). If a static check flags an unused import or name, none is introduced here.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/audit/rules/test_insight_agent_deployed.py -v -k uses_count_not_body`
Expected: PASS.

- [ ] **Step 5: Run the full rule test file for regressions**

Run: `pytest tests/audit/rules/test_insight_agent_deployed.py -v`
Expected: all PASS. **Watch for:** any existing test that registered an `agents()` sample and asserted on it — if a test set up `agents()` to return a specific sample and the rule no longer calls it, that test may now fail on an unused-registration assertion (if the fake is strict) or simply pass (if lenient). If one fails, update it to register `agent_count()` instead, matching the new contract. The unavailable-path test (`is_agents_unavailable()` True → skipped) must still pass unchanged, because `agent_count()` sets the same flag.

- [ ] **Step 6: Read-only check + commit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches.

```bash
git add src/rapid7_healthcheck/audit/rules/insight_agent_deployed.py tests/audit/rules/test_insight_agent_deployed.py
git commit -m "perf(config-audit): read fleet total via agent_count() not agents() in insight_agent_deployed"
```

---

## Task 7: Full suite + CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Run the entire test suite**

Run: `pytest -v`
Expected: all PASS across Python 3.11/3.12 (CI runs both; locally run whatever is installed).

- [ ] **Step 2: Final read-only audit**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: zero matches. Confirm `_ALLOWED_POST_PATHS` in both `client.py` and `cloud_client.py` is unchanged from `main`.

- [ ] **Step 3: Update CHANGELOG**

In `CHANGELOG.md`, under the `## [Unreleased]` section (create it below the top title if absent), add:

```markdown
### Changed
- **Performance:** the four credential audit rules (`database_targets_no_db_credentials`, `web_spider_credentials_missing`, `site_credential_centralization_candidates`, `duplicate_credential_clusters`) now prefetch each rule's site credentials in one concurrent fan-out (`prefetch_site_credentials`) instead of issuing one sequential `GET /api/3/sites/{id}/site_credentials` per site. Wall-clock for these rules drops by roughly the configured `parallel_pages` factor on consoles with many credentialed sites. Output, findings, and error semantics are unchanged; fast-mode sampling is respected (only the scanned slice is prefetched).
- **Performance:** the `insight_agent_deployed` ("Insight Agent Fleet Coverage") rule now reads the fleet total from a single `size=1` head-probe (`agent_count()`) instead of fetching agent record bodies (`agents()`). Under `full_scan: true` this drops a full `/api/3/agents` pagination to one request. Coverage math and the agents-unavailable skip path are unchanged.
```

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): credential prefetch + fleet-coverage fetch-drop speedups"
```

---

## Self-Review Notes

**Spec coverage (the five-rule investigation verdict):**
- ✅ Rule 1 — Insight Agent Fleet Coverage: `agents()` → `agent_count()` — Task 6.
- ✅ Rule 2 — Duplicate hostnames: no change (v3 has no group-by; already mitigated by `duplicate_detection_max_assets` ceiling; under-ceiling walk already inherits `parallel_pages`). **No task by design** — documented as a v3 gap, not a defect.
- ✅ Rule 3 — Duplicate IPs: same as Rule 2; shares the engine. **No task by design.**
- ✅ Rule 4 — Overlapping Scan Windows: already uses per-rule prefetch (the technique this plan generalizes); Pattern B inapplicable. **No task by design.**
- ✅ Rule 5 — Database Scan Targets Without DB Credentials: per-rule prefetch — Task 2; expanded to its three siblings sharing the `site_credentials` N+1 — Tasks 3, 4, 5.
- ✅ Snapshot accessor foundation — Task 1.
- ✅ CONTEXT.md "Per-rule prefetch" term — already added before this plan (out of plan scope; noted here for traceability).

**Placeholder scan:** No "TBD"/"handle errors"/"similar to Task N". Every code step shows the code; the only deferred specifics are the `FakeSnapshot` setter names, which are explicitly flagged as "match the file's existing fake" with the reason (the fake's API is established and varies per test file) — the implementer reads one existing test to copy setup. This is not a placeholder; it is an instruction to follow the established test pattern, which the writing-plans skill requires for existing codebases.

**Type consistency:**
- `prefetch_site_credentials(site_ids: list[int]) -> None` — defined Task 1, consumed identically in Tasks 2–5.
- `agent_count() -> int` — consumed Task 6, matches snapshot.py:765 signature.
- Prefetch slice expressions all filter `s.get("id") is not None` before passing ids — consistent across Tasks 2–5.
- All four rules return their existing `RuleResult` shape unchanged; no summary key is added or renamed.

**Read-only safety:** every task ends with the CLAUDE.md grep; no new verb or POST path is introduced; `_ALLOWED_POST_PATHS` untouched (Task 7 Step 2 asserts this explicitly).

**Ordering:** Task 1 is a hard prerequisite for 2–5 (they call the new accessor). Task 6 is independent and could run any time. Task 7 is last (full-suite gate + changelog). Tasks 2–5 are mutually independent and may be implemented/reviewed in any order once Task 1 lands.

**Regression risk flagged inline:** Task 6 Step 5 calls out the one place an existing test could break (a strict fake asserting on an `agents()` sample registration) and how to fix it. Tasks 2–5 carry near-zero regression risk because the prefetch is a no-op on `FakeSnapshot` and the per-site accessor still serves pre-registered creds.
