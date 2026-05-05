# Parallel page fetching, page size 250, 60s default timeout

**Target version:** 0.2.8
**Status:** approved (brainstorming) — pending implementation
**Owner:** Phibu
**Date:** 2026-05-04

## Summary

Speed up `/api/3/assets/search` walks (the slow path on large InsightVM consoles)
by fetching pagination pages concurrently inside a single `paginate` /
`paginate_post` call. Bundle two related tunings observed during 0.2.7
production runs:

1. Default paginated page size 500 → **250** (timeouts observed at 500 against
   large filtered searches).
2. Default request timeout 30s → **60s** (matches the README troubleshooting
   guidance for hosted consoles).
3. New opt-in **parallel page fetching** (default off — `parallel_pages: 1`),
   tunable in `config.yaml` and at the per-call level.

The InsightVM API documents up to 8 parallel requests per console. The
**shipped default** is `parallel_pages: 1` (sequential, today's behavior) so
0.2.8 is bit-for-bit compatible without a config edit. Operators who tune up
to 6 (the user-stated comfortable concurrency) get the speedup. The config
validator accepts up to 16 for operators who know their console; values >8
emit a startup warning.

## Goals

- Cut wall-clock time of asset-search-heavy audit runs (today the dominant cost
  of `data_quality.py` and the new asset coverage rules) by fetching pages 1..N
  concurrently after the page-0 probe.
- Keep the **read-only contract** intact: zero new HTTP verbs, zero new POST
  paths.
- Keep today's **iteration ordering contract** intact: callers of
  `paginate` / `paginate_post` must see resources in strict page-0 → page-N
  order. Rules that early-exit on first hit (`agent_unauth_collision`) or rely
  on the `_PER_ITEM_FINDING_CAP=500` truncation pattern (asset coverage rules)
  must observe identical "first 500" sets.
- Keep today's **error semantics** intact: a paginate iteration either yields
  every resource or raises a `Rapid7ClientError`. No silent partial results.
- Be a **single-PR change**: contained to `client.py` plus config wiring; no
  Protocol changes, no rule edits, no test rewrites.

## Non-Goals

- **Rule-level parallelism.** Running multiple audit rules concurrently is out
  of scope; deferred to a future release.
- **Per-callsite tuning today.** No rule will be edited to pass
  `parallel_pages=N`. The instance default (driven from `config.yaml`) applies
  uniformly. Per-callsite override is *available* on the kwarg but unused at
  ship time.
- **Adaptive concurrency.** No 429-driven backoff of `parallel_pages`. The
  per-request retry path already handles rate-limit pressure correctly.
- **Async / `httpx` migration.** Out of scope. Sticking with `requests` +
  `concurrent.futures.ThreadPoolExecutor`.
- **Connection-pool tuning.** `requests.Session` defaults (10 conns/host) are
  comfortably above our worst-case `parallel_pages=6` and are not changed.

## Architecture

Single change to `Rapid7Client._paginate` in
[client.py](../../../src/rapid7_healthcheck/client.py). The current
`while page < total_pages` loop becomes a two-phase walk:

### Phase 1 — probe (page 0)

Fetch page 0 sequentially exactly as today. Read `page.totalPages` from the
response. Yield page 0's resources to the caller.

This phase is required: we don't know `totalPages` until page 0 lands, so we
can't dispatch parallel work without knowing how many pages exist.

### Phase 2 — parallel batches (pages 1..N-1)

If `total_pages > 1` and `effective_parallel > 1`:

- Open a `concurrent.futures.ThreadPoolExecutor(max_workers=effective_parallel)`
  scoped to the call (`with` block — torn down at end of iteration).
- Submit pages in **batches of size `effective_parallel`**: pages 1..K, then
  K+1..2K, etc. Within each batch, submit all `K` futures simultaneously.
- Collect results in **strict page-index order**: maintain a
  `dict[int, list[dict]]` keyed on page index; as futures complete, store; once
  all K futures in the batch are done (or one raises), yield resources in page
  order from the dict before moving to the next batch.

Why batches rather than a single one-shot fan-out across all pages: bounded
memory. A 50k-asset walk at page_size=250 is 200 pages; fanning out all 200
would buffer the entire result set in memory before any yield. Batched
fan-out yields page 0..K resources before pages K+1..2K are even submitted.

### Sequential fast path

If `effective_parallel == 1` *or* `total_pages == 1`, the executor is never
created. The function falls through to today's sequential `while` loop. This
is the **safe default** for 0.2.8 — every existing config preserves bit-for-bit
behavior.

### Error handling

When any future raises `Rapid7ClientError` (including `Rapid7AuthError`):

1. Call `executor.shutdown(wait=False, cancel_futures=True)` to abort pending
   futures (Python 3.9+; we require 3.11+).
2. Re-raise the original exception. Caller sees the same exception type they'd
   see today, possibly sooner.
3. In-flight futures that have already started their HTTP call may complete on
   their thread; their results are discarded.

The internal retry loop in `_request` (429/502/503/504 with exponential backoff
and `Retry-After`) is **unchanged** and runs on each worker thread independently
before that worker's future resolves. The parallel layer only sees terminal
outcomes (success or final raise).

### Read-only invariant

`_ALLOWED_VERBS` and `_ALLOWED_POST_PATHS` are unchanged. Every page fetch
goes through `_request`, which performs the verb/path check before any
network I/O. The check is stateless — concurrency does not weaken it.

`tests/test_readonly_invariant.py` (the static-scan suite) continues to pass
unchanged: no new `.put(`/`.patch(`/`.delete(` calls, no new `client.post(...)`
paths.

## Configuration surface

### `config.yaml`

```yaml
rapid7:
  base_url: "https://console.example.com:3780"
  auth_mode: "api_key"
  request_timeout_seconds: 60   # was 30
  max_retries: 3
  parallel_pages: 1             # NEW — pages fetched concurrently per paginate call
  page_size: 250                # NEW — default page size for paginated calls
```

### Validation (`config.py`)

- `parallel_pages`: int, range 1..16. Default 1. Values >8 emit a warning log
  on startup ("InsightVM documents 8 parallel requests as the supported limit;
  N exceeds this — proceed at your own risk").
- `page_size`: int, range 1..500. Default 250.
- `request_timeout_seconds`: existing field, default value bumped from 30 to 60.

Existing configs without the new keys load unchanged (defaults applied).

### `Rapid7Client.__init__`

Two new kwargs, both consumed from the config block above:

- `parallel_pages: int = 1`
- `default_page_size: int = 250`

The constructor stores these as `self._parallel_pages` and
`self._default_page_size`.

The existing `timeout_seconds` default in the constructor signature changes
from `30` to `60`.

### `paginate` / `paginate_post`

Both gain a new optional kwarg `parallel_pages: int | None = None`. When
`None` (the default), the instance's `_parallel_pages` is used. The existing
`page_size` kwarg gains a new default sentinel: when not provided by the
caller, `self._default_page_size` is used.

```python
def paginate_post(
    self,
    path: str,
    json_body: dict,
    params: dict | None = None,
    page_size: int | None = None,
    parallel_pages: int | None = None,
) -> Iterator[dict]:
    yield from self._paginate(
        "POST", path,
        params=params,
        page_size=page_size if page_size is not None else self._default_page_size,
        json_body=json_body,
        parallel_pages=parallel_pages if parallel_pages is not None else self._parallel_pages,
    )
```

Note: `paginate` and `paginate_post` *currently* default `page_size=500`
positionally. The new behavior is "default = instance default". To preserve
backwards compatibility for any external caller passing `page_size=500`
explicitly, the kwarg still accepts an explicit int — only the *implicit*
default changes.

`post_one` is unaffected (single request, no pagination).

## Logging

- Each page fetch (parallel or sequential) emits the existing
  `→ GET /api/3/...` / `← GET /api/3/... 200 in NNNms` debug lines via
  `_request`. Timestamps in the formatter let operators reconstruct ordering.
- One new INFO line per `_paginate` call when `effective_parallel > 1`:
  `paginating <path> with N pages, parallel=K`.
- No new redaction rules — `_summarize_params` already handles sensitive
  query params.
- The progress status-line in `__main__` (`[i/N] <name>`) is unaffected: it
  fires per-rule, not per-page.

## Testing

Three new tests in [tests/test_client.py](../../../tests/test_client.py):

1. **`test_parallel_paginate_yields_in_page_order`**
   Fake session returns three pages with scrambled completion timing
   (page 1 sleeps 50ms, page 2 sleeps 0ms, page 0 sleeps 25ms). Assert iterator
   yields resources in page-0, page-1, page-2 order regardless of completion
   order.

2. **`test_parallel_paginate_propagates_first_error`**
   Configure `parallel_pages=3`. Page 1 of 4 returns HTTP 500. Assert
   `Rapid7ClientError` raises with `status_code=500`, that the iterator does
   not yield page 1's or any later page's resources, and that page 0's
   resources *were* yielded (they came in via Phase 1 before the failure).

3. **`test_parallel_paginate_default_one_is_sequential`**
   With `parallel_pages=1` (the default), patch `ThreadPoolExecutor` at the
   `client` module level and assert it is **not** instantiated. Iteration
   yields the same resources in the same order as today's sequential walk.

Plus a config validator test:

4. **`test_config_parallel_pages_validation`** — `parallel_pages: 0` rejected,
   `parallel_pages: 17` rejected, `parallel_pages: 9` accepted with a warning
   log line, `parallel_pages: 6` accepted silently. Same shape for `page_size`
   bounds (1..500).

5. **`test_config_request_timeout_default_is_60`** — loading a `config.yaml`
   without `request_timeout_seconds` sets the field to 60.

The existing 419 tests must continue to pass with the default `parallel_pages=1`
(behavior bit-for-bit identical) and with the bumped page-size / timeout
defaults (no test asserts on the literal values 500 or 30 — verified before
implementation).

## Documentation

- [README.md](../../../README.md): "Troubleshooting" gains a bullet on
  `parallel_pages` (what it does, when to bump it, the 8-parallel API limit).
  The existing `request_timeout_seconds` bullet gets a sentence noting the
  default moved from 30 to 60.
- [docs/examples/config.yaml](../../../docs/examples/config.yaml): both new
  keys included with explanatory comments.
- [CLAUDE.md](../../../CLAUDE.md): "Layer rules" section gains a sentence
  noting that `_paginate` may run concurrently — `requests.Session` is
  thread-safe for read operations and we do not add explicit locks.
- [CHANGELOG.md](../../../CHANGELOG.md): entry under `[Unreleased]`
  documenting all three changes plus the default-bump as **breaking**
  (timeout 30→60 and page_size 500→250) so operators reading the changelog
  notice the behavior shift even when they don't touch `config.yaml`.

## Rollout

- **0.2.8** ships with `parallel_pages: 1` default. Behavior change is
  invisible to anyone who doesn't touch their `config.yaml`. The page_size
  drop and timeout bump *are* visible (slight uptick in HTTP request count,
  longer per-request timeout ceiling) but neither breaks anything.
- **0.2.9 or later**: revisit the default. If 0.2.8 ships cleanly and the
  user reports `parallel_pages: 6` working in production for a few weeks,
  bump the default to a conservative value (e.g. 4). Do not bump in 0.2.8.

## Open questions

None. All decisions made during brainstorming:
- Q1: parallel pages within one paginated call (a)
- Q2: hybrid opt-in via per-call `parallel_pages` kwarg (c)
- Q3: `concurrent.futures.ThreadPoolExecutor`, pool local per call (a)
- Q4: fail-fast with `cancel_futures=True` on first error (a)
- Q5: instance default + per-call override (c)

## Out-of-scope items captured for later

- Rule-level parallelism (Q1.b) — would need a global concurrency cap to
  avoid `parallel_pages * num_concurrent_rules` exceeding the documented
  8-parallel limit.
- Adaptive `parallel_pages` backoff on 429 — current `_retry_delay` handles
  per-request rate-limiting; tool-wide concurrency adaptation is more
  complex and not warranted yet.
- `httpx` / asyncio migration — would touch ~30 files (every check + every
  rule) and the entire test surface; not justified by the parallelism scope.

## Files touched (forecast)

| File | Change |
|------|--------|
| `src/rapid7_healthcheck/client.py` | New `_paginate_parallel` helper or inlined Phase-2 logic in `_paginate`; new constructor kwargs; `paginate` / `paginate_post` get `parallel_pages` kwarg; default `timeout_seconds` 30→60. |
| `src/rapid7_healthcheck/config.py` | New `parallel_pages` and `page_size` fields on the rapid7 config dataclass; validator updates; default `request_timeout_seconds` 30→60. |
| `docs/examples/config.yaml` | New keys with comments. |
| `tests/test_client.py` | 3 new tests. |
| `tests/test_config.py` | 2 new tests. |
| `README.md` | Troubleshooting bullet. |
| `CLAUDE.md` | Note in Layer rules section about thread-safety. |
| `CHANGELOG.md` | Entry under `[Unreleased]`. |

Estimated diff size: ~150 lines net add (mostly tests).
