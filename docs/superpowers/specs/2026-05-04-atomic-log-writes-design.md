# Atomic Log Writes for `--log-file`, with HTTP-Layer Visibility

**Date:** 2026-05-04
**Status:** Approved (brainstorm complete, awaiting implementation plan)

## Goal

When `--log-file <path>` is set, two things become true:

1. **Every HTTP request issued by `client.py` is logged** at DEBUG level: method, path, query params (sanitized), status code, elapsed time, retry count if any. Non-200 responses log a body snippet (capped at ~200 chars).
2. **Every log line is flushed to disk immediately** so `tail -f <log>` shows live progress during long-running audits.

The driving use case is diagnosing long-running or hung audits -- the recent `agent_unauth_collision` 21-minute timeout is the motivating example. With this change, the user can tail the log mid-run and see exactly which API call the run is hanging on.

## Background

Today the tool's logging is sparse: ~28 calls across 5 files, mostly at the per-check granularity (`logger.info("running check: %s", instance.name)` in `__main__.py`) plus error paths. Inside an individual check or audit rule, no logging happens. The HTTP layer (`client.py`) does not log requests at all.

The `--log-file <path>` and `--verbose` flags already exist, and Python's `logging.FileHandler` is wired up in `_setup_logging()`. But two things break the live-tailing story:

- The HTTP layer is silent, so even at DEBUG verbosity the log file does not show which API call is in flight.
- `logging.FileHandler` uses Python's default OS-level file buffering, so log lines may sit in a buffer for seconds (or until the process ends) before reaching disk. `tail -f` on the log file shows nothing useful while the run is in progress.

## Design

### 1. `FlushingFileHandler` -- new module `src/rapid7_healthcheck/_log.py`

Tiny new module containing:

```python
from __future__ import annotations
import logging


class FlushingFileHandler(logging.FileHandler):
    """FileHandler that flush()es after every emit().

    Trades ~microseconds per record for live-tail visibility; appropriate
    for long-running audits where the user wants to see progress in real
    time. Used in place of logging.FileHandler when --log-file is set.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()
```

Replaces `logging.FileHandler` in the `if log_file:` branch of `_setup_logging()` in `__main__.py`. Single-line swap.

The stderr handler (`logging.StreamHandler(sys.stderr)`) is unchanged -- Python's stderr is already line-buffered (or unbuffered) by default and does not need wrapping.

### 2. HTTP request logging in `client.py`

`client.py` is the single chokepoint where every API call passes through. Add structured log lines around each request:

- **Before request** (DEBUG):
  `logger.debug("→ %s %s%s", method, path, querystring_summary)`
  `querystring_summary` is `""` when no params, otherwise `"?" + sanitized_kv_pairs` (sensitive keys redacted -- see edge case below).

- **After successful response** (DEBUG):
  `logger.debug("← %s %s %d in %dms", method, path, status_code, elapsed_ms)`

- **On retry** (DEBUG):
  `logger.debug("retry %d/%d for %s %s after %ds (Retry-After)", attempt, max_attempts, method, path, wait_s)`

- **On error response** (WARNING -- non-retried 4xx/5xx that becomes a `Rapid7ClientError`):
  `logger.warning("✗ %s %s %d: %s", method, path, status_code, body_snippet[:200])`
  This logs at the boundary so the user sees the failure in the log file *before* the exception propagates up the stack.

The `→`, `←`, `✗` glyphs are deliberate visual markers -- they scan well in a tailed log and are consistent with curl/HTTPie conventions. UTF-8 encoding (the file handler already specifies `encoding="utf-8"`).

#### Querystring summary helper

A small helper in `client.py` (or `_log.py` if cleaner) formats a params dict as `?k1=v1&k2=v2` with a defensive sanitizer that redacts any key whose lowercased name contains `key`, `token`, `secret`, `password`, or `auth`. Replacement value is `***`. Output is also length-capped at 200 chars to keep log lines bounded.

Headers (where the actual API key lives) are NEVER logged -- only the URL and querystring. This is enforced by *what we log* (we don't construct a header-stringification helper at all), not by sanitizer.

### 3. Default verbosity

- **Without `--verbose`** (effective level INFO): the existing per-check INFO lines plus the new HTTP error/warning lines. Successful API calls stay quiet.
- **With `--verbose`** (effective level DEBUG): every API call gets `→` and `←` lines. This is the mode the user enables when diagnosing a hang.

The flush behavior is a property of the file handler, not the log level, and applies regardless of verbosity. INFO-level audit runs without `--verbose` will still be tail-able -- they just have less to tail.

## Edge cases

- **`--log-file` not set** → no `FlushingFileHandler` is added; only the stderr handler runs (unchanged behavior). Existing users who don't use `--log-file` see zero behavioral change.
- **Sensitive params in URL** → `client.py` does not put credentials in URLs (the API key is a header), and the search endpoint passes its filter criteria in the body, not the querystring. The sanitizer is defense-in-depth: any future endpoint that accidentally accepts an `api_key=` query param would still get redacted.
- **Body snippet on 4xx/5xx** → capped at 200 chars in the log line. `client.py` already truncates bodies in `Rapid7ClientError` messages to ~1500 chars; the log-line cap is tighter to keep tailed output skimmable.
- **Pre-config logging** → `_setup_logging` is called twice in `__main__.py` (once with `log_file=None` before config loads, then again with the resolved path). The second call must replace, not duplicate, the file handler. The existing code calls `logging.basicConfig(...)` which respects `force=True` if used; verify that the second call cleans up the first set of handlers (current code uses `basicConfig` which honors handler replacement only with `force=True`). If not already set, add `force=True` to the `basicConfig` call.
- **High-volume DEBUG logging cost** → at DEBUG with `--log-file`, an audit run may emit thousands of API-call lines × per-line `flush()`. Estimated overhead: microseconds per line × thousands of lines ≈ tens of milliseconds total. Negligible compared to the tool's network-bound runtime (minutes).

## Out of scope

- **Rule/check-level DEBUG logging.** Each audit rule could emit "examining site 47", "computing freshness for site 47" lines. Deferred -- the per-check INFO line plus HTTP-level DEBUG is enough narrative for the diagnosis use case. If we later want per-call rule context (which rule was responsible for which API call), the HTTP-call log line is a natural place to attach a `rule_id=...` extra. Cheap follow-up.
- **Structured / JSON log output.** Plain-text human-readable lines only. JSON would be useful for machine ingestion but is gratuitous complexity for the live-tailing use case.
- **Log rotation.** The file is whatever path the user passes; if it grows large, that's the user's choice (and the tool runs once per audit, not as a daemon).
- **CLI knob to toggle flush behavior.** Decision C from brainstorming Q3 was rejected -- the only people writing to a log file are people who want to read it, and they almost certainly want it tail-able. Unconditional flush.
- **Logging request/response bodies in full.** Only error-response body snippets, capped. Successful response bodies are not logged (they would dominate the log file).
- **Configurable log format / format strings.** The format set by the existing `logging.basicConfig(format=...)` stays unchanged.

## Files touched

| File | Change |
|---|---|
| `src/rapid7_healthcheck/_log.py` | NEW -- `FlushingFileHandler` class. ~12 lines including docstring. |
| `src/rapid7_healthcheck/__main__.py` | In `_setup_logging`, swap `logging.FileHandler` for `FlushingFileHandler`. Add `force=True` to `basicConfig` call if not already there. |
| `src/rapid7_healthcheck/client.py` | Add DEBUG log lines around request and retry paths. Add WARNING log line on non-retried error responses. New private helper `_summarize_params(params: dict | None) -> str` for sanitized querystring formatting. |
| `tests/test_log_flush.py` | NEW -- verifies `FlushingFileHandler.emit` calls `flush`. ~20 lines. |
| `tests/test_client.py` (or the existing client test file -- verify name first) | Add tests: (a) successful request emits DEBUG `→` + `←`; (b) 404 emits WARNING `✗` with status + body snippet; (c) retry emits DEBUG retry line; (d) sanitizer redacts sensitive keys. Use `caplog` fixture. |
| `README.md` | Add one sentence under the logging section: "When `--log-file` is set, every HTTP request is logged at DEBUG level (use `--verbose` to see them) and every log line is flushed immediately so the file can be tailed live during long audits." |
| `CHANGELOG.md` | One bullet under upcoming version: "Live-tailable log file with HTTP-request visibility (use `--log-file <path>` + `--verbose` to see every API call as it happens)." |

## Test plan

1. **`FlushingFileHandler` flushes on emit** -- instantiate handler against a tmp file, log a record, assert the file content is on disk *before* the handler is closed (read the file in a separate file handle and assert the line is there).
2. **Successful GET emits a DEBUG line** -- using the existing client test fixtures (mocked HTTP), make a GET and assert `caplog.records` contains a DEBUG record matching `→ GET /api/3/...` and another matching `← GET /api/3/... 200`.
3. **404 emits a WARNING line** -- mock a 404 response; assert a WARNING record contains `✗`, the status code `404`, and a body snippet substring.
4. **Retry emits a DEBUG line** -- mock a 429 response with `Retry-After: 1` followed by a 200; assert a `retry 1/` DEBUG record appears.
5. **Querystring sanitizer drops sensitive keys** -- call the helper with `{"q": "x", "api_key": "secret", "auth_token": "abc"}`; assert `"secret"` and `"abc"` do NOT appear in the output, and `"***"` does. Also assert the helper output is capped at 200 chars when given many keys.
6. **`--log-file` not set → no FlushingFileHandler** -- call `_setup_logging(verbose=True, log_file=None)`, assert no instance of `FlushingFileHandler` in `logging.root.handlers`.
7. **Re-init replaces handlers** -- call `_setup_logging(verbose=False, log_file=None)` then `_setup_logging(verbose=True, log_file=tmp_path)`; assert exactly one `FlushingFileHandler` and one `StreamHandler` in `logging.root.handlers` (no leftover handlers from the first call).

## Acceptance criteria

- All new and existing tests pass; full `pytest -v` is green.
- Manual smoke test: `python -m rapid7_healthcheck --verbose --log-file /tmp/r7.log` against a real environment, tail `/tmp/r7.log` in another terminal, observe API call lines appearing in real time as the run progresses (not buffered until the end).
- Read-only invariant intact: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/` returns no new matches. (This change only logs requests; it does not add any.)
- No credential leak: test #5 passes; manual scan of a real run's log file shows no API key value, no Basic Auth password, no sensitive header content.
- CHANGELOG entry merged under the upcoming version.
