# Atomic Log Writes + HTTP-Layer Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `--log-file <path>` log live-tailable during long-running audits by flushing every record to disk on emit, and add per-HTTP-request visibility (DEBUG for success, WARNING for non-retried errors) so users can see exactly which API call a hung run is on.

**Architecture:** One tiny new module (`_log.py`) holds a `FlushingFileHandler` subclass; `__main__.py` swaps it in for `logging.FileHandler` in `_setup_logging`. `client.py`'s `_request()` is the single chokepoint for HTTP I/O — augment its existing log lines (one already exists at line 198) with a `→`/`←`/`✗`/retry vocabulary plus a sanitized querystring helper.

**Tech Stack:** Python 3.11+ stdlib `logging`, `requests` (for the HTTP layer this wraps), pytest with `caplog` fixture.

---

## Pre-flight

- [ ] **Step 0.1: Confirm baseline tests pass before any edits**

Run: `pytest -v 2>&1 | tail -3`
Expected: 376 passed (or higher if more landed since 2026-05-04). If anything is red on `main`, stop and surface — don't layer changes on a broken baseline.

- [ ] **Step 0.2: Read-only invariant baseline**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: no matches. Establishes the line we must not cross. (This entire plan only adds logging; it cannot violate this invariant, but verify anyway per CLAUDE.md.)

---

## Task 1: `FlushingFileHandler` — failing test first

**Files:**
- Test: `tests/test_log_flush.py` (NEW)

- [ ] **Step 1.1: Create the new test file**

Create `tests/test_log_flush.py` with the following contents (verbatim):

```python
from __future__ import annotations

import logging
from pathlib import Path

from rapid7_healthcheck._log import FlushingFileHandler


def test_flushing_file_handler_writes_to_disk_on_each_emit(tmp_path: Path):
    """A record logged via FlushingFileHandler must be readable from disk
    immediately, before the handler is closed — proves we're flushing."""
    log_path = tmp_path / "live.log"
    handler = FlushingFileHandler(str(log_path), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Log a record. Do NOT close the handler.
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello-from-flush", args=(), exc_info=None,
    )
    handler.emit(record)

    # Read the file from a separate handle while the handler is still open.
    # If flush() is not called inside emit(), this will see an empty (or
    # incomplete) file because OS-level buffering hasn't released the data.
    contents = log_path.read_text(encoding="utf-8")
    assert "hello-from-flush" in contents

    handler.close()


def test_flushing_file_handler_is_a_filehandler_subclass():
    """Sanity check: behaves like a normal FileHandler for the rest of the
    Logging stack (level, formatter, baseFilename, etc.)."""
    assert issubclass(FlushingFileHandler, logging.FileHandler)
```

- [ ] **Step 1.2: Run the new test, expect FAIL (module doesn't exist yet)**

Run: `pytest tests/test_log_flush.py -v`
Expected: `ModuleNotFoundError: No module named 'rapid7_healthcheck._log'` (collection error). Both tests are RED via missing import.

---

## Task 2: `FlushingFileHandler` — implementation

**Files:**
- Create: `src/rapid7_healthcheck/_log.py`

- [ ] **Step 2.1: Create the module**

Create `src/rapid7_healthcheck/_log.py` with the following contents (verbatim):

```python
"""Logging helpers internal to rapid7_healthcheck.

Public surface:
    FlushingFileHandler — drop-in for logging.FileHandler that flushes the
        underlying stream after every emit, so a tailed log file shows live
        progress during long-running audits.
"""
from __future__ import annotations

import logging


class FlushingFileHandler(logging.FileHandler):
    """FileHandler that flush()es after every emit().

    Trades ~microseconds per record for live-tail visibility. Used in
    place of logging.FileHandler when --log-file is set so the user can
    `tail -f` the log mid-run and see API calls as they happen.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()
```

- [ ] **Step 2.2: Re-run the test, expect PASS**

Run: `pytest tests/test_log_flush.py -v`
Expected: both tests PASS.

- [ ] **Step 2.3: Commit Task 1+2 together**

```bash
git add src/rapid7_healthcheck/_log.py tests/test_log_flush.py
git commit -m "feat(log): add FlushingFileHandler for live-tailable log file"
```

---

## Task 3: Wire `FlushingFileHandler` into `_setup_logging`

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py`
- Test: `tests/test_log_flush.py`

- [ ] **Step 3.1: Append two integration tests to `tests/test_log_flush.py`**

Append to `tests/test_log_flush.py`:

```python
import logging as _logging  # noqa: E402  (deliberately separate import for clarity below)

from rapid7_healthcheck.__main__ import _setup_logging  # noqa: E402


def test_setup_logging_uses_flushing_file_handler_when_log_file_set(tmp_path):
    """When _setup_logging is called with a log_file path, the resulting
    root logger handlers must include a FlushingFileHandler (NOT a plain
    logging.FileHandler)."""
    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path))

    file_handlers = [
        h for h in _logging.root.handlers
        if isinstance(h, _logging.FileHandler)
    ]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0], FlushingFileHandler), (
        f"expected FlushingFileHandler, got {type(file_handlers[0]).__name__}"
    )


def test_setup_logging_no_file_handler_when_log_file_none(tmp_path):
    """Without --log-file, only the stderr StreamHandler runs; no
    FileHandler-of-any-kind is added."""
    _setup_logging(verbose=True, log_file=None)

    file_handlers = [
        h for h in _logging.root.handlers
        if isinstance(h, _logging.FileHandler)
    ]
    assert file_handlers == []
```

- [ ] **Step 3.2: Run the two new tests, expect FAIL**

Run: `pytest tests/test_log_flush.py::test_setup_logging_uses_flushing_file_handler_when_log_file_set -v`
Expected: FAIL — `_setup_logging` currently uses `logging.FileHandler`, not our subclass; the `isinstance(...,  FlushingFileHandler)` assertion fails.

- [ ] **Step 3.3: Swap `FileHandler` → `FlushingFileHandler` in `_setup_logging`**

In `src/rapid7_healthcheck/__main__.py`, find this line (currently around line 65):

```python
            handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
```

Replace it with:

```python
            handlers.append(FlushingFileHandler(log_file, encoding="utf-8"))
```

Then add the import at the top of the file. Find the existing import block (the `import logging` line, around line 4) and add directly after `from pathlib import Path`:

```python
from rapid7_healthcheck._log import FlushingFileHandler
```

(If the import order in the file groups stdlib + third-party + local, place this in the local-imports group near the other `from rapid7_healthcheck.*` imports — read the surrounding 5 lines to find the right block.)

- [ ] **Step 3.4: Re-run the two integration tests, expect PASS**

Run: `pytest tests/test_log_flush.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 3.5: Run the full suite to confirm no regression**

Run: `pytest -v 2>&1 | tail -5`
Expected: same pass count as baseline + 4 new tests, all green.

- [ ] **Step 3.6: Commit Task 3**

```bash
git add src/rapid7_healthcheck/__main__.py tests/test_log_flush.py
git commit -m "feat(log): use FlushingFileHandler in _setup_logging when --log-file is set"
```

---

## Task 4: Querystring sanitizer helper

**Files:**
- Modify: `src/rapid7_healthcheck/client.py`
- Test: `tests/test_client.py`

This task adds a private helper `_summarize_params` that formats a params dict into a sanitized, length-capped querystring suitable for log lines. It's a pure function with no side effects — easy to TDD.

- [ ] **Step 4.1: Append failing tests to `tests/test_client.py`**

Append to `tests/test_client.py`:

```python
from rapid7_healthcheck.client import _summarize_params


def test_summarize_params_none_returns_empty_string():
    assert _summarize_params(None) == ""


def test_summarize_params_empty_dict_returns_empty_string():
    assert _summarize_params({}) == ""


def test_summarize_params_basic_kv_pairs():
    out = _summarize_params({"page": 0, "size": 100})
    # Order may vary (dict iteration is insertion-order in 3.7+, but be
    # tolerant). Both keys + values appear, prefixed with "?".
    assert out.startswith("?")
    assert "page=0" in out
    assert "size=100" in out


def test_summarize_params_redacts_sensitive_keys():
    """Defense-in-depth: any key whose lowercased name contains
    'key', 'token', 'secret', 'password', or 'auth' must be redacted."""
    out = _summarize_params({
        "q": "x",
        "api_key": "MUST-NOT-LEAK-1",
        "auth_token": "MUST-NOT-LEAK-2",
        "user_password": "MUST-NOT-LEAK-3",
        "session_secret": "MUST-NOT-LEAK-4",
        "X-Api-Key": "MUST-NOT-LEAK-5",
    })
    assert "MUST-NOT-LEAK-1" not in out
    assert "MUST-NOT-LEAK-2" not in out
    assert "MUST-NOT-LEAK-3" not in out
    assert "MUST-NOT-LEAK-4" not in out
    assert "MUST-NOT-LEAK-5" not in out
    assert "***" in out
    assert "q=x" in out  # non-sensitive keys still appear


def test_summarize_params_caps_output_at_200_chars():
    """Long params dicts get truncated with an ellipsis marker so log
    lines stay scannable."""
    big = {f"k{i}": f"v{i}" for i in range(100)}
    out = _summarize_params(big)
    assert len(out) <= 200
```

- [ ] **Step 4.2: Run the new tests, expect FAIL (helper doesn't exist)**

Run: `pytest tests/test_client.py -k "summarize_params" -v`
Expected: `ImportError: cannot import name '_summarize_params'` (collection error). All 5 tests RED.

- [ ] **Step 4.3: Add the helper to `client.py`**

In `src/rapid7_healthcheck/client.py`, near the top of the file (after the imports and any module-level constants like `_ALLOWED_VERBS`, but before the `Rapid7Client` class definition), add:

```python
_SENSITIVE_PARAM_SUBSTRINGS = ("key", "token", "secret", "password", "auth")
_PARAM_SUMMARY_MAX_LEN = 200


def _summarize_params(params: dict | None) -> str:
    """Format a params dict as `?k1=v1&k2=v2` for log lines.

    Sanitizer: any key whose lowercased name contains one of
    {"key", "token", "secret", "password", "auth"} has its value replaced
    with "***" — defense-in-depth against a future endpoint accidentally
    accepting a credential as a query param.

    Output is capped at 200 chars to keep log lines scannable; if the cap
    is hit, the trailing portion is replaced with "...".
    """
    if not params:
        return ""
    parts: list[str] = []
    for k, v in params.items():
        key_lower = str(k).lower()
        if any(s in key_lower for s in _SENSITIVE_PARAM_SUBSTRINGS):
            parts.append(f"{k}=***")
        else:
            parts.append(f"{k}={v}")
    body = "&".join(parts)
    if len(body) > _PARAM_SUMMARY_MAX_LEN - 1:  # -1 for the leading "?"
        body = body[:_PARAM_SUMMARY_MAX_LEN - 4] + "..."
    return "?" + body
```

- [ ] **Step 4.4: Re-run the helper tests, expect PASS**

Run: `pytest tests/test_client.py -k "summarize_params" -v`
Expected: all 5 PASS.

- [ ] **Step 4.5: Run full suite**

Run: `pytest -v 2>&1 | tail -5`
Expected: all green.

- [ ] **Step 4.6: Commit Task 4**

```bash
git add src/rapid7_healthcheck/client.py tests/test_client.py
git commit -m "feat(client): add _summarize_params helper for sanitized log output"
```

---

## Task 5: HTTP request logging — augment `_request()`

**Files:**
- Modify: `src/rapid7_healthcheck/client.py`
- Test: `tests/test_client.py`

The `_request()` method in `client.py` (around line 161) is the chokepoint. Today it has two log lines: a successful-response DEBUG line at line 198 (`"%s %s -> %s (%d ms)"`) and a network-error DEBUG line at line 201. We will:

- Add a `→` DEBUG line BEFORE each request attempt (with sanitized querystring).
- Replace the existing line-198 success log with a `←` DEBUG line that includes the body length and uses the glyph for tail-readability.
- Add a `retry N/M` DEBUG line on each retry path (currently silent).
- Add a `✗` WARNING line on non-retried error responses (4xx/5xx that becomes a `Rapid7ClientError`) — currently the client raises silently and the upstream check logs `logger.exception`, but the user tailing the file sees nothing at the boundary.

- [ ] **Step 5.1: Append the failing tests to `tests/test_client.py`**

Append to `tests/test_client.py`:

```python
import logging
import pytest


def _make_client_with_mock_session(mocker_or_responses):
    """Helper to construct a Rapid7Client whose session is mocked.
    Tests should adapt this to whatever mocking pattern test_client.py
    already uses — see existing tests for the canonical setup."""
    # Implementation note: the surrounding test file should already have
    # a fixture or helper that builds a client with a mocked session
    # (responses library, requests-mock, or unittest.mock). Reuse that.
    raise NotImplementedError("use the existing test helper / fixture")


def test_successful_get_emits_arrow_debug_lines(caplog, monkeypatch):
    """A successful GET produces both a `→` (request) and `←` (response)
    DEBUG line, each containing method and path."""
    from rapid7_healthcheck.client import Rapid7Client

    # Use existing test patterns to build a client + stub a 200 response
    # for GET /api/3/test. Read the surrounding tests in test_client.py
    # to mirror the setup (responses lib, requests-mock, or mock.Mock).
    # The assertion shape is what's specified here:
    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")

    # ... build client, stub 200 for GET /api/3/test, call client.get("/api/3/test")
    # (if the existing test scaffolding gives you a `client` fixture, use it)

    request_lines = [r for r in caplog.records if "→" in r.getMessage()]
    response_lines = [r for r in caplog.records if "←" in r.getMessage()]
    assert len(request_lines) >= 1
    assert len(response_lines) >= 1
    assert "GET" in request_lines[0].getMessage()
    assert "/api/3/test" in request_lines[0].getMessage()
    assert "GET" in response_lines[0].getMessage()
    assert "200" in response_lines[0].getMessage()


def test_get_with_params_includes_sanitized_querystring(caplog):
    """Querystring appears in the `→` line; sensitive keys are redacted."""
    from rapid7_healthcheck.client import Rapid7Client

    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")

    # ... build client, stub 200 for GET /api/3/test, call
    # client.get("/api/3/test", params={"page": 0, "api_key": "SECRET"})
    request_lines = [r for r in caplog.records if "→" in r.getMessage()]
    assert any("page=0" in r.getMessage() for r in request_lines)
    assert all("SECRET" not in r.getMessage() for r in request_lines)
    assert any("***" in r.getMessage() for r in request_lines)


def test_404_response_emits_x_warning_line(caplog):
    """Non-retried error (404) emits a WARNING with `✗`, status, and body snippet."""
    from rapid7_healthcheck.client import Rapid7Client, Rapid7ClientError

    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")

    # ... build client, stub 404 with body "not found here" for GET /api/3/missing
    # ... assert client.get("/api/3/missing") raises Rapid7ClientError
    warning_lines = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "✗" in r.getMessage()
    ]
    assert len(warning_lines) == 1
    msg = warning_lines[0].getMessage()
    assert "404" in msg
    assert "/api/3/missing" in msg
    assert "not found here" in msg


def test_retry_path_emits_debug_line(caplog):
    """A retry-status response (e.g. 429) followed by 200 emits a
    `retry N/M` DEBUG line."""
    from rapid7_healthcheck.client import Rapid7Client

    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")

    # ... build client, stub 429 (with Retry-After: 0) then 200 for the same URL.
    # Use a client constructed with max_retries >= 1.
    # ... call client.get("/api/3/flaky"); assert it returns successfully.

    retry_lines = [r for r in caplog.records if "retry " in r.getMessage()]
    assert len(retry_lines) >= 1
    assert "/api/3/flaky" in retry_lines[0].getMessage()
```

**IMPORTANT — read existing tests first.** The four tests above describe their assertions but leave the test setup as a comment. The `tests/test_client.py` file already has a working pattern for building a `Rapid7Client` with a mocked session and stubbing responses. Before you can make these tests runnable, OPEN `tests/test_client.py` and find an existing test that successfully exercises `client.get(...)`. Mirror its setup pattern (likely `responses`, `requests-mock`, or `unittest.mock`) and fill in the comment-only sections of the new tests with the exact same scaffolding. Do not reinvent the mocking strategy.

- [ ] **Step 5.2: Run the new tests, expect FAIL**

Run: `pytest tests/test_client.py -k "arrow_debug or sanitized_querystring or x_warning or retry_path" -v`
Expected: FAIL on assertions about `→`, `←`, `✗`, and `retry ` substrings (the existing log line at line 198 uses `->` not `←`).

- [ ] **Step 5.3: Augment `_request()` in `client.py`**

In `src/rapid7_healthcheck/client.py`, find `_request()` (currently around line 161). Modify the body as follows:

**Insert at the top of the `while attempt <= self._max_retries:` loop** (just before `try:` at the current line 185), add:

```python
            logger.debug("→ %s %s%s", method, path, _summarize_params(params))
```

(This logs every attempt, including retries. The retry context is captured by the separate retry log line below.)

**Replace the existing success log line** (currently line 198, `logger.debug("%s %s -> %s (%d ms)", method, path, resp.status_code, elapsed_ms)`) with:

```python
                logger.debug("← %s %s %d in %dms", method, path, resp.status_code, elapsed_ms)
```

(Only the format string and the use of `←` change. Same args, same level.)

**Replace the existing network-error log line** (currently line 201, `logger.debug("%s %s network error: %s", method, path, e)`) with:

```python
                logger.debug("✗ %s %s network error: %s", method, path, e)
```

(Glyph added for visual consistency. Still DEBUG — network errors that DO retry shouldn't be WARN.)

**Add a retry log line on the retry-status path** — find the block (around line 216):

```python
            if resp.status_code in _RETRY_STATUS:
                if attempt >= self._max_retries:
                    raise Rapid7ClientError(...)
                delay = self._retry_delay(resp, attempt)
                time.sleep(delay)
                attempt += 1
                continue
```

Insert directly after the `delay = self._retry_delay(resp, attempt)` line:

```python
                logger.debug(
                    "retry %d/%d for %s %s after %.1fs (status %d)",
                    attempt + 1, self._max_retries, method, path, delay, resp.status_code,
                )
```

(Note `attempt + 1` — the `attempt` variable is 0-indexed; humans want 1-indexed.)

**Add a WARNING log on the non-retried error path** — find (around line 226):

```python
            if resp.status_code >= 400:
                raise Rapid7ClientError(
                    f"HTTP {resp.status_code} from {method} {path}: {resp.text[:1500]}",
                    status_code=resp.status_code,
                )
```

Insert directly BEFORE the `raise`:

```python
                logger.warning(
                    "✗ %s %s %d: %s", method, path, resp.status_code,
                    resp.text[:200] if resp.text else "<empty body>",
                )
```

(The 1500-char snippet stays in the exception message; the WARNING line gets a tighter 200-char cap so tailed output stays scannable.)

**Also add WARNING for the auth-failure path** — find (line 211):

```python
            if resp.status_code in (401, 403):
                raise Rapid7AuthError(
                    f"auth failed ({resp.status_code}); check R7_API_KEY and base_url",
                    status_code=resp.status_code,
                )
```

Insert directly BEFORE the `raise`:

```python
                logger.warning(
                    "✗ %s %s %d: auth failed", method, path, resp.status_code,
                )
```

(Auth failures are non-retried errors; they deserve the same boundary log line as 4xx/5xx for symmetry. Body snippet omitted because auth-failure bodies are usually empty or HTML and add noise.)

- [ ] **Step 5.4: Re-run the four new tests, expect PASS**

Run: `pytest tests/test_client.py -k "arrow_debug or sanitized_querystring or x_warning or retry_path" -v`
Expected: all 4 PASS. If a test fails because the test scaffolding (mock setup) is wrong, that's a Step 5.1 bug — fix the scaffolding to match the existing test pattern.

- [ ] **Step 5.5: Run all client tests + full suite to catch regressions**

Run: `pytest tests/test_client.py -v`
Expected: all green. Existing client tests should not break — we only changed log-line text and added new lines.

Run: `pytest -v 2>&1 | tail -5`
Expected: full suite green.

- [ ] **Step 5.6: Commit Task 5**

```bash
git add src/rapid7_healthcheck/client.py tests/test_client.py
git commit -m "feat(client): log every HTTP request with →/←/✗ glyphs and retry visibility

DEBUG lines for request (→), successful response (←), retry, and network
error (✗); WARNING on non-retried 4xx/5xx and auth failures. Querystring
is sanitized via _summarize_params to redact any sensitive-looking keys."
```

---

## Task 6: README and CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 6.1: Find the existing logging section in README**

Run: `grep -n -i 'log\|--log-file\|--verbose' README.md | head -10`
Expected: at least one match referring to `--log-file` and `--verbose`. Note the line number(s).

- [ ] **Step 6.2: Add a sentence to the logging section**

In `README.md`, locate the section that documents `--log-file` and `--verbose`. Append (or insert as a new bullet/sentence within the same paragraph) the following:

> When `--log-file` is set, every HTTP request to the Security Console is logged at DEBUG level (use `--verbose` to enable) and every log line is flushed to disk immediately, so the file can be tailed live (`tail -f /path/to/log`) during long-running audits to see exactly which API call is in flight.

If the README has no existing logging section (only mentions `--log-file` in the help-output table), add a short subsection titled "Live-tailable run log" with the sentence above.

- [ ] **Step 6.3: Add CHANGELOG entry**

In `CHANGELOG.md`, find the topmost release-stub section (likely `## [Unreleased]` or whatever version is being prepared next). Add under a `### Changed` (or `### Added`, depending on existing convention) heading:

```markdown
- **Logging**: when `--log-file` is set, every log line is flushed to
  disk immediately so the file can be tailed live during long-running
  audits. Combined with `--verbose`, every HTTP request is logged
  (`→ GET /api/3/sites/47/assets?page=12` ... `← GET ... 200 in 340ms`)
  with retry visibility and a WARNING line on non-retried 4xx/5xx
  responses. Querystring values for sensitive-looking parameter names
  (`*key*`, `*token*`, `*secret*`, `*password*`, `*auth*`) are redacted.
```

If `[Unreleased]` doesn't exist, add it at the top:

```markdown
## [Unreleased]

### Changed

- **Logging**: ... (as above)
```

- [ ] **Step 6.4: Commit Task 6**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document live-tailable log file and HTTP-request visibility"
```

---

## Task 7: Final verification

- [ ] **Step 7.1: Full test suite**

Run: `pytest -v 2>&1 | tail -5`
Expected: all green. Total pass count should be baseline + 11 new tests (2 in test_log_flush.py basic, 2 integration in test_log_flush.py, 5 helper in test_client.py, 4 HTTP-log in test_client.py).

- [ ] **Step 7.2: Read-only invariant**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: no matches. (This change adds no HTTP verbs.)

- [ ] **Step 7.3: Smoke import**

Run: `python -c "from rapid7_healthcheck._log import FlushingFileHandler; from rapid7_healthcheck.client import _summarize_params; print('OK')"`
Expected: prints `OK` with no errors.

- [ ] **Step 7.4: Manual smoke (OPTIONAL — only if a real Rapid7 environment is available)**

If you have an `R7_API_KEY` set and a `config.yaml` configured, run:
```
python -m rapid7_healthcheck --verbose --log-file /tmp/r7-smoke.log --output /tmp/r7-smoke.html
```
In a second terminal, `tail -f /tmp/r7-smoke.log`. You should see `→ GET /api/3/...` and `← GET /api/3/... 200 in Nms` lines streaming in real time as the audit runs. If the log file appears empty until the run completes, flushing is broken — investigate.

If you don't have a real environment, skip this step.

- [ ] **Step 7.5: Git state**

Run: `git status` and `git log --oneline | head -10`
Expected: working tree clean; 6 new commits on the branch (Tasks 1+2, 3, 4, 5, 6, plus any corrective commits).

---

## Notes for the implementer

- **The existing log line at line 198 of `client.py` is being REPLACED**, not deleted. The new `←` line carries the same information in a slightly different format. Don't accidentally end up with both.
- **`force=True` is already in `_setup_logging`** at the existing `logging.basicConfig(...)` call. Don't add it again — the spec mentioned "verify it's there"; this plan confirms it is, no edit needed.
- **The four HTTP-log tests in Task 5 have placeholder mock-setup comments.** You MUST read the existing `tests/test_client.py` to find the canonical mocking pattern (responses, requests-mock, or `unittest.mock.Mock` patching `_session.request`) and fill those sections in. Do not write new mocks from scratch when the file already has a working pattern.
- **The `→`, `←`, `✗` glyphs are intentional UTF-8.** The file handler already uses `encoding="utf-8"`; don't change that.
- **No CLI knob for flush behavior** — decision was made in brainstorming Q3. Don't add one even if it seems "more flexible." The whole point of the file is being tail-able.
- **Sanitizer scope** — the redaction is defense-in-depth for query params only. We do NOT log request headers (where the actual API key lives), and we do NOT log request bodies (the search endpoint's filter criteria don't carry credentials). If you find yourself adding a body or header logging path, STOP and surface — that needs separate threat-model review.
- **Avoid scope creep.** The spec's "Out of scope" section is binding: no rule-level DEBUG logging, no JSON output, no log rotation, no full-body logging, no per-rule context tags. If you find yourself wanting any of these, stop and surface.
