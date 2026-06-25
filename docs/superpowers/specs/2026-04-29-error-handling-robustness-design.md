# Error-handling robustness -- design

**Status:** approved
**Target release:** 0.1.5
**Date:** 2026-04-29

## Background

Code review of the v0.1.4 hosted-console compatibility patch flagged
brittle error handling in two places:

1. `EnvSnapshot.blackouts()` traps a 404 from `/api/3/blackouts` by doing
   `if "404" in str(e): ...` against a `Rapid7ClientError`. The error
   message format is `f"HTTP {status} from {method} {path}: {body[:1500]}"`,
   so any non-404 error whose path or response body contains "404"
   could be silently swallowed. The truncation bump to 1500 chars in
   v0.1.4 made the false-match surface area larger.
2. `AssetCoverageCheck` has the same pattern: `"400" in str(e) and
   "is-empty" in str(e)`. The `is-empty` substring narrows the
   false-positive risk, but it also means the trap fails open if a
   future console returns a generic 400 without echoing the operator
   name.

Separately, `EnvSnapshot.blackouts_unavailable` is a property that
performs a network call on first access -- a hidden side effect that
violates least-surprise.

## Goal

Replace string-substring error matching with numeric HTTP-status-code
checks, and make the blackouts-availability accessor honest about its
IO. No behaviour change for the happy path or for any currently passing
test.

## Non-goals

- Restructuring the exception hierarchy beyond adding one attribute.
- Adding new compatibility traps for hypothetical future hosted-console
  quirks.
- Adding a `flag_blackouts_check` config knob (premature).
- Renaming `template_vuln_enabled` or normalising its precedence
  semantics -- its existing top-level-wins behaviour is correct;
  documentation only.

## Design

### `Rapid7ClientError` gains a `status_code` attribute

```python
class Rapid7ClientError(Exception):
    """HTTP or network failure interacting with the Rapid7 API."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
```

`Rapid7AuthError` and `ReadOnlyViolationError` keep their existing
class definitions; they inherit the new keyword-only `status_code`
attribute through `super().__init__`. No new exception types are
introduced.

The attribute is `int | None`:

- Populated on every HTTP-status-derived raise (4xx / 5xx).
- `None` for raises that happen *before* the response (network errors,
  read-only violations) or where the response was 2xx but unparseable.

### `_request` populates `status_code` at every raise site

In `client.py`, five raise sites change. Each one passes the actual
HTTP status when the response was received:

- 401 / 403 → `Rapid7AuthError(..., status_code=resp.status_code)`
- Retryable status exhausted → `Rapid7ClientError(..., status_code=resp.status_code)`
- Non-retryable 4xx / 5xx → `Rapid7ClientError(..., status_code=resp.status_code)`
- Non-JSON 2xx body → `Rapid7ClientError(...)` (no status_code; the
  HTTP layer succeeded, parsing failed)
- Network error → `Rapid7ClientError(...)` (no status_code; never
  reached the server)

`ReadOnlyViolationError` raises happen before any HTTP call, so they
keep `status_code=None` by default.

### Substring traps replaced with numeric checks

`snapshot.py`:

```python
except Rapid7ClientError as e:
    if e.status_code == 404:
        # blackouts endpoint not implemented on this console
        ...
    else:
        raise
```

`asset_coverage.py`:

```python
except Rapid7ClientError as e:
    if e.status_code == 400:
        unscanned_unavailable = True
    else:
        raise
```

The `"is-empty"` substring guard is removed. The status code itself is
the trap. If a future console returns 400 on this endpoint+filter for a
*different* reason, we still want to mark the count unavailable and
move on -- the existing rule already handles that case gracefully.

### `blackouts_unavailable` property → `is_blackouts_unavailable()` method

The property currently triggers a network call on first access (via
`self.blackouts()`). Methods communicate "this might do work" without
surprise. Caller pattern:

```python
snapshot.blackouts()  # primes the cache + flag
if snapshot.is_blackouts_unavailable():
    ...
```

In `EnvSnapshot`, the method just returns `self._blackouts_unavailable`
(no IO, no fetch-on-read). The caller is responsible for having called
`blackouts()` first; in practice every caller already does, since they
need the data.

`FakeSnapshot` mirrors the rename. The rule call site
(`overlapping_scan_windows.py`) changes from a `getattr(...)` defensive
read to a direct method call.

### `template_vuln_enabled` docstring tightened

Add one sentence to the existing docstring:

> When both shapes are present, the top-level `vulnerabilityEnabled` is
> authoritative -- older nested shapes are read only as a fallback.

This documents the existing behaviour without changing it.

### Documentation

- **`.env.example`** -- add (commented out) entries for `R7_BASIC_USER`
  and `R7_BASIC_PASSWORD`. The 0.1.3 release added Basic Auth support
  but `.env.example` only documents `R7_API_KEY`; new operators using
  `auth_mode: basic` have no template to copy.
- **README.md Troubleshooting section** -- one new bullet explaining
  that some `info`-severity findings ("endpoint not available on this
  console", "operator unsupported on this console") are *expected* on
  Rapid7-hosted consoles and indicate API surface differences, not
  bugs in the tool.
- **CLAUDE.md architecture section** -- one paragraph noting that
  `Rapid7ClientError.status_code` is the canonical way to branch on
  HTTP status, and that string-substring matching on error messages
  is a footgun.
- **CHANGELOG.md** -- `[0.1.5]` entry under `### Changed` and `### Tests`.
- **SECURITY.md** -- no changes; the read-only invariant is unaffected.

## Tests

New tests (4):

- `test_client.py`: 4xx / 5xx raises expose `e.status_code` correctly.
- `test_client.py`: 401 raises `Rapid7AuthError` with `status_code == 401`.
- `test_client.py`: network errors raise `Rapid7ClientError` with
  `status_code is None`.
- `test_snapshot.py`: `is_blackouts_unavailable()` after a 500 raises
  the underlying error (regression guard for the property-with-IO
  hazard the reviewer flagged).

Updated tests:

- `test_snapshot.py`: switch `.blackouts_unavailable` reads to
  `.is_blackouts_unavailable()`.
- `test_overlapping_scan_windows.py`: same rename.

Updated `FakeSnapshot`: property → method.

Total expected: 199 passing (up from 195; +4 new tests).

## Failure modes covered

| Scenario | Behaviour |
|---|---|
| Hosted console returns 404 from `/api/3/blackouts` | Trap matches; rule emits info finding. |
| Console returns 500 from `/api/3/blackouts` whose body contains "404" | No false trap. Error propagates. |
| Path-with-404 returns 500 (e.g. `/api/3/sites/404/foo`) | No false trap. Error propagates. |
| Console returns 400 on `is-empty + last-scan-date` filter | Trap matches; check emits info finding and continues. |
| Console returns 400 on a different filter | Same trap fires. Acceptable: the rule already degrades gracefully and the operator can disable the sub-check. |
| Console returns 400 on the search endpoint with no operator name in body | Trap still matches via status code. (Old code would have failed open here.) |
| Caller reads `is_blackouts_unavailable()` without first calling `blackouts()` | Returns `False` (the default); honest about its state. |

## Backwards compatibility

- Adding `status_code` to `Rapid7ClientError` is fully backwards
  compatible. Existing `except Rapid7ClientError as e` blocks
  continue to work; `e.status_code` is just a new attribute they can
  optionally inspect.
- The `blackouts_unavailable` property → method rename is technically
  a breaking change to the snapshot's public API. The property was
  introduced in v0.1.4 (released the same day as v0.1.5) and is only
  consumed by one in-tree rule plus tests, so the impact is zero in
  practice.

## Out of scope (Minor review items not addressed)

- `template_vuln_enabled` precedence redesign -- documented only.
- `site_scan_template_id` falsy-id-zero edge -- IDs are strings.
- Static helpers as module-level functions -- refactoring is theatrical.
- `flag_blackouts_check: false` config knob -- ship when asked.
