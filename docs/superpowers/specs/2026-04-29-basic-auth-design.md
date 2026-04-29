# Basic Auth support for Security Console — design

**Status:** approved
**Target release:** 0.1.3
**Date:** 2026-04-29

## Background

The tool today authenticates against the Rapid7 InsightVM `/api/3` Security
Console API exclusively via the `X-Api-Key` header, sourced from the
`R7_API_KEY` environment variable. This works for self-hosted consoles
where the operator can mint an API key from the console's user-management
UI.

It does not work for at least one common Rapid7-hosted-console scenario:
SAML-provisioned users with MFA enabled (e.g. Global Administrators on a
`*.hosted.rapid7.com` tenant) cannot generate a console-local API key
through the UI — Rapid7 disables that path because there is no local
password to scope the key against. The same users *can* still authenticate
to the API via HTTP Basic Auth using their console-local credentials (or
service-account credentials provisioned by an admin).

## Goal

Let the operator choose between API-key auth and HTTP Basic Auth via a
single config field, without changing any other behaviour. Read-only
invariant enforcement (verb allowlist, path allowlist, static-scan tests)
must keep working unchanged.

## Non-goals

- Auto-detection or fallback between auth modes. The operator picks one
  explicitly. (Brainstorm Q2: option B chosen over A and C.)
- Cookie-based or session-token auth. The Security Console's `/api/3`
  accepts Basic Auth on every request, so no session dance is needed.
- Adding an OAuth flow or platform-side token exchange.

## Design

### Config schema

`Rapid7Config` (in `src/rapid7_healthcheck/config.py`) gains one optional
field:

```python
@dataclass(frozen=True)
class Rapid7Config:
    base_url: str
    verify_tls: bool
    request_timeout_seconds: int
    max_retries: int
    auth_mode: str = "api_key"  # "api_key" | "basic"
```

The validator accepts only `"api_key"` or `"basic"`. Any other value
raises `ConfigError` listing the allowed values. Default is `"api_key"`
so existing configs keep working without edits.

`docs/examples/config.yaml` gains a commented `# auth_mode: basic` under
the `rapid7:` block with a one-line note about when to use it.

### Credential loading

`__main__.py` already reads `R7_API_KEY` once at startup and exits with
code 3 (startup failure) when missing. New behaviour, branching on
`config.rapid7.auth_mode`:

- `"api_key"` — same as today.
- `"basic"` — read `R7_BASIC_USER` and `R7_BASIC_PASSWORD` from env (or
  `.env`). Either missing → exit code 3 with a precise message naming the
  missing variable.

The resolved credential flows into `Rapid7Client` via one of two
mutually-exclusive constructor kwargs:

- `api_key: str | None`
- `basic_auth: tuple[str, str] | None`

Exactly one must be provided; passing both or neither is a programming
bug, raised as `ValueError` (not `ReadOnlyViolationError` — that name is
reserved for runtime read-only enforcement).

### Client

`Rapid7Client.__init__` constructs headers and auth as follows:

- API-key mode: existing `X-Api-Key` header (unchanged).
- Basic mode: pass `auth=(user, password)` to every `self._session.request`
  call. Don't manually base64-encode the `Authorization` header — `requests`
  handles encoding correctly.

The `User-Agent` header stays the same in both modes. The auth machinery
is the only thing that changes; verb/path enforcement, retry logic,
pagination, and error handling are untouched.

### Read-only invariant

Unchanged. `_ALLOWED_VERBS`, `_ALLOWED_POST_PATHS`,
`ReadOnlyViolationError`, and `tests/test_readonly_invariant.py` all keep
working as-is. Auth mode is orthogonal to verb/path enforcement.

### Tests

New tests, organised by file:

`tests/test_client.py`:
- `test_client_uses_api_key_header_in_api_key_mode`
- `test_client_uses_basic_auth_in_basic_mode` — assert the `auth=` kwarg
  is passed to the mocked session.
- `test_client_rejects_both_api_key_and_basic_auth` — mutual exclusivity.
- `test_client_rejects_neither_api_key_nor_basic_auth` — same gate from
  the other side.

`tests/test_config.py`:
- `test_auth_mode_defaults_to_api_key`
- `test_auth_mode_accepts_basic`
- `test_auth_mode_rejects_unknown_value`

`tests/test_main.py`:
- `test_startup_fails_when_basic_user_missing`
- `test_startup_fails_when_basic_password_missing`

### Documentation

`README.md` Setup section gains a new subsection,
**"Authenticating against a Rapid7-hosted Security Console"**, explaining:

- Hosted-console SAML/MFA users may not be able to mint an API key in the
  UI.
- Workaround: set `auth_mode: basic` in `config.yaml`; set `R7_BASIC_USER`
  and `R7_BASIC_PASSWORD` in `.env`.
- Hosted-console `base_url` is `https://<tenant>.hosted.rapid7.com` (no
  port suffix; uses 443).

`SECURITY.md` gains one paragraph: Basic Auth doesn't change the
read-only invariant — same allowlist enforcement applies.

`CHANGELOG.md` `[Unreleased]` → `[0.1.3]` entry under `### Added` /
`### Changed`.

## Failure modes and exit codes

| Scenario | Behaviour |
|---|---|
| `auth_mode` missing from `config.yaml` | Defaults to `"api_key"`. No error. |
| `auth_mode` set to anything other than `api_key` / `basic` | `ConfigError` at startup → exit code 3. |
| `auth_mode: api_key` and `R7_API_KEY` unset | Existing behaviour. Exit code 3. |
| `auth_mode: basic` and `R7_BASIC_USER` unset | New. Exit code 3 with explicit message. |
| `auth_mode: basic` and `R7_BASIC_PASSWORD` unset | New. Exit code 3 with explicit message. |
| Both `api_key` and `basic_auth` passed to `Rapid7Client` | `ValueError`. Should never happen via `__main__`; protects library use. |
| 401 from console with valid-looking credentials | Existing `Rapid7AuthError` path. Exit code 3. |

## Out of scope

- Auto-detect / fallback between auth modes.
- Storing the password anywhere except env.
- Cookie-/session-based auth.
- Migration from `R7_API_KEY` (no migration needed; default unchanged).

## Open questions resolved during brainstorm

1. **Tie this change to a `verify_tls: false` toggle?** No (Q1 = A). The
   `verify_tls` field already exists; SSL issues are a separate concern.
2. **Implicit auth selection vs explicit knob vs auto-detect?** Explicit
   knob (Q2 = B). Operator picks; failure messages stay precise.
3. **One env var or two for credentials?** Two — `R7_BASIC_USER` and
   `R7_BASIC_PASSWORD` (Q3 = A). Mirrors the existing `R7_API_KEY`
   pattern.
