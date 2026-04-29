# Security Policy

## Read-Only Invariant

`rapid7-insightvm-audit` is a **read-only** tool. It is designed to gather
data from a Rapid7 InsightVM console and produce an HTML report — it never
mutates state on the customer's console.

The guarantee is enforced in three layers:

1. **Runtime.** `Rapid7Client._request` (in `src/rapid7_healthcheck/client.py`)
   rejects any HTTP verb outside `{GET, POST}`, and any `POST` whose path
   is not in the explicit `_ALLOWED_POST_PATHS` allowlist. Violations raise
   `ReadOnlyViolationError` *before* the request is sent.
2. **Static-scan tests** (`tests/test_readonly_invariant.py`) fail CI if:
   - any file outside `client.py` calls `.put(`, `.patch(`, or `.delete(`
   - any file outside `client.py` calls `requests.<write-verb>(` directly
   - `Rapid7Client` grows methods named `put`, `patch`, or `delete`
   - any static `client.post(...)` call site targets a path not in
     `_ALLOWED_POST_PATHS`.
3. **Documentation.** This file and the README disclose every legitimate
   `POST` exception.

### The single legitimate POST

`POST /api/3/assets/search` is the only `POST` endpoint the tool calls.
Rapid7's v3 API requires `POST` for asset filter searches because the
filter criteria travel in the request body. The endpoint is documented as
read-only — it returns assets matching the filter and does not mutate
state.

Adding a new `POST` endpoint requires editing `_ALLOWED_POST_PATHS` in
`client.py`. That edit is a deliberate, reviewed change.

## Supported Versions

Only the latest minor release receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please open a
GitHub Security Advisory (preferred) or a private issue rather than a
public one. Do not include exploit details in a public issue.

For non-security bugs and feature requests, please open a normal GitHub
issue.
