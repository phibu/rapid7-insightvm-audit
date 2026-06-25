# Security Policy

## Read-Only Invariant

`rapid7-insightvm-audit` is a **read-only** tool. It is designed to gather
data from a Rapid7 InsightVM console and produce an HTML report -- it never
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

### Auth modes do not change the invariant

The tool supports two authentication modes against the Security Console:
`X-Api-Key` header (default) and HTTP Basic Auth (`auth_mode: basic`).
Both flow through the same `Rapid7Client._request` and are subject to the
same verb / path allowlist enforcement. Switching auth modes does not
relax, broaden, or otherwise affect the read-only invariant.

### The single legitimate POST

`POST /api/3/assets/search` is the only `POST` endpoint the tool calls.
Rapid7's v3 API requires `POST` for asset filter searches because the
filter criteria travel in the request body. The endpoint is documented as
read-only -- it returns assets matching the filter and does not mutate
state.

Adding a new `POST` endpoint requires editing `_ALLOWED_POST_PATHS` in
`client.py`. That edit is a deliberate, reviewed change.

### Cloud Drift Audit (v4 client)

When the Cloud Drift audit is enabled, a second HTTP client (`CloudClient`)
talks to the InsightVM Cloud Integrations API at
`https://{region}.api.insight.rapid7.com/vm/`. The same read-only contract
applies, with a separate, equally explicit allowlist:

- Verbs: `GET` and `POST` only.
- POST paths: `/v4/integration/assets` only (search endpoint with filter
  criteria in the request body).
- Endpoints deliberately excluded from the allowlist:
  - `POST /v4/integration/scan` (starts a scan)
  - `POST /v4/integration/scan/{id}/stop` (stops a running scan)
  - `POST /v4/integration/scan/engine/{id}/configuration` (mutates engine config)
  - `DELETE /v4/integration/scan/engine/{id}/configuration` (removes engine config)
  - `POST /v4/integration/sites` and `POST /v4/integration/vulnerabilities` (read-safe but unused; YAGNI)

Mutator endpoints are unreachable from the tool: invoking them raises
`ReadOnlyViolationError` before any HTTP request is sent.

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
