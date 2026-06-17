# Rapid7 InsightVM Health-Check

Domain and architecture language for the read-only audit tool that runs against InsightVM Security Consoles and the InsightVM Cloud. Terms here are the agreed vocabulary; use them exactly and avoid the listed synonyms.

## The two Rapid7 APIs

**Console API (v3)**:
The on-prem Security Console REST API under `/api/3/...`. Responses wrap results in `{resources, page}`, with `page.totalPages` driving pagination. Auth is `X-Api-Key` or HTTP Basic.
_Avoid_: "the main API", "the REST API" (ambiguous — there are two).

**Cloud Integrations API (v4)**:
The InsightVM Cloud API under `/v4/integration/...`. Responses wrap results in `{data, metadata, links}`, with `metadata.totalPages` driving pagination. Auth is `X-Api-Key` only.
_Avoid_: "the cloud endpoint", "the v4 endpoint" (it is an API surface, not one endpoint).

## HTTP layer

**HttpTransport**:
The single deep module that owns everything identical across both APIs — the retry loop, backoff, `Retry-After` handling, the read-only verb/path allowlist *enforcement*, JSON parsing, and the page-0-probe-then-batch pagination machinery. It learns the per-API differences from an injected `ApiDialect`.
_Avoid_: "base client", "HTTP helper", "the requests wrapper".

**ApiDialect**:
The small value object injected into an `HttpTransport` that carries the only things that differ between the Console API (v3) and the Cloud Integrations API (v4): the response envelope keys, the POST allowlist contents, the failure exception class, and the auth-error hint. It is the adapter at the transport's seam — pure data, no behaviour.
_Avoid_: "config", "options", "profile" (those imply tuning knobs; a dialect is the API's fixed shape).

**Rapid7Client / CloudClient**:
The two thin adapters callers construct. Each is an `HttpTransport` wired with its `ApiDialect` (v3 and v4 respectively) and the auth its API accepts. They add no behaviour beyond construction; all transport logic is inherited from `HttpTransport`.
_Avoid_: "the v3 client / v4 client object" when you mean the class — use the class names.

## Audit orchestration

**Audit category**:
One of the four parallel audit verticals — Configuration Audit, Template Configuration Audit, User & Permission Audit, Cloud Drift Audit. Each owns a rule registry, a config block, and a `Check` class, but all four run their rules through the same loop.
_Avoid_: "audit type", "audit module", "audit subsystem" (use "category").

**AuditRunner**:
The single deep module that owns everything identical across the four audit categories — the enabled-skip envelope, the per-rule enable/skip cards, the progress step/done choreography, per-rule timing, the exception trap (`_extract_diagnostics` → error `RuleResult`), the status rollup, and the `rules_*` summary counts. It learns the per-category differences from an injected `AuditCategory`. Analogous to `HttpTransport`: one loop, many categories.
_Avoid_: "audit engine", "audit loop", "base orchestrator".

**AuditCategory**:
The descriptor value object injected into the `AuditRunner` that carries the only things differing between the four categories: identity (`name`/`description`/`progress_prefix`), the rule `registry`, the `rules_config` accessor, the sampling args (`full_scan`/`sample_size`) forwarded to each rule, and three callables — `gate` (enabled? plus the rich skip Finding), `build_snapshot` (pure snapshot construction), and an optional `prime` (an I/O early-exit, e.g. User & Permission's `/api/3/users` 404 self-skip). It is the adapter at the runner's seam — mostly data, with the irreducible per-category behaviour held in the three callables.
_Avoid_: "audit descriptor", "audit spec", "audit profile", "audit config" (it is not the YAML config block).

**The four check classes** (`ConfigurationAuditCheck`, `TemplateAuditCheck`, `UserPermissionAuditCheck`, `CloudDriftAuditCheck`):
The thin `Check` adapters `__main__` registers. Each supplies an `AuditCategory` and delegates to the `AuditRunner`; they add no loop logic. Analogous to `Rapid7Client`/`CloudClient` wiring an `ApiDialect` into an `HttpTransport`.
_Avoid_: "audit orchestrator" for these — the orchestrator is the `AuditRunner`; these are suppliers.
