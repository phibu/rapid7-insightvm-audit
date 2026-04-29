# User & Permission Audit + version-drift fix — design

**Status:** approved
**Target release:** 0.1.8
**Date:** 2026-04-29

## Background

The tool today audits scan configuration (R1–R12 across two release
waves). It does not audit *who has access to the console*. A user
asked for the equivalent rules at the people / RBAC layer ("never
logged in", "local password not changed within 90 days", etc.).

API research via Context7 (authoritative source: `/riza/rapid7-insightvm-api-docs`)
confirmed two unwelcome facts about `/api/3`:

- The `User` schema does **not** expose `lastLoggedOnDate`, `lastSignedIn`,
  `passwordLastChanged`, or any last-activity timestamp. Those fields
  exist in the UI Users table but not in the REST surface.
- There is no `/api/3/password_policy` endpoint. The password-policy
  editor is UI-only on Nexpose.

Two of the three example rules the user asked for are therefore
unimplementable against `/api/3`. What *is* exposed is enough for 7
real, high-value rules — covering MFA on privileged accounts, SSO
bypass, multi-admin sprawl, locked accounts, orphaned role bindings,
and the `superuser` flag escape hatch.

A separate, longstanding bug surfaced during this brainstorm: every
report shipped since 0.1.1 has displayed `Version: 0.1.0` because
`src/rapid7_healthcheck/__init__.py` carries `__version__ = "0.1.0"`
and was never bumped alongside `pyproject.toml`. The fix folds in here
because both touch the same release flow.

## Goals

1. Add a new audit category — **User & Permission Audit** — with 7
   rules grounded in confirmed `/api/3` endpoints.
2. Introduce the new category as a sibling to the existing
   `Configuration Audit` (separate `Check`, separate config block,
   separate report section), not as more rules in the existing
   registry.
3. Eliminate the version-drift bug at its root: make `__version__`
   read from package metadata so `pyproject.toml` is the single
   source of truth.

## Non-goals

- Last-login / password-age / account-inactivity rules — the API
  doesn't expose the data. Documented honestly in the README.
- Auditing the password policy itself — no API endpoint.
- Per-user privileges audit via `/api/3/users/{id}/privileges` — that
  endpoint just echoes role privileges already on the user object.
- Building a "manual review" companion table in the report listing
  every user — the UI already does that better.
- Auto-detecting service accounts — heuristic too fragile, allowlist
  via config covers the case.

## API surface used

Confirmed via Context7. All endpoints `GET`, all read-only:

- `/api/3/users` — paginated list of users with role, auth source, enabled, locked.
- `/api/3/users/{id}/2FA` — returns the 2FA seed if 2FA is configured. Empty/404 means not configured.
- `/api/3/users/{id}/sites` — paginated.
- `/api/3/users/{id}/asset_groups` — paginated.
- `/api/3/authentication_sources` — list of configured auth sources with `external` flag.

All endpoints documented as **Global Administrator only**. The tool's
existing role recommendation already covers it.

## Design

### New audit category

A new module `src/rapid7_healthcheck/audit/user_permission/__init__.py`
defines `UserPermissionAuditCheck`. It mirrors the existing
`ConfigurationAuditCheck` pattern: registry of rules, per-rule
exception isolation, summary counts.

The new check is registered in `__main__._REGISTRY` next to the
existing audit, gated by a new config toggle
`checks.user_permission_audit: true`.

### New snapshot accessors

Added to `EnvSnapshot`:

- `users()` — paginated `/api/3/users`. Cached. Returns `list[dict]`.
- `authentication_sources()` — `/api/3/authentication_sources`. Cached.
- `user_2fa_enabled(user_id) -> bool | None` — calls
  `/api/3/users/{id}/2FA`. Returns `True` if response has a non-empty
  `key` field, `False` if the field is absent or empty, `None` on 404
  (the endpoint may not be exposed on hosted consoles, same defensive
  pattern as `blackouts`).
- `user_sites(user_id)` — paginated `/api/3/users/{id}/sites`.
- `user_asset_groups(user_id)` — paginated `/api/3/users/{id}/asset_groups`.

Each accessor traps 404 by checking `e.status_code == 404` (per the
v0.1.5 contract — never substring-match). The 2FA accessor's tri-state
return distinguishes "not configured" (False) from "endpoint missing"
(None) so the rule can skip honestly rather than falsely flag every
user.

A new snapshot flag `users_endpoints_unavailable` mirrors
`is_blackouts_unavailable()`: set to True when `/api/3/users` itself
returns 404, signalling that this entire audit category should
self-skip (some heavily restricted custom roles don't expose user
listings).

### The 7 rules

Each is a single file under
`src/rapid7_healthcheck/audit/user_permission/rules/`, matching the
existing `audit/rules/*.py` shape: implements `Rule` protocol,
decorated with `@register_user_rule`, returns `RuleResult`.

| `rule_id` | Severity | `expensive` | Logic |
|---|---|---|---|
| `privileged_user_without_mfa` | fail | True | Iterates users where `role.id == "global-admin" or role.superuser`. Skips users in `mfa_exempt_logins` knob. For each, checks `snapshot.user_2fa_enabled(id)`. Flags users where 2FA is disabled (False). Skips entirely if the 2FA endpoint returns None for any user. Honours `sample_size` for the per-user fan-out. |
| `local_account_when_sso_configured` | warn | False | Self-skips if `authentication_sources()` has no `external: true` entry. Counts `enabled` users with `authentication.type == "normal"`. Flags when count exceeds `max_local_accounts_when_sso` (default 2). |
| `multiple_global_administrators` | warn | False | Counts `enabled` users with `role.id == "global-admin"`. Flags when > `max_global_administrators` (default 2). |
| `locked_user_account` | warn | False | One finding per user with `locked == true`. |
| `disabled_user_with_role_bindings` | info | False | `enabled == false` AND has any role/site/asset-group binding. |
| `user_with_role_but_no_access` | info | True | `enabled == true`, role assigned, `role.allSites == false`, `role.allAssetGroups == false`, AND both `user_sites(id)` and `user_asset_groups(id)` return empty. Honours `sample_size`. |
| `superuser_flag_outside_global_admin` | fail | False | `role.superuser == true` AND `role.id != "global-admin"`. |

The MFA rule narrows scope to **privileged accounts only** because
HTTP Basic Auth (used by the tool itself in some configurations)
bypasses MFA at the protocol level. A blanket "every user must have
MFA" rule would fail on every legitimate service account, including
the one running this tool. By scoping to privileged users (GA / superuser),
the rule catches the actually-actionable cases. The `mfa_exempt_logins`
knob handles the edge case where a service account does need GA.

Two rules are `expensive=True` (per-user fan-out HTTP). Five are
list-only over the cached `users()` snapshot.

### Config schema

`config.yaml` gets a new top-level block parallel to `audit:`:

```yaml
user_audit:
  enabled: true
  full_scan: false
  sample_size: 500
  rules:
    privileged_user_without_mfa:
      enabled: true
      severity: fail
      mfa_exempt_logins: []
    local_account_when_sso_configured:
      enabled: true
      severity: warn
      max_local_accounts_when_sso: 2
    multiple_global_administrators:
      enabled: true
      severity: warn
      max_global_administrators: 2
    locked_user_account:
      enabled: true
      severity: warn
    disabled_user_with_role_bindings:
      enabled: true
      severity: info
    user_with_role_but_no_access:
      enabled: true
      severity: info
    superuser_flag_outside_global_admin:
      enabled: true
      severity: fail
```

`config.py` gets:

- `_USER_AUDIT_VALID_RULE_IDS` set with the 7 ids.
- `UserAuditConfig` dataclass mirroring `AuditConfig` (`enabled`,
  `full_scan`, `sample_size`, `rules: dict[str, RuleConfig]`).
- `_build_user_audit_config()` builder mirroring
  `_build_audit_config`. Unknown rule ids raise `ConfigError`. Unknown
  knobs in `RuleConfig.knobs` are preserved (same as existing audit —
  rules read what they need).
- `AppConfig.user_audit: UserAuditConfig` with default-disabled when
  the block is missing (so existing configs keep working untouched).

`checks:` block gains `user_permission_audit: true` toggle, defaulting
to True when missing (consistent with `configuration_audit`).

### Report rendering

The report iterates `results: list[CheckResult]`. Both audit checks
produce `CheckResult` with `rule_results: list[RuleResult]`, so the
existing template rendering — including the v0.1.6 Duration column —
just works for the new section.

The new section appears in the report after the existing audit
section because of registry ordering.

### Version-drift fix

`src/rapid7_healthcheck/__init__.py` becomes:

```python
from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("rapid7-insightvm-audit")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
```

After this, `pyproject.toml` is the only place the version is
declared. The bump-two-places trap is structurally eliminated.

A new test asserts the equivalence:

```python
def test_version_matches_package_metadata():
    from importlib.metadata import version
    from rapid7_healthcheck import __version__
    assert __version__ == version("rapid7-insightvm-audit")
```

This will fail loudly if anyone reintroduces a hardcoded
`__version__`.

### Required role

The new audit needs Global Administrator. The README already
recommends GA (or a service-account-with-GA role) for the tool
generally; the user-audit subsection notes it's strictly required for
this category. Operators on a custom least-privilege role will see
the `users_endpoints_unavailable` self-skip path.

## Failure modes

| Scenario | Behaviour |
|---|---|
| `/api/3/users` returns 404 | Snapshot sets `users_endpoints_unavailable`. The whole category emits a single info finding and no rule findings. |
| `/api/3/users` returns 401/403 | Auth error propagates per existing v0.1.5 contract. Audit aborts with `error` status; other checks unaffected. |
| `/api/3/users/{id}/2FA` returns 404 | `user_2fa_enabled` returns None. The MFA rule self-skips with an info finding. |
| `authentication_sources` empty / no external source | The `local_account_when_sso_configured` rule self-skips (rule isn't applicable when SSO isn't configured). |
| User with `role.id == None` | Treated as "no role assigned" — only relevant to the `disabled_user_with_role_bindings` rule which won't flag it. |
| Per-rule exception | Caught by the orchestrator, rule gets `status="error"` `RuleResult`, other rules continue. |

## Tests

New tests by area:

- **Rules** — 7 files under `tests/audit/user_permission/rules/test_*.py`. Each: happy path + each finding case + each knob + sample/skip path where applicable.
- **Orchestrator** — `tests/audit/user_permission/test_user_audit_check.py`: skipped-when-disabled, error-isolation, summary counts, the `users_endpoints_unavailable` self-skip path.
- **Config** — `tests/test_config.py`: 4 new tests (defaults, valid rule, unknown rule rejected, unknown knob preserved).
- **Snapshot** — `tests/audit/test_snapshot.py`: 4 new tests (caching, 404 trap on `/api/3/users`, 2FA tri-state, 2FA endpoint missing).
- **Version** — `tests/test_version.py` (new): the metadata-equivalence test.
- **FakeSnapshot** gains `set_users`, `set_authentication_sources`, `set_user_2fa_enabled`, `set_user_sites`, `set_user_asset_groups`, `set_users_endpoints_unavailable`.

Estimated total: ~25 new tests, current 207 → ~232 passing.

## Documentation

- **README** — new "User & Permission Audit" subsection under the existing audit category. Lists the 7 rules with severities and knobs. Calls out the GA-only requirement and explicitly documents the unimplementable rules (last login, password age, password policy) with a one-line "use the UI for these".
- **CHANGELOG** — `[0.1.8]` entry under `### Added` (the new category, the 7 rules) and `### Fixed` (the version-drift bug).
- **CLAUDE.md** — brief addition to the architecture section: user-audit rules live in their own subpackage at `src/rapid7_healthcheck/audit/user_permission/`; registration follows the same `@register` decorator pattern but uses a separate registry.
- **`docs/examples/config.yaml`** — populated `user_audit:` block with comments on each knob.

## Out of scope (deliberate, repeated for clarity)

- Last-login / inactivity rules — API doesn't expose the data.
- Password-age / password-policy rules — no API endpoint.
- Auto-detect service accounts — too fragile; allowlist via knob covers it.
- Per-user privileges audit — `/api/3/users/{id}/privileges` is redundant with the role object.

## Release

- Version bump to **0.1.8** in `pyproject.toml`. The `__init__.py` constant becomes derivative.
- Branch `feat/user-permission-audit`.
- PR → CI → squash-merge → tag `v0.1.8` → slim release zip.
- Same flow as 0.1.5 / 0.1.6 / 0.1.7.
