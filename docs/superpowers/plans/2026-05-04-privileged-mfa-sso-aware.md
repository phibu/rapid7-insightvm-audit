# Privileged-MFA SSO + Severity Bumps + Insight Agent Modes + Bounded Agent-Unauth-Collision -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship four targeted audit-rule corrections in one coherent change: SSO-aware privileged-MFA, severity bumps for two RBAC-hygiene rules, three-mode Insight Agent version currency, and bounded per-site asset enumeration to fix the agent-unauth-collision timeout.

**Architecture:** Each rule lives in its own file under `audit/rules/` or `audit/user_permission/rules/`, self-registers via a decorator, and reads through `EnvSnapshot`. One new snapshot accessor (`iter_site_assets`) is added for the bounded-pagination use case. No HTTP-layer changes (`client.py` untouched). Read-only contract unchanged -- no new POSTs or other verbs.

**Tech Stack:** Python 3.11+, pytest, dataclasses, Jinja2 (report -- not touched here).

---

## Pre-flight

- [ ] **Step 0.1: Confirm baseline tests pass before any edits**

Run: `pytest -v`
Expected: all green. If anything is red on `main`, stop and surface to the user -- don't layer changes on a broken baseline.

- [ ] **Step 0.2: Read-only invariant baseline**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: no matches (CLAUDE.md "Read-only safety" section). Establishes the line we must not cross.

---

## Task 1: SSO-aware `privileged_user_without_mfa` -- failing test for the SAML skip

**Files:**
- Test: `tests/audit/user_permission/rules/test_privileged_user_without_mfa.py`

- [ ] **Step 1.1: Append the new test (TDD red)**

Append at the end of `tests/audit/user_permission/rules/test_privileged_user_without_mfa.py`:

```python
def _user_with_auth(uid: int, login: str, auth_type: str | None, role_id: str = "global-admin") -> dict:
    """Helper: build a user dict with an explicit authentication.type."""
    u = {
        "id": uid,
        "login": login,
        "enabled": True,
        "role": {"id": role_id, "name": role_id, "superuser": False},
    }
    if auth_type is not None:
        u["authentication"] = {"type": auth_type}
    return u


def test_external_saml_user_skipped_no_2fa_call(fake_snapshot):
    """SAML-authenticated privileged user must NOT trigger a 2FA endpoint call;
    they appear in a single aggregate info finding instead."""
    fake_snapshot.set_users([_user_with_auth(1, "saml-admin", "saml")])
    # Deliberately do NOT set_user_2fa_enabled -- if the rule calls it, the fake
    # returns False (default) and we'd see a fail finding. We assert there is none.
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.summary["users_external_auth"] == 1
    assert r.summary["users_without_mfa"] == 0
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert "external sources" in info_findings[0].message.lower()
    assert info_findings[0].details["external_auth_user_count"] == 1
    assert info_findings[0].details["external_auth_users"] == [
        {"login": "saml-admin", "auth_type": "saml"},
    ]
```

- [ ] **Step 1.2: Run the new test to verify it fails**

Run: `pytest tests/audit/user_permission/rules/test_privileged_user_without_mfa.py::test_external_saml_user_skipped_no_2fa_call -v`
Expected: FAIL -- current rule will call `user_2fa_enabled(1)` (gets `False`), emit a `fail` finding, status `fail`. The `users_external_auth` summary key won't exist, raising `KeyError`. Either failure mode is fine; we just need RED.

---

## Task 2: SSO-aware `privileged_user_without_mfa` -- implementation

**Files:**
- Modify: `src/rapid7_healthcheck/audit/user_permission/rules/privileged_user_without_mfa.py`

- [ ] **Step 2.1: Replace the rule with the SSO-aware version**

Open `src/rapid7_healthcheck/audit/user_permission/rules/privileged_user_without_mfa.py` and replace its entire contents with:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.user_permission import register_user_rule
from rapid7_healthcheck.checks import Finding
from rapid7_healthcheck.client import Rapid7ClientError


def _is_privileged(user: dict) -> bool:
    role = user.get("role") or {}
    return bool(role.get("superuser")) or role.get("id") == "global-admin"


def _is_external_auth(user: dict) -> bool:
    """True iff the user authenticates via an external IdP (SAML, LDAP, Kerberos).

    Mirrors the `local_account_when_sso_configured` rule's contract: anything
    other than `authentication.type == "normal"` is treated as external. A
    missing `authentication` field (or empty `type`) is treated as local --
    conservative; preserves prior behavior on malformed user objects.
    """
    auth = user.get("authentication") or {}
    auth_type = auth.get("type")
    if not isinstance(auth_type, str) or not auth_type:
        return False
    return auth_type != "normal"


@register_user_rule
class PrivilegedUserWithoutMfaRule:
    rule_id = "privileged_user_without_mfa"
    rule_name = "Privileged User Without MFA"
    description = (
        "Flags Global Administrator or superuser accounts that authenticate "
        "against InsightVM's local credential store and do not have two-factor "
        "authentication configured. Accounts whose `authentication.type` is "
        "`saml`, `ldap`, or `kerberos` are excluded -- MFA enforcement for "
        "those is the upstream IdP's responsibility, and a single aggregate "
        "info finding lists them so they can be verified at the IdP. Service "
        "accounts that need to authenticate via HTTP Basic Auth necessarily "
        "can't use MFA (the protocol bypasses it); list those in the "
        "`mfa_exempt_logins` knob to suppress findings on them. Requires the "
        "calling key to belong to a Global Administrator: per-user calls to "
        "/api/3/users/{id}/2FA return 401 for non-GA keys."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/managing-users-and-authentication/#enabling-two-factor-authentication",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        exempt = {
            login.strip().lower()
            for login in rule_config.get("mfa_exempt_logins") or []
            if isinstance(login, str)
        }

        users = snapshot.users()
        privileged = [u for u in users if u.get("enabled") and _is_privileged(u)]

        sampled = False
        sample_info: str | None = None
        examined = privileged
        if not full_scan and len(privileged) > sample_size:
            examined = privileged[:sample_size]
            sampled = True
            sample_info = f"checked {len(examined)} of {len(privileged)} privileged users"

        findings: list[Finding] = []
        endpoint_unavailable = False
        users_without_mfa = 0
        users_exempt = 0
        users_succeeded = 0       # at least one 2FA call returned a status
        users_auth_denied: list[dict] = []  # 401s -- disambiguated post-pass
        external_auth_users: list[dict] = []  # NEW: {login, auth_type} per external user

        for u in examined:
            login = (u.get("login") or "").strip()
            if login.lower() in exempt:
                users_exempt += 1
                continue
            if _is_external_auth(u):
                # External-auth users delegate MFA to the IdP -- do NOT call
                # the 2FA endpoint; collect for the aggregate info finding.
                auth_type = (u.get("authentication") or {}).get("type") or ""
                external_auth_users.append({"login": login, "auth_type": auth_type})
                continue
            try:
                mfa = snapshot.user_2fa_enabled(u["id"])
            except Rapid7ClientError as e:
                if e.status_code == 401:
                    # Could be "user has no MFA" OR "calling key lacks GA";
                    # disambiguate post-pass once we know if any user succeeded.
                    users_auth_denied.append(u)
                    continue
                raise
            users_succeeded += 1
            if mfa is None:
                # Endpoint not available on this console at all -- skip the rule honestly.
                endpoint_unavailable = True
                break
            if mfa is False:
                users_without_mfa += 1
                role = u.get("role") or {}
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Privileged user '{login}' (role: {role.get('name', role.get('id', '?'))}) "
                        f"has no MFA configured."
                    ),
                    details={
                        "user_id": u["id"],
                        "login": login,
                        "role_id": role.get("id"),
                        "role_name": role.get("name"),
                        "superuser": bool(role.get("superuser")),
                    },
                ))

        # 404: endpoint absent on this console -- preserve existing behavior.
        if endpoint_unavailable:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "MFA-status endpoint /api/3/users/{id}/2FA returned 404 -- "
                        "this console does not expose 2FA state via API. Audit MFA in the UI."
                    ),
                    details={"reason": "2FA endpoint unavailable"},
                )],
                summary={
                    "privileged_users": len(privileged),
                    "users_examined": len(examined),
                    "endpoint_available": False,
                },
                sampled=sampled,
                sample_info=sample_info,
                sources=list(self.sources),
            )

        # 401 disambiguation: if no user succeeded AND no external user was
        # processed, the calling key likely lacks GA. (External users do NOT
        # count toward "succeeded" because we never called the endpoint for
        # them -- but their presence proves we got past role/auth filtering,
        # so a pure-401 outcome with external users present is ambiguous in
        # a different way and falls through to the per-user 401-as-no-MFA
        # branch below.)
        if users_auth_denied and users_succeeded == 0 and not external_auth_users:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "All privileged users' 2FA status returned HTTP 401. The "
                        "calling key likely lacks Global Administrator privileges, "
                        "which this rule requires. Audit MFA in the Security "
                        "Console UI, or run the audit with a Global Admin key."
                    ),
                    details={"reason": "401 from /api/3/users/{id}/2FA across all users"},
                )],
                summary={
                    "privileged_users": len(privileged),
                    "users_examined": len(examined),
                    "users_auth_denied": len(users_auth_denied),
                    "users_succeeded": 0,
                    "users_external_auth": len(external_auth_users),
                    "endpoint_available": True,
                },
                sampled=sampled,
                sample_info=sample_info,
                sources=list(self.sources),
            )

        # At least one user succeeded (or at least one external user existed)
        # -- 401s on others mean "no MFA configured".
        for u in users_auth_denied:
            login = (u.get("login") or "").strip()
            users_without_mfa += 1
            role = u.get("role") or {}
            findings.append(Finding(
                severity=severity,
                message=(
                    f"Privileged user '{login}' (role: {role.get('name', role.get('id', '?'))}) "
                    f"has no MFA configured (2FA endpoint returned 401)."
                ),
                details={
                    "user_id": u["id"],
                    "login": login,
                    "role_id": role.get("id"),
                    "role_name": role.get("name"),
                    "superuser": bool(role.get("superuser")),
                    "_2fa_status": "401",
                },
            ))

        # Aggregate info finding for external-auth users (if any).
        if external_auth_users:
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(external_auth_users)} privileged users authenticate via "
                    f"external sources (SAML / LDAP / Kerberos). MFA enforcement for "
                    f"these accounts is delegated to the upstream identity provider -- "
                    f"verify it is enforced there. Local InsightVM 2FA does not apply "
                    f"to these accounts."
                ),
                details={
                    "external_auth_user_count": len(external_auth_users),
                    "external_auth_users": external_auth_users[:20],
                },
            ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "privileged_users": len(privileged),
                "users_examined": len(examined),
                "users_without_mfa": users_without_mfa,
                "users_exempt": users_exempt,
                "users_external_auth": len(external_auth_users),
            },
            sampled=sampled,
            sample_info=sample_info,
            sources=list(self.sources),
        )
```

- [ ] **Step 2.2: Run the failing test -- should now pass**

Run: `pytest tests/audit/user_permission/rules/test_privileged_user_without_mfa.py::test_external_saml_user_skipped_no_2fa_call -v`
Expected: PASS.

- [ ] **Step 2.3: Run the full file to confirm no regressions in existing tests**

Run: `pytest tests/audit/user_permission/rules/test_privileged_user_without_mfa.py -v`
Expected: all green.

- [ ] **Step 2.4: Commit Task 1+2**

```bash
git add src/rapid7_healthcheck/audit/user_permission/rules/privileged_user_without_mfa.py tests/audit/user_permission/rules/test_privileged_user_without_mfa.py
git commit -m "feat(audit): SSO-aware privileged_user_without_mfa rule"
```

---

## Task 3: Privileged-MFA -- remaining test cases

**Files:**
- Test: `tests/audit/user_permission/rules/test_privileged_user_without_mfa.py`

- [ ] **Step 3.1: Add the four remaining tests**

Append to the same test file:

```python
def test_mixed_local_and_external(fake_snapshot):
    """One local-without-MFA + 1 SAML + 1 LDAP. The local user gets a fail
    finding; both external users get aggregated into one info finding."""
    fake_snapshot.set_users([
        _user_with_auth(1, "alice", "normal"),
        _user_with_auth(2, "saml-admin", "saml"),
        _user_with_auth(3, "ldap-admin", "ldap"),
    ])
    fake_snapshot.set_user_2fa_enabled(1, False)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "fail"
    assert r.summary["users_without_mfa"] == 1
    assert r.summary["users_external_auth"] == 2
    fail_findings = [f for f in r.findings if f.severity == "fail"]
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(fail_findings) == 1
    assert "alice" in fail_findings[0].message
    assert len(info_findings) == 1
    logins_in_info = {e["login"] for e in info_findings[0].details["external_auth_users"]}
    assert logins_in_info == {"saml-admin", "ldap-admin"}


def test_exempt_wins_over_external(fake_snapshot):
    """A user in mfa_exempt_logins is counted as exempt, not external,
    even when their authentication.type is non-normal."""
    fake_snapshot.set_users([_user_with_auth(1, "saml-svc", "saml")])
    r = PrivilegedUserWithoutMfaRule().run(
        fake_snapshot, "fail", False, 500,
        {"mfa_exempt_logins": ["saml-svc"]},
    )
    assert r.status == "pass"
    assert r.summary["users_exempt"] == 1
    assert r.summary["users_external_auth"] == 0
    # No aggregate info finding (external_auth_users is empty)
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert info_findings == []


def test_all_privileged_external_no_2fa_calls(fake_snapshot):
    """When every privileged user is external, zero 2FA calls happen and
    only the aggregate info finding is emitted; status is pass."""
    fake_snapshot.set_users([
        _user_with_auth(1, "krb-admin-1", "kerberos"),
        _user_with_auth(2, "krb-admin-2", "kerberos"),
    ])
    # Configure user_2fa_enabled to RAISE if called -- proves no call happened.
    from rapid7_healthcheck.client import Rapid7ClientError
    fake_snapshot.set_user_2fa_raises(1, Rapid7ClientError("must not be called", status_code=500))
    fake_snapshot.set_user_2fa_raises(2, Rapid7ClientError("must not be called", status_code=500))
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.summary["users_external_auth"] == 2
    assert r.summary["users_without_mfa"] == 0
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1


def test_missing_authentication_field_treated_as_local(fake_snapshot):
    """If the user has no authentication field, fall back to local-account
    handling (existing 2FA-call path runs)."""
    fake_snapshot.set_users([_user_with_auth(1, "alice", None)])  # no auth field
    fake_snapshot.set_user_2fa_enabled(1, True)
    r = PrivilegedUserWithoutMfaRule().run(fake_snapshot, "fail", False, 500, {})
    assert r.status == "pass"
    assert r.summary["users_external_auth"] == 0
    # users_without_mfa is 0 because mfa was True
```

- [ ] **Step 3.2: Run all four**

Run: `pytest tests/audit/user_permission/rules/test_privileged_user_without_mfa.py -v`
Expected: all green (existing + 5 new tests).

- [ ] **Step 3.3: Commit**

```bash
git add tests/audit/user_permission/rules/test_privileged_user_without_mfa.py
git commit -m "test(audit): add SSO-aware privileged-MFA test coverage"
```

---

## Task 4: Severity bump -- `disabled_user_with_role_bindings`

**Files:**
- Modify: `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py`
- Test: `tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py`

- [ ] **Step 4.1: Read the current rule file to find the line**

Run: `grep -n 'default_severity' src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py`
Expected: one match showing `default_severity = "info"`.

- [ ] **Step 4.2: Bump default severity to warn**

Edit `src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py`:

Change:
```python
    default_severity = "info"
```
To:
```python
    default_severity = "warn"
```

(One-line change. Do not touch any other line.)

- [ ] **Step 4.3: Run existing tests -- they should fail on severity assertions**

Run: `pytest tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py -v`
Expected: failures on any assertion that compares finding severity to `"info"` or expects exit-code/status `"pass"` when findings exist.

- [ ] **Step 4.4: Update the test assertions**

For every failing assertion in `tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py`:
- Replace `severity="info"` (or `severity == "info"`) with `severity="warn"` / `== "warn"`.
- Replace any status assertion that expected `"pass"` with `"warn"` when findings are present.

Be careful: tests that pass an explicit `severity` argument (e.g. `Rule().run(snapshot, "fail", ...)`) override the default -- only update assertions that read finding severities or rule status, not the call sites.

- [ ] **Step 4.5: Re-run the file**

Run: `pytest tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py -v`
Expected: all green.

- [ ] **Step 4.6: Commit**

```bash
git add src/rapid7_healthcheck/audit/user_permission/rules/disabled_user_with_role_bindings.py tests/audit/user_permission/rules/test_disabled_user_with_role_bindings.py
git commit -m "feat(audit): bump disabled_user_with_role_bindings severity to warn"
```

---

## Task 5: Severity bump -- `user_with_role_but_no_access`

**Files:**
- Modify: `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py`
- Test: `tests/audit/user_permission/rules/test_user_with_role_but_no_access.py`

- [ ] **Step 5.1: Bump default severity to warn**

Edit `src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py`:

Change:
```python
    default_severity = "info"
```
To:
```python
    default_severity = "warn"
```

- [ ] **Step 5.2: Run tests, identify failures**

Run: `pytest tests/audit/user_permission/rules/test_user_with_role_but_no_access.py -v`
Expected: failures on info-severity assertions.

- [ ] **Step 5.3: Update test assertions**

Same pattern as Step 4.4 -- `info` → `warn` for severity assertions, `pass` → `warn` for status assertions where findings are present.

- [ ] **Step 5.4: Re-run the file**

Run: `pytest tests/audit/user_permission/rules/test_user_with_role_but_no_access.py -v`
Expected: all green.

- [ ] **Step 5.5: Commit**

```bash
git add src/rapid7_healthcheck/audit/user_permission/rules/user_with_role_but_no_access.py tests/audit/user_permission/rules/test_user_with_role_but_no_access.py
git commit -m "feat(audit): bump user_with_role_but_no_access severity to warn"
```

---

## Task 6: Insight Agent -- add `LATEST_KNOWN_INSIGHT_AGENT_VERSION` constant

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/_agent_version.py`

- [ ] **Step 6.1: Add the constant at the top of the module**

Open `src/rapid7_healthcheck/audit/rules/_agent_version.py` and insert near the top of the module (after the existing imports and any docstring, before the first function definition):

```python
# Tool-maintained "current latest" Insight Agent version. Bumped manually as
# Rapid7 ships new releases. As of 2026-05-04 the latest GA build is 4.1.0.2.
LATEST_KNOWN_INSIGHT_AGENT_VERSION: tuple[int, int, int, int] = (4, 1, 0, 2)
```

- [ ] **Step 6.2: Sanity-check by importing it**

Run: `python -c "from rapid7_healthcheck.audit.rules._agent_version import LATEST_KNOWN_INSIGHT_AGENT_VERSION; print(LATEST_KNOWN_INSIGHT_AGENT_VERSION)"`
Expected: `(4, 1, 0, 2)`.

- [ ] **Step 6.3: Commit**

```bash
git add src/rapid7_healthcheck/audit/rules/_agent_version.py
git commit -m "feat(audit): add LATEST_KNOWN_INSIGHT_AGENT_VERSION constant"
```

---

## Task 7: Insight Agent -- failing test for pinned-mode exact match

**Files:**
- Test: `tests/audit/rules/test_insight_agent_version_currency.py`

- [ ] **Step 7.1: Append the new test (TDD red)**

Append to `tests/audit/rules/test_insight_agent_version_currency.py`:

```python
def test_pinned_mode_exact_match_passes(fake_snapshot):
    """Single agent on the pinned version should pass with no findings,
    summary.reference_mode == 'pinned', no behind/ahead counts."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.1.0.2"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "pass"
    assert r.summary["reference_mode"] == "pinned"
    assert r.summary["reference_version"] == "4.1.0.2"
    assert r.summary["agents_drifted"] == 0
    assert r.summary["agents_ahead_of_pin"] == 0
```

If the test file doesn't import `InsightAgentVersionCurrencyRule` already, add at the top:

```python
from rapid7_healthcheck.audit.rules.insight_agent_version_currency import (
    InsightAgentVersionCurrencyRule,
)
```

- [ ] **Step 7.2: Run the test to verify it fails**

Run: `pytest tests/audit/rules/test_insight_agent_version_currency.py::test_pinned_mode_exact_match_passes -v`
Expected: FAIL -- current rule has no `reference_mode` summary key (KeyError) and computes drift against fleet-newest.

---

## Task 8: Insight Agent -- three-mode implementation

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/insight_agent_version_currency.py`

- [ ] **Step 8.1: Replace the rule with the three-mode version**

Replace the entire contents of `src/rapid7_healthcheck/audit/rules/insight_agent_version_currency.py` with:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules._agent_version import (
    LATEST_KNOWN_INSIGHT_AGENT_VERSION,
    find_agent_version,
)
from rapid7_healthcheck.checks import Finding


def _format_version(v: tuple[int, int, int, int]) -> str:
    return ".".join(str(x) for x in v)


def _parse_version_string(s: str) -> tuple[int, int, int, int] | None:
    """Parse a 4-part dotted version string into a tuple. Returns None on
    any malformedness -- the caller decides whether to skip or fall back."""
    if not isinstance(s, str):
        return None
    parts = s.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        ints = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return (ints[0], ints[1], ints[2], ints[3])


def _resolve_mode(rule_config: dict) -> tuple[str, tuple[int, int, int, int] | None, str | None]:
    """Resolve the (mode, reference_tuple, raw_pinned_string) triple.

    Returns:
        (mode, reference, raw):
            mode in {"pinned", "latest_known", "fleet_newest"}.
            reference is the parsed version tuple, or None for fleet_newest
                (computed later from the fleet) or pinned-with-bad-input.
            raw is the original pinned_version string when mode is "pinned"
                with unparseable input -- used in the skip message.
    """
    pinned_raw = rule_config.get("pinned_version")
    if pinned_raw is not None:
        parsed = _parse_version_string(pinned_raw)
        return ("pinned", parsed, pinned_raw if parsed is None else None)
    if rule_config.get("use_latest_known"):
        return ("latest_known", LATEST_KNOWN_INSIGHT_AGENT_VERSION, None)
    return ("fleet_newest", None, None)


@register
class InsightAgentVersionCurrencyRule:
    rule_id = "insight_agent_version_currency"
    rule_name = "Insight Agent Version Currency"
    description = (
        "Flags Insight Agents whose version is out of step with a reference. "
        "Three modes, in precedence order: (1) pinned -- `pinned_version: "
        "\"4.1.0.2\"` requires every agent to match exactly; both behind-pin "
        "and ahead-of-pin agents are flagged (the latter is a change-control "
        "gap). (2) latest-known -- `use_latest_known: true` compares against "
        "a tool-maintained 'current latest' version, with `version_drift_minor` "
        "tolerance. (3) fleet-newest (default) -- self-bootstrapping comparison "
        "against the newest version observed in the fleet, with "
        "`version_drift_minor` tolerance. Does NOT detect uniform fleet "
        "staleness in fleet-newest mode (different rule territory)."
    )
    default_severity = "warn"
    expensive = False
    sources = [
        "https://docs.rapid7.com/insightvm/insight-agent-overview/",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        drift_threshold = rule_config.get("version_drift_minor", 1)
        try:
            drift_threshold = int(drift_threshold)
        except (TypeError, ValueError):
            drift_threshold = 1

        mode, reference, raw_pinned = _resolve_mode(rule_config)

        # Pinned mode with unparseable input -- skip loudly.
        if mode == "pinned" and reference is None:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"pinned_version '{raw_pinned}' is not a parseable "
                        f"4-part version (e.g. '4.1.0.2'). Fix config or "
                        f"remove the knob to fall back to drift detection."
                    ),
                    details={"reason": "unparseable pinned_version", "pinned_version_raw": raw_pinned},
                )],
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": "pinned",
                    "reference_version": None,
                },
                sources=list(self.sources),
            )

        agents, total = snapshot.agents()

        if snapshot.is_agents_unavailable():
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "/api/3/agents returned 404 -- this console does not expose "
                        "the Insight Agent fleet via API. Audit agent versions via "
                        "the Security Console UI."
                    ),
                    details={"reason": "agents endpoint unavailable"},
                )],
                summary={
                    "agents_total": 0,
                    "endpoint_available": False,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        if total == 0:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message="No Insight Agents deployed -- nothing to compare.",
                    details={"reason": "empty fleet"},
                )],
                summary={
                    "agents_total": 0,
                    "agents_examined": 0,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        # Parse versions from each agent.
        parsed: list[tuple[dict, tuple[int, int, int, int]]] = []
        unparseable = 0
        for agent in agents:
            v = find_agent_version(agent)
            if v is None:
                unparseable += 1
                continue
            parsed.append((agent, v))

        # Fleet-newest needs >=2 parseable agents to compute drift; pinned and
        # latest-known only need >=1 (they have an external reference).
        min_required = 2 if mode == "fleet_newest" else 1
        if len(parsed) < min_required:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                description=self.description,
                severity=severity,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        f"Only {len(parsed)} agent(s) had parseable Insight Agent "
                        f"version strings; need at least {min_required} for "
                        f"{mode} mode."
                    ),
                    details={"reason": "insufficient parseable versions"},
                )],
                summary={
                    "agents_total": total,
                    "agents_examined": len(parsed),
                    "agents_unparseable": unparseable,
                    "reference_mode": mode,
                },
                sources=list(self.sources),
            )

        # Resolve the reference for fleet-newest mode now that we have parsed agents.
        if mode == "fleet_newest":
            reference = max(v for _, v in parsed)

        findings: list[Finding] = []
        drifted = 0
        ahead_of_pin = 0

        for agent, version in parsed:
            host = agent.get("hostName") or agent.get("id") or "?"
            if mode == "pinned":
                if version == reference:
                    continue
                drifted += 1
                if version > reference:
                    ahead_of_pin += 1
                    direction = "ahead"
                    msg = (
                        f"Insight Agent on '{host}' is running "
                        f"{_format_version(version)} -- ahead of pinned version "
                        f"{_format_version(reference)} (change-control gap)."
                    )
                else:
                    direction = "behind"
                    msg = (
                        f"Insight Agent on '{host}' is running "
                        f"{_format_version(version)} -- behind pinned version "
                        f"{_format_version(reference)}."
                    )
                findings.append(Finding(
                    severity=severity,
                    message=msg,
                    details={
                        "agentId": agent.get("agentId"),
                        "hostName": agent.get("hostName"),
                        "observed_version": _format_version(version),
                        "pinned_version": _format_version(reference),
                        "drift_direction": direction,
                    },
                ))
            else:
                # fleet_newest or latest_known -- minor-drift logic.
                minor_drift = (reference[0] - version[0]) * 1000 + (reference[1] - version[1])
                if minor_drift > drift_threshold:
                    drifted += 1
                    if mode == "latest_known":
                        msg = (
                            f"Insight Agent on '{host}' is running "
                            f"{_format_version(version)} -- behind known-current "
                            f"{_format_version(reference)} by {minor_drift} minor "
                            f"version(s)."
                        )
                    else:  # fleet_newest
                        msg = (
                            f"Insight Agent on '{host}' is running "
                            f"{_format_version(version)} -- {minor_drift} minor "
                            f"version(s) behind newest "
                            f"({_format_version(reference)})."
                        )
                    findings.append(Finding(
                        severity=severity,
                        message=msg,
                        details={
                            "agentId": agent.get("agentId"),
                            "hostName": agent.get("hostName"),
                            "observed_version": _format_version(version),
                            "reference_version": _format_version(reference),
                            "minor_drift": minor_drift,
                        },
                    ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        summary: dict = {
            "agents_total": total,
            "agents_examined": len(parsed),
            "agents_unparseable": unparseable,
            "agents_drifted": drifted,
            "reference_version": _format_version(reference),
            "reference_mode": mode,
        }
        if mode == "pinned":
            summary["agents_ahead_of_pin"] = ahead_of_pin
        else:
            summary["drift_threshold"] = drift_threshold

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary=summary,
            sources=list(self.sources),
        )
```

- [ ] **Step 8.2: Re-run the failing test -- should now pass**

Run: `pytest tests/audit/rules/test_insight_agent_version_currency.py::test_pinned_mode_exact_match_passes -v`
Expected: PASS.

- [ ] **Step 8.3: Run the full test file to find existing-test breakage from the summary rename**

Run: `pytest tests/audit/rules/test_insight_agent_version_currency.py -v`
Expected: failures in any existing test that asserts on `summary["newest_version"]` (now `reference_version`) or `details["newest_version"]` (now `reference_version`).

- [ ] **Step 8.4: Update existing-test assertions for the rename**

For every failing assertion in `tests/audit/rules/test_insight_agent_version_currency.py`:
- `summary["newest_version"]` → `summary["reference_version"]`
- `details["newest_version"]` → `details["reference_version"]`
- If a test asserts `summary["reference_mode"]` does NOT exist, change it to expect `"fleet_newest"`.

Don't change behavior -- only rename keys in assertions.

- [ ] **Step 8.5: Re-run**

Run: `pytest tests/audit/rules/test_insight_agent_version_currency.py -v`
Expected: all green.

- [ ] **Step 8.6: Commit**

```bash
git add src/rapid7_healthcheck/audit/rules/insight_agent_version_currency.py tests/audit/rules/test_insight_agent_version_currency.py
git commit -m "feat(audit): three-mode insight_agent_version_currency (pinned/latest_known/fleet_newest)"
```

---

## Task 9: Insight Agent -- remaining test coverage

**Files:**
- Test: `tests/audit/rules/test_insight_agent_version_currency.py`

- [ ] **Step 9.1: Add the remaining 10 tests**

Append to `tests/audit/rules/test_insight_agent_version_currency.py`:

```python
def test_pinned_mode_behind_flagged(fake_snapshot):
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["drift_direction"] == "behind"
    assert r.summary["agents_drifted"] == 1
    assert r.summary["agents_ahead_of_pin"] == 0


def test_pinned_mode_ahead_flagged(fake_snapshot):
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.2.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert len(r.findings) == 1
    assert r.findings[0].details["drift_direction"] == "ahead"
    assert "ahead of pinned" in r.findings[0].message
    assert r.summary["agents_ahead_of_pin"] == 1
    assert r.summary["agents_drifted"] == 1


def test_pinned_mode_mixed_behind_match_ahead(fake_snapshot):
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "behind-h", "version": "4.0.0.0"},
        {"agentId": "b", "hostName": "match-h",  "version": "4.1.0.2"},
        {"agentId": "c", "hostName": "ahead-h",  "version": "4.2.0.0"},
    ], total=3)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert r.summary["agents_drifted"] == 2
    assert r.summary["agents_ahead_of_pin"] == 1
    directions = sorted(f.details["drift_direction"] for f in r.findings)
    assert directions == ["ahead", "behind"]


def test_pinned_mode_unparseable_pin_skipped(fake_snapshot):
    """Bad pinned_version → skipped with a clear info finding; no agent
    pagination happens (we never get to snapshot.agents())."""
    # Deliberately do NOT set any agents -- proves the rule short-circuits.
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "garbage"},
    )
    assert r.status == "skipped"
    assert len(r.findings) == 1
    assert "garbage" in r.findings[0].message
    assert r.findings[0].details["pinned_version_raw"] == "garbage"


def test_latest_known_mode_behind(fake_snapshot):
    """Agent at 4.0.0.0 vs constant 4.1.0.2 = 1 minor behind, threshold default 1
    → not flagged (drift > threshold). Use 3.0.0.0 to make it >1 minor behind."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "3.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["reference_mode"] == "latest_known"
    assert r.summary["reference_version"] == "4.1.0.2"
    assert "behind known-current" in r.findings[0].message


def test_latest_known_mode_within_threshold(fake_snapshot):
    """Agent at 4.0.0.0 with version_drift_minor=5 → within tolerance, pass."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"use_latest_known": True, "version_drift_minor": 5},
    )
    assert r.status == "pass"


def test_pinned_mode_single_agent_not_skipped(fake_snapshot):
    """Pinned mode with one parseable agent must NOT trip the >=2 skip."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"pinned_version": "4.1.0.2"},
    )
    assert r.status == "warn"
    assert r.summary["agents_examined"] == 1


def test_latest_known_mode_single_agent_not_skipped(fake_snapshot):
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "3.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {"use_latest_known": True},
    )
    assert r.status == "warn"
    assert r.summary["agents_examined"] == 1


def test_pinned_takes_precedence_over_latest_known(fake_snapshot):
    """Both knobs set → pinned wins, reference_mode == 'pinned'."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.0.0.0"},
    ], total=1)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500,
        {"pinned_version": "4.1.0.2", "use_latest_known": True},
    )
    assert r.summary["reference_mode"] == "pinned"


def test_fleet_newest_default_mode_unchanged(fake_snapshot):
    """No new knobs → fleet-newest mode, summary keys present."""
    fake_snapshot.set_agents([
        {"agentId": "a", "hostName": "h1", "version": "4.0.0.0"},
        {"agentId": "b", "hostName": "h2", "version": "4.5.0.0"},
    ], total=2)
    r = InsightAgentVersionCurrencyRule().run(
        fake_snapshot, "warn", False, 500, {},
    )
    assert r.summary["reference_mode"] == "fleet_newest"
    assert r.summary["reference_version"] == "4.5.0.0"
```

Note on agent payload shape: `find_agent_version` (in `_agent_version.py`) is the same parser used today; the existing tests in this file already use whichever agent dict shape makes it return a parsed tuple. If `version` as a top-level string doesn't parse, look at how the existing tests in the file populate agents (search for `set_agents` calls) and mirror that exact shape. Do not modify `find_agent_version` -- that's out of scope.

- [ ] **Step 9.2: Run all new tests**

Run: `pytest tests/audit/rules/test_insight_agent_version_currency.py -v`
Expected: all green. If `find_agent_version` doesn't recognize the `version` key, adjust the test fixtures' agent dict shape (add whatever field the parser reads -- typically nested under `software` or similar; look at the existing-test fixtures in the file for the canonical shape).

- [ ] **Step 9.3: Commit**

```bash
git add tests/audit/rules/test_insight_agent_version_currency.py
git commit -m "test(audit): cover all three Insight Agent version-currency modes"
```

---

## Task 10: Snapshot -- add `iter_site_assets` generator

**Files:**
- Modify: `src/rapid7_healthcheck/audit/snapshot.py`
- Modify: `tests/audit/conftest.py`

- [ ] **Step 10.1: Add the snapshot accessor**

Open `src/rapid7_healthcheck/audit/snapshot.py`. Find the existing `asset_sample` method (around line 140). Insert the new method directly after `asset_sample`:

```python
    def iter_site_assets(self, site_id: int):
        """Yield assets for a site one at a time WITHOUT materializing or caching.

        Used by rules that need to break out of the iteration early (e.g. on
        first agent-managed asset found). Distinct from `asset_sample()`, which
        materializes the whole sample and caches it for repeat use. Honors the
        underlying client's pagination -- caller decides when to stop.

        Yields:
            dict: each asset record from /api/3/sites/{id}/assets, in API order.
        """
        yield from self._client.paginate(f"/api/3/sites/{site_id}/assets")
```

- [ ] **Step 10.2: Add the FakeSnapshot mirror + setter**

Open `tests/audit/conftest.py`. Find the existing `set_asset_sample` setter and the `asset_sample` accessor. Add a new setter `set_site_assets_iter` and a new accessor `iter_site_assets`:

In `__init__`, add to the existing dict declarations block:
```python
        self._site_assets_iter: dict[int, list[dict]] = {}
```

In the registration helpers section, after `set_asset_sample`:
```python
    def set_site_assets_iter(self, site_id: int, assets: list[dict]) -> None:
        """Configure iter_site_assets() to yield this list for the given site."""
        self._site_assets_iter[site_id] = assets
```

In the EnvSnapshot mirror section, after `asset_sample`:
```python
    def iter_site_assets(self, site_id: int):
        if site_id not in self._site_assets_iter:
            raise AssertionError(
                f"FakeSnapshot.iter_site_assets({site_id}) not registered"
            )
        yield from self._site_assets_iter[site_id]
```

- [ ] **Step 10.3: Verify the existing test suite still passes (no rule uses iter_site_assets yet)**

Run: `pytest -v`
Expected: all green. The new methods are unused; no behavior changes.

- [ ] **Step 10.4: Commit**

```bash
git add src/rapid7_healthcheck/audit/snapshot.py tests/audit/conftest.py
git commit -m "feat(snapshot): add iter_site_assets generator for bounded per-site pagination"
```

---

## Task 11: `agent_unauth_collision` -- failing test for short-circuit

**Files:**
- Test: `tests/audit/rules/test_agent_unauth_collision.py`

- [ ] **Step 11.1: Append the new test**

Append to `tests/audit/rules/test_agent_unauth_collision.py`:

```python
def test_short_circuits_on_first_agent_match(fake_snapshot):
    """Site with 50 assets where only the 3rd is agent-managed. Rule must
    consume exactly 3 items from the iterator and then break."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "ProdSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])

    consumed: list[int] = []

    def asset_gen():
        for i in range(50):
            consumed.append(i)
            if i == 2:
                yield {"id": 100 + i, "agent": {"agentId": "abc"}}
            else:
                yield {"id": 100 + i}

    fake_snapshot.set_site_assets_iter(1, list(asset_gen()))
    # Reset consumed because list(asset_gen()) above already drained it;
    # we want to count what the RULE consumes when it iterates the registered
    # list. Switch to a different counting strategy: wrap the registered list
    # in a counting iterator via monkey-patching iter_site_assets.

    consumed.clear()
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 500, {})

    assert r.status == "fail"
    # Rule consumed assets 100, 101, 102 only (broke after finding agent on 102).
    assert consumed == [100, 101, 102]
    f = [f for f in r.findings if f.severity == "fail"][0]
    assert f.details["examined"] == 3
    assert f.details["short_circuited"] is True
```

- [ ] **Step 11.2: Run -- expect FAIL**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py::test_short_circuits_on_first_agent_match -v`
Expected: FAIL -- current rule still uses `asset_sample` and doesn't expose `examined` or `short_circuited` in details.

---

## Task 12: `agent_unauth_collision` -- bounded implementation

**Files:**
- Modify: `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py`

- [ ] **Step 12.1: Replace the rule with the bounded version**

Replace the entire contents of `src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py` with:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult, register
from rapid7_healthcheck.audit.rules.site_vuln_template_no_creds import _site_has_credentials
from rapid7_healthcheck.checks import Finding


def _has_agent_history(history) -> bool:
    if not isinstance(history, list):
        return False
    return any((h.get("type") or "").upper() == "AGENT-IMPORT" for h in history)


def _asset_is_agent_managed(snapshot, asset: dict) -> bool:
    """Combine the cheap signal with the inline-history fallback."""
    cheap = snapshot.asset_has_agent(asset)
    if cheap is True:
        return True
    if cheap is False:
        return False
    return _has_agent_history(asset.get("history"))


@register
class AgentUnauthCollisionRule:
    rule_id = "agent_unauth_collision"
    rule_name = "Insight Agent Asset Scanned Without Authentication"
    description = (
        "Sites running unauthenticated vulnerability scans against assets that "
        "already have the Insight Agent installed. The agent produces strictly "
        "richer authenticated data; redundant unauth scans add load, cause "
        "asset-correlation drift, and (prior to console release 6.6.229) could "
        "degrade results. In fast mode (`full_scan: false`), per-site asset "
        "enumeration is bounded by `audit.sample_size` and short-circuits on "
        "the first agent-managed asset found. Sites that exceed the per-site "
        "cap without a match are listed in a single aggregate info finding so "
        "the gap is visible. Run with `full_scan: true` to remove the cap."
    )
    default_severity = "fail"
    expensive = True
    sources = [
        "https://docs.rapid7.com/insightvm/security-console-best-practices/",
        "https://docs.rapid7.com/release-notes/insightvm/20231129/",
        "https://docs.rapid7.com/insightvm/correlate-assets-with-insight-agent-uuids/",
        "https://discuss.rapid7.com/t/problem-with-conflicting-ip-fo-assets-home-office/10539",
    ]

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        per_site_cap = None if full_scan else sample_size

        findings: list[Finding] = []
        sites_examined = 0
        sites_flagged = 0
        truncated_sites: list[dict] = []  # {site_id, name, total_assets}

        for site in snapshot.sites():
            sid = site["id"]
            name = site.get("name", f"id={sid}")
            tpl_id = snapshot.site_scan_template_id(site)
            if not tpl_id:
                continue
            tpl = snapshot.scan_template(tpl_id)
            if not snapshot.template_vuln_enabled(tpl):
                continue
            if _site_has_credentials(snapshot, sid):
                continue

            sites_examined += 1
            total_assets = snapshot.site_asset_count(sid)

            examined = 0
            agent_found = False
            for asset in snapshot.iter_site_assets(sid):
                examined += 1
                if _asset_is_agent_managed(snapshot, asset):
                    agent_found = True
                    break
                if per_site_cap is not None and examined >= per_site_cap:
                    break

            if agent_found:
                sites_flagged += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Site '{name}' runs unauthenticated vuln scans, and at "
                        f"least 1 of {examined} sampled assets is Insight "
                        f"Agent-managed (total site assets: {total_assets}). "
                        f"Stop unauth scanning where the agent already covers "
                        f"the host."
                    ),
                    details={
                        "site_id": sid,
                        "scan_template_id": tpl_id,
                        "examined": examined,
                        "total_assets": total_assets,
                        "sampled": per_site_cap is not None and examined >= 1 and total_assets > examined,
                        "short_circuited": True,
                    },
                ))
            elif per_site_cap is not None and examined >= per_site_cap and total_assets > examined:
                truncated_sites.append({
                    "site_id": sid,
                    "name": name,
                    "total_assets": total_assets,
                })

        if truncated_sites:
            findings.append(Finding(
                severity="info",
                message=(
                    f"{len(truncated_sites)} sites exceeded the per-site sample "
                    f"cap ({per_site_cap} assets) without finding an Insight "
                    f"Agent -- verify in the Security Console UI: "
                    f"{', '.join(s['name'] for s in truncated_sites[:20])}."
                ),
                details={
                    "truncated_site_count": len(truncated_sites),
                    "cap": per_site_cap,
                    "truncated_sites": truncated_sites[:20],
                },
            ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "sites_examined": sites_examined,
                "sites_flagged": sites_flagged,
                "sites_truncated": len(truncated_sites),
                "per_site_cap": per_site_cap,
            },
            sources=list(self.sources),
        )
```

- [ ] **Step 12.2: Run the new test -- should now pass**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py::test_short_circuits_on_first_agent_match -v`
Expected: PASS.

- [ ] **Step 12.3: Run the full file -- many existing tests will fail because they used `set_asset_sample` and asserted on `details.agent_count`**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`
Expected: failures on existing tests. They now need to:
- Call `set_site_assets_iter(...)` AND `set_site_asset_count(...)` instead of `set_asset_sample(...)`.
- Assert on `details["examined"]` instead of `details["agent_count"]`.
- Assert on `details["short_circuited"]` where applicable.

---

## Task 13: `agent_unauth_collision` -- fix existing tests

**Files:**
- Test: `tests/audit/rules/test_agent_unauth_collision.py`

- [ ] **Step 13.1: Update each existing test in the file**

For every existing test in `tests/audit/rules/test_agent_unauth_collision.py`, replace the per-test setup pattern as follows:

**Old pattern:**
```python
    fake_snapshot.set_asset_sample(1, [<assets>], total=N)
```

**New pattern:**
```python
    fake_snapshot.set_site_asset_count(1, N)
    fake_snapshot.set_site_assets_iter(1, [<assets>])
```

For assertions:
- `f.details["agent_count"] == N` → `f.details["examined"] >= 1` (we now stop at first hit; exact count is no longer counted past 1 unless the first asset itself is the only one yielded).
- `f.details["sample_size"]` → `f.details["examined"]`
- `f.details["total_assets"]` is unchanged.
- For tests asserting `r.sampled` and `r.sample_info`: those properties are now `False` / `None` because the new rule doesn't set them -- instead the truncation info finding carries the disclosure. Update those tests to assert on `r.summary["sites_truncated"]` and / or `r.summary["per_site_cap"]` as appropriate.

The pre-existing `test_uses_cheap_agent_signal_when_available` test had two assets and asserted `agent_count == 2`. Under the new rule this becomes `examined == 1` (we break on the first cheap-signal asset). Update its assertion to `examined == 1` and add `short_circuited == True`.

The pre-existing `test_sampling_recorded` test asserted `r.sampled` and `"of 4200" in r.sample_info`. Under the new rule, with one agent on the first asset (so the rule short-circuits immediately), the meaningful new assertion is `r.summary["per_site_cap"] == 500` and `r.findings[0].details["total_assets"] == 4200`. Update accordingly.

- [ ] **Step 13.2: Re-run the file**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`
Expected: all green.

- [ ] **Step 13.3: Commit Task 11+12+13**

```bash
git add src/rapid7_healthcheck/audit/rules/agent_unauth_collision.py tests/audit/rules/test_agent_unauth_collision.py
git commit -m "perf(audit): bound agent_unauth_collision per-site asset enumeration

Fixes the ~21-minute timeout observed in production by short-circuiting
on first agent-managed asset found per site and capping per-site
pagination at audit.sample_size in fast mode. full_scan: true opts out.
Truncated sites are listed in a single aggregate info finding.

Drops details.agent_count from per-site fail findings (replaced by
details.examined and details.short_circuited)."
```

---

## Task 14: `agent_unauth_collision` -- new test cases

**Files:**
- Test: `tests/audit/rules/test_agent_unauth_collision.py`

- [ ] **Step 14.1: Add the cap, full-scan, aggregate-cap, status, and interaction tests**

Append to `tests/audit/rules/test_agent_unauth_collision.py`:

```python
def test_per_site_cap_no_agent_truncates(fake_snapshot):
    """Site with 1000 assets, none agent-managed, sample_size=100. Rule
    consumes exactly 100, no per-site fail finding, site appears in the
    aggregate info finding's truncated_sites list."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 1000)
    # 1000 assets, none agent-managed (no agent block, no AGENT-IMPORT history).
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert len(consumed) == 100  # capped at sample_size
    fail_findings = [f for f in r.findings if f.severity == "fail"]
    assert fail_findings == []
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert info_findings[0].details["truncated_site_count"] == 1
    assert info_findings[0].details["truncated_sites"][0]["site_id"] == 1
    assert r.summary["sites_truncated"] == 1
    assert r.summary["per_site_cap"] == 100


def test_full_scan_disables_cap(fake_snapshot):
    """full_scan=True → no cap, all 1000 assets consumed, no truncation."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 1000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", True, 100, {})

    assert len(consumed) == 1000  # no cap in full_scan mode
    info_findings = [f for f in r.findings if f.severity == "info"]
    assert info_findings == []
    assert r.summary["sites_truncated"] == 0
    assert r.summary["per_site_cap"] is None


def test_aggregate_info_finding_caps_at_20(fake_snapshot):
    """25 truncated sites → info finding's truncated_sites list is capped at 20,
    but the count in the message reflects the true total."""
    sites = [_site(i, "tpl-vuln", f"Site{i}") for i in range(1, 26)]
    fake_snapshot.set_sites(sites)
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_shared_credentials([])
    for s in sites:
        sid = s["id"]
        fake_snapshot.set_site_credentials(sid, [])
        fake_snapshot.set_site_asset_count(sid, 200)
        fake_snapshot.set_site_assets_iter(sid, [{"id": i} for i in range(200)])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    info_findings = [f for f in r.findings if f.severity == "info"]
    assert len(info_findings) == 1
    assert info_findings[0].details["truncated_site_count"] == 25
    assert len(info_findings[0].details["truncated_sites"]) == 20
    assert "25 sites" in info_findings[0].message


def test_truncated_aggregate_does_not_lift_status(fake_snapshot):
    """Only truncated sites, no fail findings → status is 'pass', not 'info'."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "BigSite")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 1000)
    fake_snapshot.set_site_assets_iter(1, [{"id": i} for i in range(1000)])

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert r.status == "pass"


def test_short_circuit_in_full_scan_mode(fake_snapshot):
    """full_scan=True still short-circuits on first agent -- pagination consumed
    exactly 1 item even with 5000 total assets."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Huge")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 5000)
    fake_snapshot.set_site_assets_iter(1, [
        {"id": 0, "agent": {"agentId": "yes"}},
        *[{"id": i} for i in range(1, 5000)],
    ])

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", True, 100, {})

    assert consumed == [0]
    assert r.status == "fail"


def test_cap_and_short_circuit_interact_correctly(fake_snapshot):
    """sample_size=100, agent on the 50th asset → consumed=50, site flagged
    (short-circuit wins over cap)."""
    fake_snapshot.set_sites([_site(1, "tpl-vuln", "Mid")])
    fake_snapshot.set_scan_template("tpl-vuln", {
        "id": "tpl-vuln", "name": "Vuln",
        "vulnerabilityChecks": {"enabled": True},
    })
    fake_snapshot.set_site_credentials(1, [])
    fake_snapshot.set_shared_credentials([])
    fake_snapshot.set_site_asset_count(1, 500)
    assets = [{"id": i} for i in range(500)]
    assets[49] = {"id": 49, "agent": {"agentId": "found"}}
    fake_snapshot.set_site_assets_iter(1, assets)

    consumed: list[int] = []
    original_iter = fake_snapshot.iter_site_assets

    def counting_iter(site_id):
        for asset in original_iter(site_id):
            consumed.append(asset["id"])
            yield asset
    fake_snapshot.iter_site_assets = counting_iter

    r = AgentUnauthCollisionRule().run(fake_snapshot, "fail", False, 100, {})

    assert len(consumed) == 50  # short-circuited at agent hit, before reaching cap
    assert r.status == "fail"
    fail_findings = [f for f in r.findings if f.severity == "fail"]
    assert fail_findings[0].details["examined"] == 50
```

- [ ] **Step 14.2: Run all new tests**

Run: `pytest tests/audit/rules/test_agent_unauth_collision.py -v`
Expected: all green.

- [ ] **Step 14.3: Commit**

```bash
git add tests/audit/rules/test_agent_unauth_collision.py
git commit -m "test(audit): cover bounded agent_unauth_collision (cap, full_scan, aggregate, interactions)"
```

---

## Task 15: Documentation -- README rule-table updates

**Files:**
- Modify: `README.md`

- [ ] **Step 15.1: Find each affected rule row**

Run: `grep -n -E 'privileged_user_without_mfa|disabled_user_with_role_bindings|user_with_role_but_no_access|insight_agent_version_currency|agent_unauth_collision' README.md`
Expected: at least one row per rule, plus possibly per-rule subsections.

- [ ] **Step 15.2: Update each row**

For each rule:

- **`privileged_user_without_mfa`** -- modify the description column (or its prose subsection) to mention: "External-auth users (SAML/LDAP/Kerberos) are excluded from local 2FA checks; their MFA enforcement is delegated to the IdP and they are surfaced in a single aggregate info finding."
- **`disabled_user_with_role_bindings`** -- change the default-severity column from `info` to `warn`.
- **`user_with_role_but_no_access`** -- change the default-severity column from `info` to `warn`.
- **`insight_agent_version_currency`** -- add a sentence: "Three modes (in precedence): `pinned_version: \"4.1.0.2\"` for exact match (flags both behind and ahead), `use_latest_known: true` for tool-maintained latest-known reference, otherwise self-bootstrapping fleet-newest."
- **`agent_unauth_collision`** -- add a sentence: "In fast mode, per-site enumeration is capped at `audit.sample_size` and short-circuits on first agent-managed asset; sites that hit the cap without a match are listed in a single aggregate info finding. Set `full_scan: true` to remove the cap."

Be conservative -- only modify the cells/sentences identified above. Do not restructure the README.

- [ ] **Step 15.3: Commit**

```bash
git add README.md
git commit -m "docs(readme): describe SSO-aware MFA, severity bumps, agent rule modes, bounded enumeration"
```

---

## Task 16: Documentation -- example config

**Files:**
- Modify: `docs/examples/config.yaml`

- [ ] **Step 16.1: Locate the `insight_agent_version_currency` rule block**

Run: `grep -n -A 5 'insight_agent_version_currency' docs/examples/config.yaml`
Expected: a YAML block under `audit.rules.insight_agent_version_currency:`.

- [ ] **Step 16.2: Add the new commented-out knobs to that block**

Edit `docs/examples/config.yaml`. Under the `insight_agent_version_currency:` block (preserving any existing keys), add (commented):

```yaml
      # Pin to an exact version for change-control-managed fleets. When set,
      # both behind-pin and ahead-of-pin agents are flagged. Mutually exclusive
      # with use_latest_known (pinned wins).
      # pinned_version: "4.1.0.2"

      # Compare against the tool-maintained "current latest" Insight Agent
      # version. Honors version_drift_minor as the tolerance.
      # use_latest_known: false
```

- [ ] **Step 16.3: Locate the two severity-bumped rule blocks**

Run: `grep -n -B 1 -A 3 -E 'disabled_user_with_role_bindings|user_with_role_but_no_access' docs/examples/config.yaml`

If the example file renders explicit `severity:` keys for these rules, change them from `info` to `warn`. If the rules are listed without explicit severity (relying on the default), no change needed for those blocks.

- [ ] **Step 16.4: Locate the `agent_unauth_collision` block**

Run: `grep -n -A 3 'agent_unauth_collision' docs/examples/config.yaml`

Add a comment above (or near) the rule explaining the sample_size interaction:

```yaml
      # Note: in fast mode (audit.full_scan: false), this rule's per-site
      # enumeration is capped at audit.sample_size and short-circuits on the
      # first agent-managed asset found. Sites that exceed the cap without a
      # match are listed in a single aggregate info finding. Set
      # audit.full_scan: true to remove the cap.
```

- [ ] **Step 16.5: Validate the example config still parses**

Run: `python -c "from rapid7_healthcheck.config import load_config; load_config('docs/examples/config.yaml')"`
Expected: no exceptions. (If the example file requires a Rapid7 URL or other field that the loader validates, the command will print an error indicating which field -- that means the test loader needs the missing field; check the existing CI / test setup for how it loads the example.)

If `load_config` enforces fields the example doesn't have on its own, fall back to a YAML syntax check:
Run: `python -c "import yaml; yaml.safe_load(open('docs/examples/config.yaml'))"`
Expected: no exceptions.

- [ ] **Step 16.6: Commit**

```bash
git add docs/examples/config.yaml
git commit -m "docs(config): document pinned_version/use_latest_known and agent_unauth_collision cap"
```

---

## Task 17: CHANGELOG entry

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 17.1: Read the top of the CHANGELOG to understand the format**

Run: `grep -n -E '^## |^### ' CHANGELOG.md | head -20`
Expected: section headers showing the project's CHANGELOG style (typically Keep-a-Changelog: `## [unreleased]` or `## X.Y.Z`).

- [ ] **Step 17.2: Add the entry**

Edit `CHANGELOG.md`. Add at the top (under the existing top-level header, above the most recent released version) -- adapt the version number to whatever the project's "next release" target is (look at `backlog.md` or the most recent commit's `release: X.Y.Z` to infer):

```markdown
## [unreleased]

### Changed
- **`privileged_user_without_mfa`**: SSO-aware. Privileged accounts whose
  `authentication.type` is `saml`, `ldap`, or `kerberos` no longer trigger
  per-user `fail` findings; they are listed in a single aggregate `info`
  finding noting that MFA enforcement is delegated to the upstream IdP. New
  `summary.users_external_auth` count.
- **`disabled_user_with_role_bindings`**: default severity bumped from `info`
  to `warn`. **Behavior change**: when this rule fires, the run's exit code
  now becomes `1` (warn) instead of `0` (info).
- **`user_with_role_but_no_access`**: default severity bumped from `info` to
  `warn`. Same exit-code impact.
- **`insight_agent_version_currency`**: now supports three reference-version
  modes via new optional knobs.
  - `pinned_version: "4.1.0.2"` -- exact-match mode; flags both behind-pin
    and ahead-of-pin agents (the latter is a change-control gap).
  - `use_latest_known: true` -- compares against a tool-maintained constant
    (currently `4.1.0.2`); honors `version_drift_minor` tolerance.
  - Otherwise: existing fleet-newest behavior, unchanged.
  - **Summary key rename**: `newest_version` → `reference_version`. New keys
    `reference_mode` (always present) and `agents_ahead_of_pin` (pinned mode
    only). Downstream consumers of the JSON state blob need to update.
- **`agent_unauth_collision`**: bounded per-site asset enumeration to fix the
  ~21-minute timeout observed in production. Per-site enumeration now
  short-circuits on first agent-managed asset and is capped at
  `audit.sample_size` in fast mode. Sites that exceed the cap without a
  match are listed in a single aggregate `info` finding. `full_scan: true`
  removes the cap.
  - **Finding-detail change**: `details.agent_count` and `details.sample_size`
    are removed; replaced by `details.examined` and `details.short_circuited`.
    Downstream parsers need to update.
  - New summary keys: `sites_truncated`, `per_site_cap`.
```

- [ ] **Step 17.3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record SSO-MFA, severity bumps, agent rule modes, bounded enumeration"
```

---

## Task 18: Final verification

- [ ] **Step 18.1: Run the full test suite**

Run: `pytest -v`
Expected: all green.

- [ ] **Step 18.2: Re-verify the read-only invariant**

Run: `grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/`
Expected: no matches. (We only added one new snapshot accessor that uses GET-only `client.paginate()`.)

- [ ] **Step 18.3: Smoke-import sanity**

Run: `python -c "from rapid7_healthcheck.audit import _RULE_REGISTRY; from rapid7_healthcheck.audit.user_permission import _USER_RULE_REGISTRY; import rapid7_healthcheck.audit; import rapid7_healthcheck.audit.user_permission; print('audit rules:', sorted(_RULE_REGISTRY)); print('user rules:', sorted(_USER_RULE_REGISTRY))"`
Expected: Both rule sets enumerate and contain the modified rules. No import errors.

- [ ] **Step 18.4: Final summary commit if any housekeeping changed**

Run: `git status`
Expected: clean working tree (everything already committed in earlier tasks). If anything is dirty, inspect and decide whether it belongs in a commit or should be reverted.

---

## Notes for the implementer

- **Why no `config.py` change despite the spec saying "extend validator":** the spec was over-broad. `RuleConfig.knobs` is built as `{k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}` -- a passthrough dict with no per-rule sub-key validation. Adding `pinned_version` / `use_latest_known` requires no validator changes; they're just two more passthrough keys. Don't touch `config.py`.

- **TDD discipline:** Tasks 1, 7, 11 all follow the strict red-green pattern. Tasks 4, 5 are severity-only edits where the existing tests are the ones that go red -- that's also TDD, just with the test as the canary.

- **Why the rule rewrites are full-file replacements rather than surgical edits:** the changes touch the body of `run()` substantially. Replacing the whole file is easier to review (no chance of leaving stray old logic in place) and the rules are short enough (~150-200 lines) for whole-file replacement to be reasonable.

- **`asset_sample()` still exists.** The new `iter_site_assets()` is additive. Other rules continue to use `asset_sample()`. Do not remove `asset_sample()` -- it has other consumers.

- **Avoid scope creep.** The spec's "Out of scope" section is binding: do NOT add `pinned_tolerance`, do NOT add `agent_asset_ids`, do NOT add per-truncated-site individual findings, do NOT cross-reference `/api/3/authentication_sources`. If you find yourself wanting any of these, stop and surface to the user -- they're deliberate non-decisions.
