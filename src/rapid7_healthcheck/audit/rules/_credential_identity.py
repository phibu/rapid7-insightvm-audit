"""Shared credential-identity helpers for the credential-governance rules.

Rule-layer helpers (they interpret credential JSON; they do not fetch). Used by
``site_credential_centralization_candidates`` and ``duplicate_credential_clusters``.

The **dedup key** identifies "the same credential" without ever touching a
secret: on GET, Rapid7 does not return credential passwords (they are
write-only), and keying on a secret would be a leak regardless. We key on the
non-secret identity -- service type, username, domain, and host/port
restriction. See CONTEXT.md and issue #33.
"""
from __future__ import annotations

import re
from typing import Any

# Default name pattern marking a credential as *intentionally* site-local
# (excluded from centralization findings). Operator-overridable via the rule's
# `local_name_pattern` knob. Example: `LOCAL_EU1_db_admin`.
DEFAULT_LOCAL_NAME_PATTERN = r"^LOCAL_"


def credential_key(cred: dict) -> tuple:
    """The non-secret identity of a credential, used to detect "the same"
    credential across sites.

    Key = ``(service, username, domain, hostRestriction, portRestriction)``.
    Never includes the password (write-only on GET; a secret has no place in a
    grouping key). Missing parts normalize to ``None`` so two creds that differ
    only by an absent-vs-empty field still group together.
    """
    acct = cred.get("account") or {}

    def _norm(v: Any) -> Any:
        if v is None:
            return None
        s = str(v).strip()
        return s or None

    return (
        _norm(acct.get("service")),
        _norm(acct.get("username")),
        _norm(acct.get("domain")),
        _norm(cred.get("hostRestriction")),
        _norm(cred.get("portRestriction")),
    )


def key_label(key: tuple) -> str:
    """Human-readable rendering of a credential key for finding messages.

    ``(service, username, domain, host, port)`` → e.g. ``ssh root@10.0.0.0/24``
    or ``cifs administrator@CORP``. Omits absent parts.
    """
    service, username, domain, host, port = key
    user = username or "?"
    if domain:
        user = f"{user}@{domain}"
    target = host or ""
    if port:
        target = f"{target}:{port}" if target else f":{port}"
    parts = [p for p in [service or "?", user, target] if p]
    return " ".join(parts)


def compile_local_pattern(rule_config: dict) -> re.Pattern[str]:
    """Compile the `local_name_pattern` knob (default ``^LOCAL_``).

    A credential whose ``name`` matches is treated as an intentional local and
    excluded from centralization findings. A malformed user pattern falls back
    to the default rather than crashing the run.
    """
    pat = (rule_config or {}).get("local_name_pattern") or DEFAULT_LOCAL_NAME_PATTERN
    try:
        return re.compile(pat)
    except re.error:
        return re.compile(DEFAULT_LOCAL_NAME_PATTERN)


def is_intentional_local(cred: dict, local_pattern: re.Pattern[str]) -> bool:
    """Whether a credential's name marks it as an intentional site-local cred."""
    name = cred.get("name")
    return isinstance(name, str) and bool(local_pattern.search(name))
