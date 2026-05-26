"""Shared heuristic for identifying the console-co-located local scan engine.

Used by both the operational scan-engines check and the configuration
audit (local_engine_production_scope rule). v3 ScanEngine has no
first-class local/distributed flag, so we detect by loopback address or
the default name Rapid7 ships.
"""
from __future__ import annotations

_LOOPBACK_ADDRESSES = {"localhost", "127.0.0.1", "::1"}
_DEFAULT_LOCAL_NAMES = {"local scan engine"}


def is_local_engine(engine: dict, extra_names: set[str] | None = None) -> bool:
    """Return True if `engine` is the console-local scan engine.

    Detects either a loopback address or the default name. `extra_names`
    is for audit rules that thread an operator-overridden name list
    (lower-cased) from their `rule_config`; pass None when no override
    is available (op-check rules today do not receive `rule_config`).
    """
    addr = (engine.get("address") or "").strip().lower()
    if addr in _LOOPBACK_ADDRESSES:
        return True
    name = (engine.get("name") or "").strip().lower()
    if name in _DEFAULT_LOCAL_NAMES:
        return True
    if extra_names and name in extra_names:
        return True
    return False
