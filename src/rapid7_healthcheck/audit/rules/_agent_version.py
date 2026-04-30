"""Parse Rapid7 Insight Agent versions from /api/3/agents `software[]` entries.

The Rapid7 v3 API does not expose the agent's own version as a top-level field.
Instead, the agent binary appears as a `software[]` entry with vendor=`Rapid7`
and product matching `Insight Agent` (case-insensitive). This module finds and
parses that entry.
"""
from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+)(?:\.(\d+))?)?$")


def parse_version(s: str) -> tuple[int, int, int, int] | None:
    """Parse '4.0.12.14' or '4.0.12' or '4.0' into (major, minor, patch, build).

    Missing trailing components default to 0. Returns None if `s` doesn't
    match the expected dotted-integer pattern.
    """
    if not isinstance(s, str) or not s:
        return None
    m = _VERSION_RE.match(s)
    if m is None:
        return None
    return (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)) if m.group(3) is not None else 0,
        int(m.group(4)) if m.group(4) is not None else 0,
    )


def find_agent_version(agent: dict) -> tuple[int, int, int, int] | None:
    """Extract the Rapid7 Insight Agent version from an agent.software[] block.

    Looks for the first entry where vendor == 'Rapid7' (case-insensitive) and
    product contains 'Insight Agent' (case-insensitive). Returns the parsed
    version tuple, or None if no such entry exists or its version string is
    unparseable.
    """
    software = agent.get("software") or []
    if not isinstance(software, list):
        return None
    for entry in software:
        if not isinstance(entry, dict):
            continue
        vendor = entry.get("vendor")
        product = entry.get("product")
        if not isinstance(vendor, str) or not isinstance(product, str):
            continue
        if vendor.lower() != "rapid7":
            continue
        if "insight agent" not in product.lower():
            continue
        return parse_version(entry.get("version"))
    return None
