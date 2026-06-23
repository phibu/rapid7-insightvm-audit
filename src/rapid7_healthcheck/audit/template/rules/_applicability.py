"""Shared rule-layer helpers for the discovery-settings template rules.

These are *applicability* and *parsing* helpers, deliberately kept at the rule
layer rather than on ``EnvSnapshot`` — they interpret template JSON, they do
not fetch data. See CONTEXT.md "Scan template".
"""
from __future__ import annotations

import re

from rapid7_healthcheck.audit.snapshot import EnvSnapshot


def performs_discovery(template: dict) -> bool:
    """Whether a scan template actually performs asset discovery.

    Discovery-settings rules (``tcp_reset``, ``retry_limit``, ``timeout``,
    ``udp_all_ports``) only apply to templates that discover: vulnerability-
    enabled templates *and* discovery-only templates. A policy-only template
    (``policyEnabled: true``, ``vulnerabilityEnabled: false``,
    ``discoveryOnly: false``) carries discovery settings in its JSON but they
    are inert — flagging them would be noise. See the project ADR/CONTEXT for
    why discovery-only is included (the purest discovery case).
    """
    if EnvSnapshot.template_vuln_enabled(template):
        return True
    return template.get("discoveryOnly") is True


# ISO-8601 duration as InsightVM emits it for discovery timeouts: ``PT0.5S``,
# ``PT3S``, ``P30S`` (seconds only, optional fractional). The spec types these
# as free-form strings and documents the ``PnS`` / ``PTnS`` shape; we parse only
# that shape. Anything else (unexpected format, older-console variant) returns
# None and the caller skips that template — never crash, never false-flag.
_DURATION_RE = re.compile(r"^P(?:T)?(\d+(?:\.\d+)?)S$", re.IGNORECASE)


def parse_iso8601_seconds_to_ms(value: object) -> float | None:
    """Parse an InsightVM ISO-8601 second-duration string to milliseconds.

    Returns None for anything that is not a ``PnS``/``PTnS`` string — the
    caller treats None as "unparseable, skip this template". Mirrors the
    defensive posture of ``telnet_regex_invalid``: a malformed value is never
    allowed to crash the run or produce a false finding.
    """
    if not isinstance(value, str):
        return None
    m = _DURATION_RE.match(value.strip())
    if not m:
        return None
    try:
        return float(m.group(1)) * 1000.0
    except (TypeError, ValueError):
        return None
