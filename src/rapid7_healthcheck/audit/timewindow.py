"""Temporal parsing shared across both verticals (see CONTEXT.md "timewindow").

The single deep module owning the InsightVM time-shape parsing the audit rules
and operational checks used to copy: ISO-8601 timestamps, ``PT[nH][nM][nS]``
durations, and half-open interval overlap. Lives beside ``rule_rollup`` because
the ``checks -> audit`` import direction is already the convention.

``parse_iso`` returns an **always-aware** UTC datetime: a parse that lands naive
(the Console sometimes omits the offset) is forced to UTC, so a downstream
``aware_now - parsed`` subtraction cannot raise ``TypeError``. That contract was
the cloud-drift copy's; the extraction propagates it to all six former callers.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# ISO-8601 duration as InsightVM emits it for scan/report windows: PT[nH][nM][nS].
_DURATION_RE = re.compile(r"^P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


def parse_iso(value: object) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    # The Console/Cloud emit "...Z"; fromisoformat in 3.11 accepts "+00:00" but
    # not a bare "Z". If the offset is omitted entirely, treat the naive result
    # as UTC so the value is always tz-aware.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_duration(value: str | None) -> timedelta:
    if not value:
        return timedelta(0)
    m = _DURATION_RE.match(value)
    if not m:
        return timedelta(0)
    h, mn, s = (int(x) if x else 0 for x in m.groups())
    return timedelta(hours=h, minutes=mn, seconds=s)


def windows_intersect(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end
