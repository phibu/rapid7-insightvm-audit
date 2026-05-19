from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.checks import Finding

logger = logging.getLogger(__name__)


_DEFAULT_LAST_SEEN_MAX_AGE_HOURS = 24


def _coerce_positive_int(value, *, name: str, default: int) -> int:
    """Return value as a positive int; fall back to ``default`` on bad input.

    Rejects ``True``/``False`` (bool is an int subclass — accepting it is
    almost always a user typo). Rejects floats with a fractional part
    (``0.5`` silently truncating to ``0`` would set the threshold equal
    to ``now()`` and flag every engine as stale). Rejects zero and
    negatives. Anything rejected logs a warning and falls back to
    ``default`` rather than raising — rule loaders that aren't validated
    upstream shouldn't take down the whole audit on one typo.
    """
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); using default %d", name, value, default)
        return default
    if isinstance(value, float):
        if not value.is_integer():
            logger.warning(
                "ignoring %s=%r (fractional values truncate to a threshold of "
                "now() and flag everything); using default %d",
                name, value, default,
            )
            return default
        value = int(value)
    if isinstance(value, int) and value > 0:
        return value
    logger.warning("ignoring %s=%r (must be a positive int); using default %d", name, value, default)
    return default


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    # v4 emits "YYYY-MM-DDTHH:MM:SSZ"; fromisoformat in Python 3.11 accepts
    # "+00:00" but not bare "Z" — handle both via the standard replace trick.
    # If a future v4 response ever omits the offset entirely, treat the
    # naive result as UTC so the downstream `last_seen < threshold`
    # comparison cannot raise TypeError on a tz mismatch.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@register_cloud_rule
class ScanEngineCloudRegistrationRule:
    rule_id = "cd.scan_engine_cloud_registration"
    rule_name = "Scan Engine Cloud Registration"
    description = (
        "Cross-references the on-prem console scan engine list "
        "(/api/3/scan_engines) with the cloud-registered engines "
        "(/v4/integration/scan/engine). Engines that exist in the "
        "console but never registered with Insight Platform cannot "
        "service cloud-driven workflows (Insight Agent assessment, "
        "Cloud Risk Insights). Engines registered but with a stale "
        "last_seen indicate the cloud-platform connection is degraded. "
        "Match key is engine name; configure ignore_engines to exempt "
        "deliberately on-prem-only scanners."
    )
    default_severity = "warn"
    expensive = False
    # Tuple, not list — class-level mutable defaults are a footgun even
    # when nothing currently mutates them.
    sources: tuple[str, ...] = (
        "https://docs.rapid7.com/insightvm/working-with-scan-engines/",
    )

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_age_hours = _coerce_positive_int(
            rule_config.get("last_seen_max_age_hours", _DEFAULT_LAST_SEEN_MAX_AGE_HOURS),
            name="last_seen_max_age_hours",
            default=_DEFAULT_LAST_SEEN_MAX_AGE_HOURS,
        )
        ignore = set(rule_config.get("ignore_engines", []) or [])

        console_engines = snapshot.console_engines()
        cloud_engines = snapshot.cloud_engines()
        # Duplicate names are real-world unlikely but unguarded: pick the
        # most-recently-seen entry so a stale shadow registration doesn't
        # mask the live one. last_seen is the v4 timestamp; missing/None
        # last_seen sorts oldest so live entries win.
        cloud_by_name: dict[str, dict] = {}
        for e in cloud_engines:
            name = e.get("name")
            if not name:
                continue
            existing = cloud_by_name.get(name)
            if existing is None:
                cloud_by_name[name] = e
                continue
            # Compare last_seen — newer wins. Unparseable / None loses.
            new_seen = _parse_iso(e.get("last_seen"))
            existing_seen = _parse_iso(existing.get("last_seen"))
            if new_seen is not None and (existing_seen is None or new_seen > existing_seen):
                cloud_by_name[name] = e

        threshold = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        findings: list[Finding] = []
        missing_from_cloud = 0
        stale_in_cloud = 0

        for engine in console_engines:
            name = engine.get("name")
            if not name or name in ignore:
                continue
            cloud = cloud_by_name.get(name)
            if cloud is None:
                missing_from_cloud += 1
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Console scan engine '{name}' is not registered with "
                        f"Insight Platform. It cannot service cloud-driven "
                        f"workflows (agent assessment, Cloud Risk Insights). "
                        f"Register it via Security Console → Administration → "
                        f"Scan Engines, or add to ignore_engines if intentional."
                    ),
                    details={
                        "engine_name": name,
                        "console_engine_id": engine.get("id"),
                        "missing_from_cloud": True,
                    },
                ))
                continue

            last_seen = _parse_iso(cloud.get("last_seen"))
            if last_seen is None or last_seen < threshold:
                stale_in_cloud += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Cloud-registered engine '{name}' has stale last_seen "
                        f"({cloud.get('last_seen') or 'never'}); threshold is "
                        f"{max_age_hours}h. The Insight Platform connection is "
                        f"likely down or the engine is offline."
                    ),
                    details={
                        "engine_name": name,
                        "console_engine_id": engine.get("id"),
                        "last_seen": cloud.get("last_seen"),
                        "max_age_hours": max_age_hours,
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
                "console_engines": len(console_engines),
                "cloud_engines": len(cloud_engines),
                "missing_from_cloud": missing_from_cloud,
                "stale_in_cloud": stale_in_cloud,
                "max_age_hours": max_age_hours,
                "ignore_engines": sorted(ignore),
            },
            sources=list(self.sources),
        )
