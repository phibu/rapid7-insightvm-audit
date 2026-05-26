from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.audit.cloud_drift._utils import _coerce_positive_int
from rapid7_healthcheck.checks import Finding

logger = logging.getLogger(__name__)


_DEFAULT_LAST_SEEN_MAX_AGE_HOURS = 24


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


def _normalize_host_key(value) -> str | None:
    """Normalize an address / host_name for cross-key fallback matching.

    Lower-cases, strips surrounding whitespace, and strips trailing
    dot(s) (FQDNs may carry a root-zone dot on one side only).
    Returns ``None`` for empty / non-string input so callers can skip it.
    """
    if not isinstance(value, str):
        return None
    normalized = value.strip().rstrip(".").lower()
    return normalized or None


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
        "Primary match key is engine name (console.name == cloud.name); "
        "when name matching misses, falls back to "
        "console.address == cloud.host_name so an engine renamed on one "
        "side still matches. Name match always wins when both would "
        "succeed. Configure ignore_engines (name-based) to exempt "
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

        # Fallback index: console.address ↔ cloud.host_name. Used when
        # name-based match misses (engine renamed on one side, or names
        # diverge between v3 and v4 inventory). Duplicate host_names use
        # the same most-recently-seen-wins disambiguation as the name index.
        cloud_by_host_name: dict[str, dict] = {}
        for e in cloud_engines:
            host_name = _normalize_host_key(e.get("host_name"))
            if not host_name:
                continue
            existing = cloud_by_host_name.get(host_name)
            if existing is None:
                cloud_by_host_name[host_name] = e
                continue
            new_seen = _parse_iso(e.get("last_seen"))
            existing_seen = _parse_iso(existing.get("last_seen"))
            if new_seen is not None and (existing_seen is None or new_seen > existing_seen):
                cloud_by_host_name[host_name] = e

        threshold = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        findings: list[Finding] = []
        missing_from_cloud = 0
        stale_in_cloud = 0

        for engine in console_engines:
            name = engine.get("name")
            address = engine.get("address")
            # The `ignore_engines` list is name-based; null-named engines
            # are filtered here (legacy behavior — engines without a name
            # can't be referenced in config).
            if name and name in ignore:
                continue
            if not name and not address:
                # Engine record has no key at all — can't match either way.
                continue

            cloud = cloud_by_name.get(name) if name else None
            matched_via = "name" if cloud is not None else None
            if cloud is None and address:
                cloud = cloud_by_host_name.get(_normalize_host_key(address))
                if cloud is not None:
                    matched_via = "host_name_fallback"
                    logger.info(
                        "scan_engine_cloud_registration: matched console "
                        "engine name=%r address=%r to cloud engine "
                        "name=%r via host_name fallback (primary name "
                        "match failed)",
                        name, address, cloud.get("name"),
                    )

            if cloud is None:
                missing_from_cloud += 1
                # Use the available identifier in the message (name preferred,
                # then address, then a generic placeholder).
                identifier = name or address or f"id={engine.get('id')}"
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Console scan engine '{identifier}' is not registered with "
                        f"Insight Platform. It cannot service cloud-driven "
                        f"workflows (agent assessment, Cloud Risk Insights). "
                        f"Register it via Security Console → Administration → "
                        f"Scan Engines, or add to ignore_engines if intentional."
                    ),
                    details={
                        "engine_name": name,
                        "console_engine_id": engine.get("id"),
                        "console_address": address,
                        "missing_from_cloud": True,
                        "matched_via": matched_via,  # always None here; key present for schema uniformity with the stale finding
                    },
                ))
                continue

            last_seen = _parse_iso(cloud.get("last_seen"))
            if last_seen is None or last_seen < threshold:
                stale_in_cloud += 1
                # Use console name in the message when available; cloud name
                # when not (fallback match path).
                display_name = name or cloud.get("name") or "<unnamed>"
                # A missing/unparseable last_seen means the engine has NEVER
                # contacted the Insight Platform — a hard failure, distinct
                # from a merely stale connection. Hard-code "fail" for it
                # (mirrors the broken-sync hard-fail in
                # console_asset_count_drift); a previously-seen but stale
                # engine inherits the configured severity.
                never_seen = last_seen is None
                if never_seen:
                    finding_severity = "fail"
                    message = (
                        f"Cloud-registered engine '{display_name}' has never "
                        f"contacted the Insight Platform (no last_seen "
                        f"timestamp). The cloud connection has never been "
                        f"established or the engine has not yet come online."
                    )
                else:
                    finding_severity = severity
                    message = (
                        f"Cloud-registered engine '{display_name}' has stale "
                        f"last_seen ({cloud.get('last_seen')}); threshold is "
                        f"{max_age_hours}h. The Insight Platform connection is "
                        f"likely down or the engine is offline."
                    )
                findings.append(Finding(
                    severity=finding_severity,
                    message=message,
                    details={
                        "engine_name": name,
                        "cloud_engine_name": cloud.get("name"),
                        "console_engine_id": engine.get("id"),
                        "last_seen": cloud.get("last_seen"),
                        "max_age_hours": max_age_hours,
                        "matched_via": matched_via,
                        "never_seen": never_seen,
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
