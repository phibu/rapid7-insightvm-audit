from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from rapid7_healthcheck.audit.cloud_drift.rules.scan_engine_cloud_registration import (
    ScanEngineCloudRegistrationRule,
)


def _now_iso(offset_hours: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=offset_hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _snapshot(console_engines: list[dict], cloud_engines: list[dict]) -> MagicMock:
    s = MagicMock()
    s.console_engines.return_value = console_engines
    s.cloud_engines.return_value = cloud_engines
    return s


def test_all_engines_present_and_recent_passes():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(1)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "pass"


def test_engine_missing_from_cloud_fails():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "fail"
    fail = [f for f in result.findings if f.severity == "fail"]
    assert len(fail) == 1
    assert "engine-b" in fail[0].message
    # Schema uniformity: matched_via is present (always None on missing path)
    # so downstream consumers see the same details keys as the stale finding.
    assert "matched_via" in fail[0].details
    assert fail[0].details["matched_via"] is None


def test_engine_present_but_stale_warns():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(48)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "stale" in result.findings[0].message.lower() or "last_seen" in result.findings[0].message


def test_ignored_engine_skipped():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "lab-only"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"ignore_engines": ["lab-only"]})
    assert result.status == "pass"


def test_cloud_engine_without_last_seen_fails_unconditionally():
    """A cloud engine record with no last_seen has never contacted the
    Insight Platform -- that is a hard failure, distinct from a merely
    stale connection. It must be reported at "fail" severity regardless
    of the configured severity (mirrors the broken-sync hard-fail in
    console_asset_count_drift)."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": None}],
    )
    # Configured severity is "info" -- never-seen must still escalate to fail.
    result = rule.run(snap, "info", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "fail"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "fail"
    assert "never" in result.findings[0].message.lower()


def test_stale_engine_respects_configured_severity():
    """A merely-stale (but previously-seen) engine inherits the configured
    severity -- unlike the never-seen case it is not hard-coded to fail."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(48)}],
    )
    result = rule.run(snap, "info", False, 500, {"last_seen_max_age_hours": 24})
    # info severity → finding present but status stays pass.
    assert result.status == "pass"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"


def test_summary_counts():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[
            {"id": 1, "name": "engine-a"},
            {"id": 2, "name": "engine-b"},
            {"id": 3, "name": "engine-c"},
        ],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(48)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.summary["console_engines"] == 3
    assert result.summary["cloud_engines"] == 2
    assert result.summary["missing_from_cloud"] == 1
    assert result.summary["stale_in_cloud"] == 1
    assert result.card_summary == {"examined": 3, "passed": 1, "failed": 2}


def test_rule_is_registered():
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    assert "cd.scan_engine_cloud_registration" in _CLOUD_RULE_REGISTRY


def test_fractional_max_age_falls_back_to_default():
    """A user setting last_seen_max_age_hours=0.5 must not silently truncate
    to 0 (which would make the threshold == now() and flag every engine as
    stale). The coercion helper falls back to the default with a warning."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        # 1h ago: stale under 0.5h (if truncation bug present), fresh under default 24h.
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(1)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 0.5})
    # Default 24h kicks in -> 1h-old engine is fresh -> pass.
    assert result.status == "pass"
    assert result.summary["max_age_hours"] == 24


def test_zero_or_negative_max_age_falls_back_to_default():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(1)}],
    )
    for bad in (0, -5, "abc", None, True):
        result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": bad})
        assert result.summary["max_age_hours"] == 24, f"bad input {bad!r} should fall back"


def test_duplicate_engine_names_pick_most_recent_last_seen():
    """A duplicate engine name in the cloud list should not silently let the
    older shadow registration mask the live one (last-write-wins in the
    naive dict comprehension would let response order decide). The newer
    last_seen wins."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[
            # Stale shadow first; live entry second. last_seen newer on the live entry.
            {"name": "engine-a", "last_seen": _now_iso(72)},
            {"name": "engine-a", "last_seen": _now_iso(1)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    # Newer entry (1h ago) wins -> rule should not flag stale.
    assert result.status == "pass"


def test_duplicate_engine_names_live_first_then_stale_still_picks_live():
    """Order-independent: live entry first, stale shadow second. The live
    one (newer last_seen) must still win."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(1)},
            {"name": "engine-a", "last_seen": _now_iso(72)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "pass"


def test_naive_last_seen_does_not_raise_type_error():
    # Defense in depth: if a future v4 response ever omits the timezone
    # offset, the naive datetime would otherwise raise TypeError when
    # compared to the aware threshold. _parse_iso treats naive as UTC.
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": "2026-05-07T00:00:00"}],
    )
    # Should not raise; should classify as either fresh or stale based on
    # the threshold, not crash.
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status in ("pass", "warn")


def test_fallback_matches_when_name_differs_but_address_matches_host_name():
    """If console.name != cloud.name but console.address == cloud.host_name,
    treat as matched. Common scenario: engine renamed on one side."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{
            "id": 1, "name": "console-engine-a", "address": "10.0.0.5",
        }],
        cloud_engines=[{
            "name": "cloud-engine-a", "host_name": "10.0.0.5",
            "last_seen": _now_iso(0),
        }],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    # Matched via fallback => no "missing from cloud" finding.
    assert result.status == "pass"
    missing = [f for f in result.findings if f.severity == "fail"]
    assert missing == [], f"expected no missing-from-cloud finding, got {missing}"


def test_name_match_wins_when_both_would_match_different_cloud_entries():
    """If two cloud entries exist -- one matches by name, a different one
    by address/host_name -- the name match wins (it's the primary key)."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{
            "id": 1, "name": "engine-a", "address": "10.0.0.5",
        }],
        cloud_engines=[
            # Name match (this should win):
            {"name": "engine-a", "host_name": "different-host",
             "last_seen": _now_iso(0)},
            # Fallback match (loses):
            {"name": "engine-b", "host_name": "10.0.0.5",
             "last_seen": _now_iso(72)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    # Name match was fresh (0h ago) -- should pass, not be flagged stale.
    assert result.status == "pass"


def test_console_engine_with_no_name_falls_through_to_fallback():
    """console.name=null but valid address → fallback can still match."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": None, "address": "10.0.0.5"}],
        cloud_engines=[
            {"name": "cloud-engine", "host_name": "10.0.0.5",
             "last_seen": _now_iso(0)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "pass"


def test_neither_name_nor_address_matches_still_flags_missing():
    """When neither primary nor fallback matches, the engine stays flagged
    as 'missing from cloud' -- fallback is additive, never silently masks."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a", "address": "10.0.0.5"}],
        cloud_engines=[
            {"name": "engine-b", "host_name": "10.0.0.99",
             "last_seen": _now_iso(0)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "fail"
    missing = [f for f in result.findings if f.severity == "fail"]
    assert len(missing) == 1
    assert "engine-a" in missing[0].message


def test_cloud_entry_without_host_name_does_not_match_fallback():
    """Cloud entry with host_name=null cannot be matched via fallback."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a", "address": "10.0.0.5"}],
        cloud_engines=[
            {"name": "engine-b", "host_name": None,
             "last_seen": _now_iso(0)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "fail"


def test_fallback_match_logs_info(caplog):
    """When the fallback matches, emit an INFO log so operators can audit."""
    import logging
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{
            "id": 1, "name": "console-engine-a", "address": "10.0.0.5",
        }],
        cloud_engines=[{
            "name": "cloud-engine-a", "host_name": "10.0.0.5",
            "last_seen": _now_iso(0),
        }],
    )
    with caplog.at_level(
        logging.INFO,
        logger="rapid7_healthcheck.audit.cloud_drift.rules.scan_engine_cloud_registration",
    ):
        rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})

    info_records = [r for r in caplog.records if r.levelno == logging.INFO and "fallback" in r.getMessage()]
    assert len(info_records) == 1, (
        f"expected exactly 1 INFO log about fallback match, got "
        f"{len(info_records)}: {[r.getMessage() for r in info_records]}"
    )


def test_fallback_matches_when_host_name_has_trailing_dot():
    """A console engine whose address is an FQDN and a cloud engine whose
    host_name is the same FQDN with a trailing dot must still match via
    the host_name fallback -- not be reported as missing from cloud."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "renamed-on-console",
                          "address": "engine.corp.example.com"}],
        cloud_engines=[{"name": "old-cloud-name",
                        "host_name": "engine.corp.example.com.",  # trailing dot
                        "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "pass"
    assert result.summary["missing_from_cloud"] == 0


def test_fallback_matches_when_address_has_surrounding_whitespace():
    """Surrounding whitespace on the console address must not break the
    host_name fallback match."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "renamed",
                          "address": "  engine.corp.example.com  "}],
        cloud_engines=[{"name": "cloud-name",
                        "host_name": "engine.corp.example.com",
                        "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "pass"
    assert result.summary["missing_from_cloud"] == 0


def test_null_named_engine_missing_from_cloud_fails_with_address_identifier():
    """A console engine with name=None and an address set, when no cloud
    engine matches by host_name, is reported missing-from-cloud -- and the
    finding's identifier falls back to the address."""
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 7, "name": None, "address": "10.20.30.40"}],
        cloud_engines=[{"name": "some-other-engine",
                        "host_name": "10.99.99.99",
                        "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "fail"
    assert result.summary["missing_from_cloud"] == 1
    fail = [f for f in result.findings if f.severity == "fail"]
    assert len(fail) == 1
    assert "10.20.30.40" in fail[0].message
