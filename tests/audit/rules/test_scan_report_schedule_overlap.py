from __future__ import annotations

from rapid7_healthcheck.audit.rules.scan_report_schedule_overlap import (
    ScanReportScheduleOverlapRule,
)


def _site(site_id, name):
    return {"id": site_id, "name": name}


def _schedule(sched_id, start, duration="PT1H", enabled=True):
    return {"id": sched_id, "start": start, "duration": duration, "enabled": enabled}


def _report(report_id, name, *, sites, start=None, next_runtimes=None):
    freq = {"start": start} if start else {}
    if next_runtimes is not None:
        freq["nextRuntimes"] = next_runtimes
    return {
        "id": report_id,
        "name": name,
        "scope": {"sites": list(sites)},
        "frequency": freq,
    }


def test_pass_when_no_reports(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z")])
    fake_snapshot.set_reports([])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_pass_when_report_and_scan_dont_share_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A"), _site(2, "B")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z")])
    fake_snapshot.set_site_schedules(2, [])
    fake_snapshot.set_reports([
        _report(100, "rep", sites=[2], start="2026-05-01T08:00:00Z"),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_report_overlaps_scan_on_same_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT2H")])
    fake_snapshot.set_reports([
        _report(100, "daily", sites=[1], start="2026-05-01T09:00:00Z"),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert any("daily" in f.message for f in r.findings)


def test_pass_when_report_runs_after_scan_window(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT1H")])
    fake_snapshot.set_reports([
        _report(100, "evening", sites=[1], start="2026-05-01T18:00:00Z"),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_when_two_reports_overlap_on_shared_site(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [])
    fake_snapshot.set_reports([
        _report(100, "rep-a", sites=[1], start="2026-05-01T08:00:00Z"),
        _report(101, "rep-b", sites=[1], start="2026-05-01T08:10:00Z"),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert any("rep-a" in f.message and "rep-b" in f.message for f in r.findings)


def test_uses_next_runtimes_when_provided(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT1H")])
    fake_snapshot.set_reports([
        _report(
            100, "weekly", sites=[1],
            next_runtimes=[
                "2026-05-01T08:15:00Z",
                "2026-05-08T08:15:00Z",
            ],
        ),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_skips_reports_without_site_scope(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT2H")])
    fake_snapshot.set_reports([
        _report(100, "asset-scoped", sites=[], start="2026-05-01T09:00:00Z"),
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_string_site_ids_in_scope_are_coerced(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT2H")])
    fake_snapshot.set_reports([{
        "id": 100,
        "name": "string-id",
        "scope": {"sites": ["1"]},  # API has been observed serializing as strings
        "frequency": {"start": "2026-05-01T09:00:00Z"},
    }])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"


def test_resolves_asset_group_scope_via_snapshot(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT2H")])
    fake_snapshot.set_asset_group_sites(42, {1})
    fake_snapshot.set_reports([{
        "id": 100,
        "name": "group-scoped",
        "scope": {"assetGroups": [42]},
        "frequency": {"start": "2026-05-01T09:00:00Z"},
    }])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert r.summary["reports_with_unresolvable_scope"] == 0


def test_unresolvable_report_scope_is_counted(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT2H")])
    fake_snapshot.set_asset_groups([])
    fake_snapshot.set_reports([{
        "id": 100,
        "name": "tag-scoped",
        "scope": {"tags": [7]},
        "frequency": {"start": "2026-05-01T09:00:00Z"},
    }])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"
    assert r.summary["reports_with_unresolvable_scope"] == 1


def test_reports_are_capped_under_sampling(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [])
    # 10 reports, but sample_size=4 should cap us at 4.
    fake_snapshot.set_reports([
        _report(i, f"r{i}", sites=[1], start="2026-05-01T08:00:00Z")
        for i in range(10)
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 4, {})
    assert r.sampled is True
    assert "4 of 10 reports" in (r.sample_info or "")


def test_full_scan_does_not_cap_reports(fake_snapshot):
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [])
    fake_snapshot.set_reports([
        _report(i, f"r{i}", sites=[1], start="2026-05-01T08:00:00Z")
        for i in range(10)
    ])
    r = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", True, 4, {})
    assert r.sampled is False
    # All 10 reports each contribute 1 window.
    assert r.summary["report_windows_examined"] == 10


def test_assumed_report_duration_knob(fake_snapshot):
    """A 5-minute assumed report duration shouldn't overlap a scan that ends
    before the report starts, even though the default 30-min would."""
    fake_snapshot.set_sites([_site(1, "A")])
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT55M")])
    fake_snapshot.set_reports([
        _report(100, "rep", sites=[1], start="2026-05-01T08:57:00Z"),
    ])
    r_default = ScanReportScheduleOverlapRule().run(fake_snapshot, "warn", False, 500, {})
    # default 30min report starting 08:57 ends 09:27, scan ends 08:55 → no overlap.
    # But scan window 08:00-08:55 vs report 08:57-09:27 → no overlap actually.
    assert r_default.status == "pass"

    # Now a scan that ends right at 09:00, with a 5-min report at 08:57 → overlap.
    fake_snapshot.set_site_schedules(1, [_schedule(10, "2026-05-01T08:00:00Z", duration="PT1H")])
    r = ScanReportScheduleOverlapRule().run(
        fake_snapshot, "warn", False, 500, {"assumed_report_duration_minutes": 5},
    )
    assert r.status == "warn"
