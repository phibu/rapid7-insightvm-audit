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
