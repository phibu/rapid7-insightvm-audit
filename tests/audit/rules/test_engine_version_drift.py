from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit.rules.engine_version_drift import EngineVersionDriftRule


def _engine(engine_id, name, *, product=None, content=None, refreshed=None):
    eng: dict = {"id": engine_id, "name": name, "address": f"{name}.example.com"}
    if product is not None:
        eng["productVersion"] = product
    if content is not None:
        eng["contentVersion"] = content
    if refreshed is not None:
        eng["lastRefreshedDate"] = refreshed
    return eng


def _now_iso(offset_days=0):
    return (datetime.now(timezone.utc) - timedelta(days=offset_days)).isoformat()


def test_pass_when_engine_matches_console(fake_snapshot):
    fake_snapshot.set_administration_properties({
        "productVersion": "6.6.300",
        "contentVersion": "1.2.3",
    })
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", product="6.6.300", content="1.2.3", refreshed=_now_iso(0)),
    ])
    r = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_warn_on_product_version_mismatch(fake_snapshot):
    fake_snapshot.set_administration_properties({"productVersion": "6.6.300"})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", product="6.6.299", refreshed=_now_iso(0)),
    ])
    r = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert "productVersion" in r.findings[0].message


def test_warn_on_content_version_mismatch(fake_snapshot):
    fake_snapshot.set_administration_properties({"contentVersion": "1.2.3"})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", content="1.2.2", refreshed=_now_iso(0)),
    ])
    r = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert "contentVersion" in r.findings[0].message


def test_warn_on_stale_lastRefreshedDate(fake_snapshot):
    fake_snapshot.set_administration_properties({})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", refreshed=_now_iso(30)),
    ])
    r = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "warn"
    assert "lastRefreshedDate" in r.findings[0].message
    assert r.findings[0].details["age_days"] >= 29


def test_pass_when_console_version_unknown(fake_snapshot):
    """If the console doesn't surface a version key we recognise, we cannot
    detect drift — be conservative and pass rather than emit a false positive.
    """
    fake_snapshot.set_administration_properties({"unrelated": "x"})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", product="6.6.300", content="1.2.3", refreshed=_now_iso(0)),
    ])
    r = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r.status == "pass"


def test_disabling_product_version_check(fake_snapshot):
    fake_snapshot.set_administration_properties({"productVersion": "6.6.300"})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", product="6.6.299", refreshed=_now_iso(0)),
    ])
    r = EngineVersionDriftRule().run(
        fake_snapshot, "warn", False, 500, {"check_product_version": False},
    )
    assert r.status == "pass"


def test_refresh_threshold_override(fake_snapshot):
    fake_snapshot.set_administration_properties({})
    fake_snapshot.set_scan_engines([
        _engine(1, "e1", refreshed=_now_iso(10)),
    ])
    r_default = EngineVersionDriftRule().run(fake_snapshot, "warn", False, 500, {})
    assert r_default.status == "warn"  # 10 > 7 default
    r_lax = EngineVersionDriftRule().run(
        fake_snapshot, "warn", False, 500, {"refresh_stale_days": 30},
    )
    assert r_lax.status == "pass"
