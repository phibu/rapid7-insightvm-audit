from __future__ import annotations

from unittest.mock import MagicMock

from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot


def _v3_first_page(total: int) -> dict:
    return {
        "resources": [],
        "page": {"number": 0, "size": 1, "totalPages": 1 if total else 0, "totalResources": total},
    }


def _v4_assets_response(total: int) -> dict:
    return {
        "data": [],
        "metadata": {"number": 0, "size": 1, "totalPages": 1 if total else 0, "totalResources": total},
        "links": [],
    }


def test_cloud_assets_total_reads_metadata_total_resources():
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(42)
    v3 = MagicMock()
    snap = CloudSnapshot(v3_client=v3, cloud_client=v4)
    assert snap.cloud_assets_total() == 42
    v4.post_one.assert_called_once_with(
        "/v4/integration/assets",
        json_body={},
        params={"page": 0, "size": 1},
    )


def test_cloud_assets_total_is_cached():
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(7)
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)
    snap.cloud_assets_total()
    snap.cloud_assets_total()
    assert v4.post_one.call_count == 1


def test_console_assets_total_reads_v3_page_total_resources():
    v3 = MagicMock()
    v3.get.return_value = _v3_first_page(99)
    snap = CloudSnapshot(v3_client=v3, cloud_client=MagicMock())
    assert snap.console_assets_total() == 99
    v3.get.assert_called_once_with("/api/3/assets", params={"page": 0, "size": 1})


def test_cloud_assets_stale_uses_filter_dsl_with_iso_threshold():
    from datetime import datetime, timezone
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(11)
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)

    threshold = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert snap.cloud_assets_stale(threshold) == 11
    body = v4.post_one.call_args.kwargs["json_body"]
    assert body == {
        "asset": "last_assessed_for_vulnerabilities < '2026-01-01T00:00:00Z'",
    }


def test_cloud_engines_paginates_get():
    v4 = MagicMock()
    v4.paginate.return_value = iter([
        {"id": "a", "name": "engine-a", "last_seen": "2026-05-07T00:00:00Z"},
        {"id": "b", "name": "engine-b", "last_seen": None},
    ])
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)
    engines = snap.cloud_engines()
    assert len(engines) == 2
    assert engines[0]["name"] == "engine-a"
    v4.paginate.assert_called_once_with("/v4/integration/scan/engine")


def test_console_engines_paginates_v3():
    v3 = MagicMock()
    v3.paginate.return_value = iter([{"id": 1, "name": "console-a"}])
    snap = CloudSnapshot(v3_client=v3, cloud_client=MagicMock())
    engines = snap.console_engines()
    assert engines == [{"id": 1, "name": "console-a"}]
    v3.paginate.assert_called_once_with("/api/3/scan_engines")


def test_console_engines_handles_multi_page_response():
    # Regression: rules cross-reference console_engines() with the v4
    # cloud_engines() list. If the v3 side silently truncated to one
    # page, every engine past page 1 would appear "missing from cloud" —
    # false positives that scale with deployment size.
    v3 = MagicMock()
    v3.paginate.return_value = iter([
        {"id": i, "name": f"engine-{i}"} for i in range(300)
    ])
    snap = CloudSnapshot(v3_client=v3, cloud_client=MagicMock())
    engines = snap.console_engines()
    assert len(engines) == 300
