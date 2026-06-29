from __future__ import annotations

from rapid7_healthcheck.report import InventoryTotals, build_inventory_totals


class _FakeSnapshot:
    """Minimal fake snapshot for build_inventory_totals tests.

    Each accessor returns a registered value or raises a registered exception.
    """

    def __init__(
        self,
        *,
        total_assets: int = 0,
        sites: list[dict] | None = None,
        scan_engines: list[dict] | None = None,
        asset_groups: list[dict] | None = None,
        scans_total: int = 0,
        raise_on: str | None = None,
    ) -> None:
        self._total_assets = total_assets
        self._sites = sites or []
        self._scan_engines = scan_engines or []
        self._asset_groups = asset_groups or []
        self._scans_total = scans_total
        self._raise_on = raise_on

    def _maybe_raise(self, name: str) -> None:
        if self._raise_on == name:
            raise RuntimeError(f"boom on {name}")

    def total_asset_count(self) -> int:
        self._maybe_raise("total_asset_count")
        return self._total_assets

    def sites(self) -> list[dict]:
        self._maybe_raise("sites")
        return self._sites

    def scan_engines(self) -> list[dict]:
        self._maybe_raise("scan_engines")
        return self._scan_engines

    def asset_groups(self) -> list[dict]:
        self._maybe_raise("asset_groups")
        return self._asset_groups

    def scans_total(self) -> int:
        self._maybe_raise("scans_total")
        return self._scans_total


def test_build_inventory_totals_happy_path():
    snap = _FakeSnapshot(
        total_assets=4200,
        sites=[{"id": 1}, {"id": 2}, {"id": 3}],
        scan_engines=[{"id": 11}, {"id": 12}],
        asset_groups=[
            {"id": 1, "type": "static"},
            {"id": 2, "type": "dynamic"},
        ],
        scans_total=515,
    )
    result = build_inventory_totals(snap)
    assert isinstance(result, InventoryTotals)
    assert result.total_assets == 4200
    assert result.total_sites == 3
    assert result.total_scan_engines == 2
    assert result.total_asset_groups_static == 1
    assert result.total_asset_groups_dynamic == 1
    assert result.total_scans == 515


def test_build_inventory_totals_returns_none_on_accessor_failure(caplog):
    snap = _FakeSnapshot(raise_on="scans_total")
    with caplog.at_level("ERROR"):
        result = build_inventory_totals(snap)
    assert result is None
    # The exception was logged via logger.exception (ERROR level).
    assert any("inventory totals" in rec.message.lower() for rec in caplog.records)


def test_build_inventory_totals_splits_groups_by_type():
    snap = _FakeSnapshot(
        asset_groups=[
            {"type": "static"},
            {"type": "static"},
            {"type": "dynamic"},
            {"type": "static"},
        ],
    )
    result = build_inventory_totals(snap)
    assert result is not None
    assert result.total_asset_groups_static == 3
    assert result.total_asset_groups_dynamic == 1


def test_build_inventory_totals_returns_none_on_sites_failure():
    """Any single accessor failure (not just scans_total) returns None."""
    snap = _FakeSnapshot(raise_on="sites")
    assert build_inventory_totals(snap) is None
