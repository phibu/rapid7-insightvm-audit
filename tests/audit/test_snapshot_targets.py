"""Tests for EnvSnapshot.all_included_targets() — used by op.asset_coverage.agent_only_assets."""
from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from rapid7_healthcheck.audit.snapshot import EnvSnapshot


class _FakeClient:
    """Minimal fake satisfying the snapshot's client surface for sites + targets."""

    def __init__(self, sites: list[dict], targets_by_site: dict[int, list[str]]):
        self._sites = sites
        self._targets = targets_by_site
        self.calls: list[str] = []

    def paginate(self, path: str, params: dict | None = None):
        self.calls.append(f"paginate {path}")
        if path == "/api/3/sites":
            yield from self._sites
        else:
            raise AssertionError(f"unexpected paginate path: {path}")

    def get(self, path: str, params: dict | None = None) -> dict:
        self.calls.append(f"get {path}")
        if path.endswith("/included_targets"):
            site_id = int(path.split("/")[-2])
            return {"addresses": self._targets.get(site_id, [])}
        raise AssertionError(f"unexpected get path: {path}")


def _snap(sites, targets):
    return EnvSnapshot(_FakeClient(sites, targets), full_scan=True, sample_size=500)


def test_all_included_targets_empty_when_no_sites():
    snap = _snap([], {})
    targets = snap.all_included_targets()
    assert targets.networks == []
    assert targets.literals == set()


def test_all_included_targets_collects_cidrs_and_literals():
    sites = [{"id": 1}, {"id": 2}]
    targets = {1: ["10.0.0.0/24", "192.168.1.5"], 2: ["10.0.1.0/24"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    assert ip_network("10.0.0.0/24") in result.networks
    assert ip_network("10.0.1.0/24") in result.networks
    assert "192.168.1.5" in result.literals


def test_all_included_targets_handles_ip_ranges():
    """Rapid7 supports range syntax like '10.0.0.1-10.0.0.10'."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.1-10.0.0.10"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    # Range is normalized to a list of IPs in the literals set.
    assert "10.0.0.1" in result.literals
    assert "10.0.0.10" in result.literals
    assert "10.0.0.5" in result.literals


def test_all_included_targets_skips_invalid_entries():
    """Malformed targets must not crash the rule — log and skip."""
    sites = [{"id": 1}]
    targets = {1: ["not-an-ip", "10.0.0.0/24"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    assert ip_network("10.0.0.0/24") in result.networks
    assert "not-an-ip" not in result.literals


def test_all_included_targets_is_cached():
    """Second call should not re-issue HTTP."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.0/24"]}
    client = _FakeClient(sites, targets)
    snap = EnvSnapshot(client, full_scan=True, sample_size=500)
    snap.all_included_targets()
    call_count_after_first = len(client.calls)
    snap.all_included_targets()
    assert len(client.calls) == call_count_after_first


def test_all_included_targets_contains_helper():
    """The returned object provides a `contains(ip_str)` convenience."""
    sites = [{"id": 1}]
    targets = {1: ["10.0.0.0/24", "192.168.1.5"]}
    snap = _snap(sites, targets)
    t = snap.all_included_targets()
    assert t.contains("10.0.0.99") is True
    assert t.contains("192.168.1.5") is True
    assert t.contains("172.16.0.1") is False


def test_all_included_targets_oversized_range_records_endpoints_only():
    """Ranges larger than the cap (1024) record only the two endpoint IPs,
    not the full expansion — bounded-memory fallback."""
    sites = [{"id": 1}]
    # /16 has 65536 addresses; far above range_cap=1024.
    targets = {1: ["10.0.0.0-10.0.255.255"]}
    snap = _snap(sites, targets)
    result = snap.all_included_targets()
    assert "10.0.0.0" in result.literals
    assert "10.0.255.255" in result.literals
    # Interior addresses are intentionally NOT expanded.
    assert "10.0.128.0" not in result.literals
