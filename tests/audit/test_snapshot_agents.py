"""Tests for EnvSnapshot.agents() lazy accessor."""
from __future__ import annotations

from unittest.mock import MagicMock

from rapid7_healthcheck.audit.snapshot import EnvSnapshot
from rapid7_healthcheck.client import Rapid7ClientError


def _build_paginated_response(total: int):
    """Yield fake agent dicts up to `total` count."""
    return [{"id": i, "agentId": f"agent-{i}"} for i in range(total)]


def test_agents_returns_full_list_and_total_when_full_scan():
    client = MagicMock()
    fleet = _build_paginated_response(15)
    client.get.return_value = {"resources": fleet[:1], "page": {"totalResources": 15}}
    client.paginate.return_value = iter(fleet)

    snapshot = EnvSnapshot(client, full_scan=True, sample_size=10)
    sample, total = snapshot.agents()

    assert total == 15
    assert len(sample) == 15
    assert sample[0]["agentId"] == "agent-0"


def test_agents_caps_at_sample_size_when_not_full_scan():
    client = MagicMock()
    fleet = _build_paginated_response(50)
    client.get.return_value = {"resources": fleet[:1], "page": {"totalResources": 50}}
    client.paginate.return_value = iter(fleet)

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    sample, total = snapshot.agents()

    assert total == 50
    assert len(sample) == 10


def test_agents_caches_first_call():
    client = MagicMock()
    fleet = _build_paginated_response(3)
    client.get.return_value = {"resources": fleet[:1], "page": {"totalResources": 3}}
    client.paginate.return_value = iter(fleet)

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    snapshot.agents()
    snapshot.agents()  # second call

    assert client.get.call_count == 1
    assert client.paginate.call_count == 1


def test_agents_returns_empty_and_marks_unavailable_on_404():
    client = MagicMock()
    client.get.side_effect = Rapid7ClientError(
        "404 at /api/3/agents: Not Found", status_code=404
    )

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    sample, total = snapshot.agents()

    assert sample == []
    assert total == 0
    assert snapshot.is_agents_unavailable() is True


def test_agents_propagates_non_404_errors():
    client = MagicMock()
    client.get.side_effect = Rapid7ClientError(
        "500 at /api/3/agents: Server Error", status_code=500
    )

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    try:
        snapshot.agents()
    except Rapid7ClientError as e:
        assert e.status_code == 500
    else:
        raise AssertionError("expected Rapid7ClientError to propagate on 500")


def test_is_agents_unavailable_false_before_first_call():
    client = MagicMock()
    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    assert snapshot.is_agents_unavailable() is False


def test_agents_zero_total_skips_pagination():
    """If totalResources is 0, the accessor should not bother paginating."""
    client = MagicMock()
    client.get.return_value = {"resources": [], "page": {"totalResources": 0}}

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    sample, total = snapshot.agents()

    assert sample == []
    assert total == 0
    # No pagination call when there's nothing to fetch.
    assert client.paginate.call_count == 0


def test_agent_count_returns_total_from_head_request():
    """agent_count() reads page.totalResources from /api/3/agents head."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    class _FakeClient:
        def __init__(self):
            self.calls: list[tuple[str, dict]] = []

        def get(self, path, params=None):
            self.calls.append((path, params or {}))
            return {"page": {"totalResources": 12345}, "resources": []}

    client = _FakeClient()
    snap = EnvSnapshot(client, full_scan=False, sample_size=100)

    assert snap.agent_count() == 12345
    head_calls = [(p, q) for p, q in client.calls if p == "/api/3/agents"]
    assert len(head_calls) == 1
    assert head_calls[0][1] == {"size": 1}


def test_agent_count_returns_zero_and_sets_unavailable_on_404():
    """agent_count() handles the 404 path and primes is_agents_unavailable()."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot
    from rapid7_healthcheck.client import Rapid7ClientError

    class _FailingClient:
        def get(self, path, params=None):
            raise Rapid7ClientError(f"404 from {path}", status_code=404)

    snap = EnvSnapshot(_FailingClient(), full_scan=False, sample_size=100)

    assert snap.agent_count() == 0
    assert snap.is_agents_unavailable() is True


def test_agent_count_is_cached():
    """Two calls to agent_count() produce one HTTP request."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    class _FakeClient:
        def __init__(self):
            self.call_count = 0

        def get(self, path, params=None):
            self.call_count += 1
            return {"page": {"totalResources": 7}, "resources": []}

    client = _FakeClient()
    snap = EnvSnapshot(client, full_scan=False, sample_size=100)

    assert snap.agent_count() == 7
    assert snap.agent_count() == 7
    assert client.call_count == 1
