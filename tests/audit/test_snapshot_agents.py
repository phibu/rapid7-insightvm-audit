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


def _raising_paginate(status_code: int):
    """Return a paginate side_effect that raises mid-iteration with the given
    HTTP status. Mirrors the real client behavior where pagination iterates
    page-by-page and a later page can raise 504 even though the first head
    probe succeeded."""
    def _gen(*_args, **_kwargs):
        # Yield zero items, then raise on first .__next__() -- equivalent to
        # the client retrying max_retries times on the first page and giving up.
        if False:
            yield {}
        raise Rapid7ClientError(
            f"{status_code} after 4 attempts: gateway timeout",
            status_code=status_code,
        )
    return _gen


def test_agents_swallows_504_mid_pagination_and_marks_unavailable():
    """Head probe succeeds (totalResources > 0), then pagination of the full
    fleet hits 504. The rule should see is_agents_unavailable() == True and
    self-skip rather than red-error."""
    client = MagicMock()
    client.get.return_value = {"resources": [], "page": {"totalResources": 5000}}
    client.paginate.side_effect = _raising_paginate(504)

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=100)
    sample, total = snapshot.agents()

    assert sample == []
    assert total == 0
    assert snapshot.is_agents_unavailable() is True


def test_agents_swallows_502_and_503_mid_pagination():
    for status in (502, 503):
        client = MagicMock()
        client.get.return_value = {"resources": [], "page": {"totalResources": 5000}}
        client.paginate.side_effect = _raising_paginate(status)

        snapshot = EnvSnapshot(client, full_scan=False, sample_size=100)
        sample, total = snapshot.agents()

        assert sample == [], f"status {status}: expected empty sample"
        assert total == 0, f"status {status}: expected zero total"
        assert snapshot.is_agents_unavailable() is True, f"status {status}: expected unavailable flag"


def test_agents_swallows_network_error_mid_pagination():
    """status_code=None means a pre-response failure (timeout, network).
    Same /api/3/agents-is-slow story as 504 -- treat as unavailable."""
    client = MagicMock()
    client.get.return_value = {"resources": [], "page": {"totalResources": 5000}}

    def _gen(*_args, **_kwargs):
        if False:
            yield {}
        raise Rapid7ClientError("network error after 4 attempts: ConnectionResetError")
    client.paginate.side_effect = _gen

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=100)
    sample, total = snapshot.agents()

    assert sample == []
    assert total == 0
    assert snapshot.is_agents_unavailable() is True


def test_agents_propagates_non_gateway_errors_mid_pagination():
    """A 500 mid-pagination is a real bug, not a slow-endpoint timeout.
    Must still propagate, mirroring the head-probe behavior."""
    client = MagicMock()
    client.get.return_value = {"resources": [], "page": {"totalResources": 100}}
    client.paginate.side_effect = _raising_paginate(500)

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=10)
    try:
        snapshot.agents()
    except Rapid7ClientError as e:
        assert e.status_code == 500
    else:
        raise AssertionError("expected Rapid7ClientError to propagate on 500")


def test_agents_count_cache_invalidated_after_gateway_failure():
    """After agents() swallows a gateway error mid-pagination, the count
    cache must agree: agent_count() must return 0, not the positive head
    probe value. Otherwise the invariant 'unavailable ⇒ count is 0' breaks."""
    client = MagicMock()
    client.get.return_value = {"resources": [], "page": {"totalResources": 5000}}
    client.paginate.side_effect = _raising_paginate(504)

    snapshot = EnvSnapshot(client, full_scan=False, sample_size=100)
    snapshot.agents()

    assert snapshot.agent_count() == 0
    assert snapshot.is_agents_unavailable() is True


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

        def get(self, path, params=None, **_kwargs):
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
        def get(self, path, params=None, **_kwargs):
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

        def get(self, path, params=None, **_kwargs):
            self.call_count += 1
            return {"page": {"totalResources": 7}, "resources": []}

    client = _FakeClient()
    snap = EnvSnapshot(client, full_scan=False, sample_size=100)

    assert snap.agent_count() == 7
    assert snap.agent_count() == 7
    assert client.call_count == 1


def test_two_agent_accessors_share_one_head_request():
    """agent_count() and agents() must collectively issue exactly one
    GET /api/3/agents?size=1 head request, regardless of call order.
    Locks in the head-fetch unification."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    head_calls: list[dict] = []

    class _CountingClient:
        def get(self, path, params=None, **_kwargs):
            if path == "/api/3/agents" and params == {"size": 1}:
                head_calls.append(params)
            return {"page": {"totalResources": 5}, "resources": []}

        def paginate(self, path, **kwargs):
            return iter([])

    snap = EnvSnapshot(_CountingClient(), full_scan=False, sample_size=100)

    snap.agent_count()
    snap.agents()
    snap.agent_count()  # repeated -- still cached

    assert len(head_calls) == 1, (
        f"expected exactly one /api/3/agents?size=1 head request across "
        f"both accessors, got {len(head_calls)}"
    )


def test_agents_timeout_seconds_passed_to_every_agents_call_site():
    """All /api/3/agents call sites use the configured timeout."""
    from rapid7_healthcheck.audit.snapshot import EnvSnapshot

    calls: list = []

    class _FakeClient:
        def get(self, path, params=None, *, timeout=None):
            calls.append(("get", path, timeout))
            if path == "/api/3/agents":
                return {"page": {"totalResources": 1, "totalPages": 1}, "resources": []}
            return {"page": {"totalResources": 0, "totalPages": 0}, "resources": []}

        def paginate(self, path, params=None, *, timeout=None):
            calls.append(("paginate", path, timeout))
            if path == "/api/3/agents":
                yield {"id": 1}
            return

    snap = EnvSnapshot(
        _FakeClient(),
        full_scan=False,
        sample_size=500,
        agents_timeout_seconds=222,
    )
    snap.agent_count()
    snap.agents()

    agents_calls = [c for c in calls if c[1] == "/api/3/agents"]
    assert agents_calls, "no /api/3/agents calls recorded"
    for kind, path, timeout in agents_calls:
        assert timeout == 222, f"expected timeout=222 on every /api/3/agents call, got {agents_calls}"
