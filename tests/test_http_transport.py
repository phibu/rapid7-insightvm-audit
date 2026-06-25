"""Interface tests for the deep HttpTransport module.

HttpTransport owns everything identical across the v3 Console API and the
v4 Cloud Integrations API -- the retry loop, backoff, read-only allowlist
*enforcement*, JSON parsing, and pagination. The per-API differences are
injected as an ApiDialect (the adapter at the seam).

These tests drive the transport with a *fake* dialect carrying
distinctive values (envelope key ``widgets``/``meta``, its own allowlist
and error class). If the transport hardcoded ``resources``/``data`` or a
fixed allowlist, these tests would fail -- proving the variation genuinely
crosses the seam.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from rapid7_healthcheck.client import (
    ApiDialect,
    HttpTransport,
    Rapid7AuthError,
    Rapid7ClientError,
    ReadOnlyViolationError,
)


class FakeTransportError(Rapid7ClientError):
    """Distinctive failure type so tests prove dialect.error_cls is used."""


FAKE_DIALECT = ApiDialect(
    resource_key="widgets",
    page_meta_key="meta",
    allowed_post_paths=frozenset({"/x/search"}),
    error_cls=FakeTransportError,
    auth_hint="FAKE_KEY and base_url",
)


def _resp(status: int, body: dict | None = None, headers: dict | None = None):
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.headers = headers or {}
    r.text = json.dumps(body) if body is not None else ""
    r.json.return_value = body or {}
    return r


@pytest.fixture
def session():
    s = MagicMock(spec=requests.Session)
    s.headers = {}
    return s


def make_transport(session, dialect=FAKE_DIALECT, **overrides):
    kwargs = dict(
        base_url="https://transport.test",
        headers={"X-Api-Key": "k", "Accept": "application/json"},
        auth=None,
        dialect=dialect,
        verify_tls=True,
        timeout_seconds=5,
        max_retries=2,
        session=session,
    )
    kwargs.update(overrides)
    return HttpTransport(**kwargs)


def test_paginate_reads_envelope_keys_from_dialect(session):
    """resource_key and page_meta_key come from the dialect, not hardcoded."""
    page0 = {"widgets": [{"id": 1}, {"id": 2}], "meta": {"totalPages": 2}}
    page1 = {"widgets": [{"id": 3}], "meta": {"totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    t = make_transport(session)
    items = list(t.paginate("/x/things", page_size=250))
    assert [i["id"] for i in items] == [1, 2, 3]


def test_post_allowlist_uses_dialect_paths(session):
    """A POST to the dialect's allowlisted path is permitted."""
    session.request.return_value = _resp(200, {"widgets": [], "meta": {"totalPages": 1}})
    t = make_transport(session)
    t.post("/x/search", json_body={"q": 1})
    assert session.request.call_args.kwargs["method"] == "POST"


def test_post_outside_dialect_allowlist_raises_before_network(session):
    t = make_transport(session)
    with pytest.raises(ReadOnlyViolationError) as exc:
        t.post("/x/other", json_body={})
    assert "/x/other" in str(exc.value)
    session.request.assert_not_called()


def test_non_auth_failure_raises_dialect_error_cls(session):
    """A 4xx (non-auth) surfaces as the dialect's error class."""
    session.request.return_value = _resp(404, {"message": "nope"})
    t = make_transport(session)
    with pytest.raises(FakeTransportError) as exc:
        t.get("/x/missing")
    assert exc.value.status_code == 404


def test_auth_error_message_uses_dialect_hint(session):
    session.request.return_value = _resp(401, {"message": "bad"})
    t = make_transport(session)
    with pytest.raises(Rapid7AuthError) as exc:
        t.get("/x/things")
    assert "FAKE_KEY" in str(exc.value)


def test_verb_guard_rejects_put_before_network(session):
    t = make_transport(session)
    with pytest.raises(ReadOnlyViolationError):
        t._request("PUT", "/x/things")
    session.request.assert_not_called()


def test_retry_then_success_honors_retry_after(session, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: sleeps.append(s))
    session.request.side_effect = [
        _resp(429, headers={"Retry-After": "2"}),
        _resp(200, {"widgets": [], "meta": {"totalPages": 1}}),
    ]
    t = make_transport(session, max_retries=2)
    t.get("/x/things")
    assert sleeps == [2.0]


def test_negative_max_retries_rejected(session):
    """Shared guard: the v3 client historically lacked this; the transport
    enforces it for both adapters."""
    with pytest.raises(ValueError, match="max_retries"):
        make_transport(session, max_retries=-1)
