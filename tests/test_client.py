from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from rapid7_healthcheck.client import (
    Rapid7AuthError,
    Rapid7Client,
    Rapid7ClientError,
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


def make_client(session, **overrides):
    kwargs = dict(
        base_url="https://us.api.insight.rapid7.com",
        api_key="key",
        verify_tls=True,
        timeout_seconds=5,
        max_retries=2,
        session=session,
    )
    kwargs.update(overrides)
    return Rapid7Client(**kwargs)


def test_get_sends_x_api_key_header(session):
    session.request.return_value = _resp(200, {"ok": True})
    c = make_client(session)
    c.get("/api/3/sites")
    args, kwargs = session.request.call_args
    assert kwargs["headers"]["X-Api-Key"] == "key"
    assert kwargs["headers"]["Accept"] == "application/json"
    assert kwargs["url"] == "https://us.api.insight.rapid7.com/api/3/sites"
    assert kwargs["timeout"] == 5
    assert kwargs["verify"] is True


def test_paginate_yields_resources_across_pages(session):
    page0 = {"resources": [{"id": 1}, {"id": 2}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 3}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session)
    items = list(c.paginate("/api/3/sites", page_size=500))
    assert [i["id"] for i in items] == [1, 2, 3]
    # Verify pagination params
    first_call = session.request.call_args_list[0]
    assert first_call.kwargs["params"]["page"] == 0
    assert first_call.kwargs["params"]["size"] == 500


def test_401_raises_auth_error_no_retry(session):
    session.request.return_value = _resp(401, {"message": "bad key"})
    c = make_client(session)
    with pytest.raises(Rapid7AuthError):
        c.get("/api/3/sites")
    assert session.request.call_count == 1


def test_429_retries_with_retry_after(session, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: sleeps.append(s))
    session.request.side_effect = [
        _resp(429, headers={"Retry-After": "2"}),
        _resp(200, {"ok": True}),
    ]
    c = make_client(session, max_retries=2)
    c.get("/api/3/sites")
    assert sleeps == [2.0]


def test_503_retries_with_exponential_backoff(session, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: sleeps.append(s))
    session.request.side_effect = [
        _resp(503),
        _resp(503),
        _resp(200, {"ok": True}),
    ]
    c = make_client(session, max_retries=3)
    c.get("/api/3/sites")
    assert sleeps == [1.0, 2.0]


def test_max_retries_exhausted_raises(session, monkeypatch):
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: None)
    session.request.return_value = _resp(503)
    c = make_client(session, max_retries=2)
    with pytest.raises(Rapid7ClientError):
        c.get("/api/3/sites")


def test_4xx_other_than_auth_raises(session):
    session.request.return_value = _resp(400, {"message": "bad"})
    c = make_client(session)
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/sites")
    assert "400" in str(exc.value)


def test_connect_does_metadata_get(session):
    session.request.return_value = _resp(200, {"version": "3"})
    c = make_client(session)
    c.connect()
    args, kwargs = session.request.call_args
    assert kwargs["url"].endswith("/api/3")


def test_connect_auth_failure_raises_auth_error(session):
    session.request.return_value = _resp(401)
    c = make_client(session)
    with pytest.raises(Rapid7AuthError):
        c.connect()


def test_post_sends_json_body(session):
    session.request.return_value = _resp(200, {"resources": [], "page": {"number": 0, "totalPages": 1}})
    c = make_client(session)
    c.post("/api/3/assets/search", json_body={"filters": []})
    kwargs = session.request.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["json"] == {"filters": []}


def test_paginate_post_yields_across_pages(session):
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session)
    items = list(c.paginate_post("/api/3/assets/search", json_body={"filters": []}, page_size=500))
    assert [i["id"] for i in items] == [1, 2]


def test_zero_pages_returns_empty(session):
    session.request.return_value = _resp(200, {"resources": [], "page": {"number": 0, "totalPages": 0}})
    c = make_client(session)
    assert list(c.paginate("/api/3/sites")) == []


def test_client_uses_basic_auth_when_provided(session):
    """basic_auth=(user, pw) sends auth=... and omits X-Api-Key."""
    session.request.return_value = _resp(200, {"ok": True})
    c = Rapid7Client(
        base_url="https://acme.hosted.rapid7.com",
        basic_auth=("svc", "secret"),
        verify_tls=True,
        timeout_seconds=5,
        max_retries=2,
        session=session,
    )
    c.get("/api/3/sites")
    _, kwargs = session.request.call_args
    assert kwargs["auth"] == ("svc", "secret")
    assert "X-Api-Key" not in kwargs["headers"]


def test_client_passes_no_auth_kwarg_value_in_api_key_mode(session):
    """In api_key mode, auth= is None (requests treats this as 'no auth')."""
    session.request.return_value = _resp(200, {"ok": True})
    c = make_client(session)
    c.get("/api/3/sites")
    _, kwargs = session.request.call_args
    assert kwargs["auth"] is None
    assert kwargs["headers"]["X-Api-Key"] == "key"


def test_client_rejects_both_api_key_and_basic_auth():
    with pytest.raises(ValueError, match="exactly one"):
        Rapid7Client(
            base_url="https://x",
            api_key="k",
            basic_auth=("u", "p"),
        )


def test_client_rejects_neither_api_key_nor_basic_auth():
    with pytest.raises(ValueError, match="exactly one"):
        Rapid7Client(base_url="https://x")


def test_client_error_carries_status_code_on_4xx(session):
    """Non-retryable 4xx must populate Rapid7ClientError.status_code so
    callers can branch numerically rather than substring-matching."""
    session.request.return_value = _resp(404, {"message": "not found"})
    c = make_client(session)
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/blackouts")
    assert exc.value.status_code == 404


def test_client_error_carries_status_code_on_5xx_after_retries(session):
    """Retryable 5xx exhausting retries must also populate status_code."""
    session.request.return_value = _resp(503, {"message": "unavailable"})
    c = make_client(session)
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/sites")
    assert exc.value.status_code == 503


def test_auth_error_carries_status_code_on_401(session):
    session.request.return_value = _resp(401, {"message": "unauthorized"})
    c = make_client(session)
    with pytest.raises(Rapid7AuthError) as exc:
        c.get("/api/3/sites")
    assert exc.value.status_code == 401


def test_auth_error_carries_status_code_on_403(session):
    session.request.return_value = _resp(403, {"message": "forbidden"})
    c = make_client(session)
    with pytest.raises(Rapid7AuthError) as exc:
        c.get("/api/3/sites")
    assert exc.value.status_code == 403


def test_network_error_has_no_status_code(session):
    """Failures before any HTTP response → status_code=None."""
    session.request.side_effect = requests.ConnectionError("boom")
    c = make_client(session)
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/sites")
    assert exc.value.status_code is None


def test_network_error_message_includes_method_path_and_attempt_count(session):
    """The wrapped error message must name the method, path, and total
    attempts so an operator reading a multi-rule failure can identify
    which endpoint stalled. Regression guard: previously the message was
    just 'network error: <repr>' which gave no diagnostic context."""
    session.request.side_effect = requests.ReadTimeout("Read timed out (read timeout=30)")
    c = make_client(session)  # max_retries=2 from make_client default
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/sites/42/scan_credentials")
    msg = str(exc.value)
    assert "GET" in msg
    assert "/api/3/sites/42/scan_credentials" in msg
    # max_retries=2 → 1 initial + 2 retries = 3 attempts before giving up.
    assert "3 attempt(s)" in msg
    # Underlying error is preserved.
    assert "Read timed out" in msg
