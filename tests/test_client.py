from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from rapid7_healthcheck.client import (
    Rapid7AuthError,
    Rapid7Client,
    Rapid7ClientError,
    _summarize_params,
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
        c.get("/api/3/does_not_exist")
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


def test_post_one_returns_first_page_response(monkeypatch):
    """post_one issues a single POST and returns the parsed response without paginating."""
    from rapid7_healthcheck.client import Rapid7Client
    import requests

    captured = {}

    def fake_request(method, url, **kw):
        captured["method"] = method
        captured["url"] = url
        captured["json"] = kw.get("json")
        captured["params"] = kw.get("params")
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"resources":[{"id":1}],"page":{"totalResources":42,"size":10}}'
        return resp

    client = Rapid7Client(base_url="https://example.com", api_key="k")
    monkeypatch.setattr(client._session, "request", fake_request)

    body = client.post_one(
        "/api/3/assets/search",
        json_body={"filters": [], "match": "all"},
        params={"size": 10},
    )

    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/3/assets/search")
    assert captured["params"] == {"size": 10}
    assert captured["json"] == {"filters": [], "match": "all"}
    assert body["page"]["totalResources"] == 42
    assert body["resources"] == [{"id": 1}]


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


def test_summarize_params_none_returns_empty_string():
    assert _summarize_params(None) == ""


def test_summarize_params_empty_dict_returns_empty_string():
    assert _summarize_params({}) == ""


def test_summarize_params_basic_kv_pairs():
    out = _summarize_params({"page": 0, "size": 100})
    # Order may vary (dict iteration is insertion-order in 3.7+, but be
    # tolerant). Both keys + values appear, prefixed with "?".
    assert out.startswith("?")
    assert "page=0" in out
    assert "size=100" in out


def test_summarize_params_redacts_sensitive_keys():
    """Defense-in-depth: any key whose lowercased name contains
    'key', 'token', 'secret', 'password', or 'auth' must be redacted."""
    out = _summarize_params({
        "q": "x",
        "api_key": "MUST-NOT-LEAK-1",
        "auth_token": "MUST-NOT-LEAK-2",
        "user_password": "MUST-NOT-LEAK-3",
        "session_secret": "MUST-NOT-LEAK-4",
        "X-Api-Key": "MUST-NOT-LEAK-5",
    })
    assert "MUST-NOT-LEAK-1" not in out
    assert "MUST-NOT-LEAK-2" not in out
    assert "MUST-NOT-LEAK-3" not in out
    assert "MUST-NOT-LEAK-4" not in out
    assert "MUST-NOT-LEAK-5" not in out
    assert "***" in out
    assert "q=x" in out  # non-sensitive keys still appear


def test_summarize_params_caps_output_at_200_chars():
    """Long params dicts get truncated with an ellipsis marker so log
    lines stay scannable."""
    big = {f"k{i}": f"v{i}" for i in range(100)}
    out = _summarize_params(big)
    assert len(out) <= 200


import logging


def test_successful_get_emits_arrow_debug_lines(caplog, session):
    """A successful GET produces both a `→` (request) and `←` (response)
    DEBUG line, each containing method and path."""
    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")
    session.request.return_value = _resp(200, {"ok": True})
    c = make_client(session)
    c.get("/api/3/test")

    request_lines = [r for r in caplog.records if "→" in r.getMessage()]
    response_lines = [r for r in caplog.records if "←" in r.getMessage()]
    assert len(request_lines) >= 1
    assert len(response_lines) >= 1
    assert "GET" in request_lines[0].getMessage()
    assert "/api/3/test" in request_lines[0].getMessage()
    assert "GET" in response_lines[0].getMessage()
    assert "200" in response_lines[0].getMessage()


def test_get_with_params_includes_sanitized_querystring(caplog, session):
    """Querystring appears in the `→` line; sensitive keys are redacted."""
    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")
    session.request.return_value = _resp(200, {"ok": True})
    c = make_client(session)
    c.get("/api/3/test", params={"page": 0, "api_key": "SECRET"})

    request_lines = [r for r in caplog.records if "→" in r.getMessage()]
    assert any("page=0" in r.getMessage() for r in request_lines)
    assert all("SECRET" not in r.getMessage() for r in request_lines)
    assert any("***" in r.getMessage() for r in request_lines)


def test_404_response_emits_x_warning_line(caplog, session):
    """Non-retried error (404) emits a WARNING with `✗`, status, and body snippet."""
    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")
    session.request.return_value = _resp(404, None)
    # Manually set text for the body snippet assertion
    session.request.return_value.text = "not found here"
    c = make_client(session)

    with pytest.raises(Rapid7ClientError):
        c.get("/api/3/missing")

    warning_lines = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "✗" in r.getMessage()
    ]
    assert len(warning_lines) == 1
    msg = warning_lines[0].getMessage()
    assert "404" in msg
    assert "/api/3/missing" in msg
    assert "not found here" in msg


def test_retry_path_emits_debug_line(caplog, session, monkeypatch):
    """A retry-status response (e.g. 429) followed by 200 emits a
    `retry N/M` DEBUG line."""
    caplog.set_level(logging.DEBUG, logger="rapid7_healthcheck.client")
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: None)
    session.request.side_effect = [
        _resp(429, headers={"Retry-After": "0"}),
        _resp(200, {"ok": True}),
    ]
    c = make_client(session, max_retries=2)
    c.get("/api/3/flaky")

    retry_lines = [r for r in caplog.records if "retry " in r.getMessage()]
    assert len(retry_lines) >= 1
    assert "/api/3/flaky" in retry_lines[0].getMessage()


def test_client_default_timeout_is_60_seconds(session):
    """Default request timeout is 60s (was 30s in v0.2.7)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._timeout == 60


def test_client_default_parallel_pages_is_one(session):
    """Default parallel_pages is 1 (sequential — preserves today's behavior)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._parallel_pages == 1


def test_client_default_page_size_is_250(session):
    """Default paginated page size is 250 (was 500 in v0.2.7)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._default_page_size == 250


def test_client_accepts_parallel_pages_kwarg(session):
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        parallel_pages=6,
        session=session,
    )
    assert c._parallel_pages == 6


def test_client_rejects_parallel_pages_zero(session):
    with pytest.raises(ValueError, match="parallel_pages"):
        Rapid7Client(
            base_url="https://example.test",
            api_key="k",
            parallel_pages=0,
            session=session,
        )


def test_client_rejects_parallel_pages_seventeen(session):
    with pytest.raises(ValueError, match="parallel_pages"):
        Rapid7Client(
            base_url="https://example.test",
            api_key="k",
            parallel_pages=17,
            session=session,
        )


def test_client_rejects_default_page_size_zero(session):
    with pytest.raises(ValueError, match="default_page_size"):
        Rapid7Client(
            base_url="https://example.test",
            api_key="k",
            default_page_size=0,
            session=session,
        )


def test_client_rejects_default_page_size_501(session):
    with pytest.raises(ValueError, match="default_page_size"):
        Rapid7Client(
            base_url="https://example.test",
            api_key="k",
            default_page_size=501,
            session=session,
        )


def test_client_accepts_parallel_pages_sixteen(session):
    """Inclusive upper bound — 16 must be accepted."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        parallel_pages=16,
        session=session,
    )
    assert c._parallel_pages == 16


def test_client_accepts_default_page_size_500(session):
    """Inclusive upper bound — 500 must be accepted."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        default_page_size=500,
        session=session,
    )
    assert c._default_page_size == 500


import threading
import time as _time_mod


def test_parallel_paginate_yields_in_page_order(session):
    """Force page 2 to complete before page 1 via a threading barrier.
    Iterator must still yield resources in page-0, page-1, page-2 order."""
    page0 = {"resources": [{"id": "p0a"}, {"id": "p0b"}], "page": {"number": 0, "totalPages": 3}}
    page1 = {"resources": [{"id": "p1a"}], "page": {"number": 1, "totalPages": 3}}
    page2 = {"resources": [{"id": "p2a"}, {"id": "p2b"}], "page": {"number": 2, "totalPages": 3}}

    pages_by_number = {0: page0, 1: page1, 2: page2}
    page2_done = threading.Event()

    def fake_request(*args, **kwargs):
        page_num = kwargs["params"]["page"]
        if page_num == 1:
            # Block until page 2 has finished — guarantees out-of-order
            # completion so the test exercises the as_completed path.
            page2_done.wait(timeout=2.0)
        resp = _resp(200, pages_by_number[page_num])
        if page_num == 2:
            page2_done.set()
        return resp

    session.request.side_effect = fake_request
    c = make_client(session, parallel_pages=3)
    items = list(c.paginate("/api/3/sites"))
    assert [i["id"] for i in items] == ["p0a", "p0b", "p1a", "p2a", "p2b"]


def test_parallel_paginate_propagates_first_error(session):
    """Page 1 of 3 returns 500 — _paginate must raise Rapid7ClientError
    and must not yield page 1's or page 2's resources. Page 0 is yielded
    via Phase 1 before any failure."""
    page0 = {"resources": [{"id": "p0"}], "page": {"number": 0, "totalPages": 3}}
    page2 = {"resources": [{"id": "p2"}], "page": {"number": 2, "totalPages": 3}}

    def fake_request(*args, **kwargs):
        page_num = kwargs["params"]["page"]
        if page_num == 0:
            return _resp(200, page0)
        if page_num == 1:
            return _resp(500, {"message": "server error"})
        if page_num == 2:
            return _resp(200, page2)
        raise AssertionError(f"unexpected page {page_num}")

    session.request.side_effect = fake_request
    c = make_client(session, parallel_pages=3, max_retries=0)

    yielded: list[dict] = []
    with pytest.raises(Rapid7ClientError) as exc_info:
        for item in c.paginate("/api/3/sites"):
            yielded.append(item)

    assert exc_info.value.status_code == 500
    assert yielded == [{"id": "p0"}]


def test_parallel_paginate_default_one_is_sequential(session, monkeypatch):
    """With parallel_pages=1, ThreadPoolExecutor must NOT be instantiated."""
    from concurrent.futures import ThreadPoolExecutor as _real_pool
    instances: list = []

    def spy_pool(*args, **kwargs):
        instances.append((args, kwargs))
        return _real_pool(*args, **kwargs)

    monkeypatch.setattr("rapid7_healthcheck.client.ThreadPoolExecutor", spy_pool)

    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session, parallel_pages=1)
    items = list(c.paginate("/api/3/sites"))
    assert [i["id"] for i in items] == [1, 2]
    assert instances == []  # executor never created


def test_parallel_paginate_per_call_kwarg_overrides_instance(session, monkeypatch):
    """Per-call parallel_pages kwarg overrides instance default."""
    from concurrent.futures import ThreadPoolExecutor as _real_pool
    instances: list = []

    def spy_pool(*args, max_workers=None, **kwargs):
        instances.append(max_workers)
        return _real_pool(*args, max_workers=max_workers, **kwargs)

    monkeypatch.setattr("rapid7_healthcheck.client.ThreadPoolExecutor", spy_pool)

    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session, parallel_pages=1)  # instance default = 1
    items = list(c.paginate("/api/3/sites", parallel_pages=4))
    assert [i["id"] for i in items] == [1, 2]
    assert instances == [4]  # per-call kwarg won


def test_paginate_uses_default_page_size_when_unspecified(session):
    """paginate() without page_size= uses instance default_page_size (250)."""
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 1}}
    session.request.return_value = _resp(200, page0)
    c = make_client(session)  # default_page_size=250 (kwarg default)
    list(c.paginate("/api/3/sites"))
    assert session.request.call_args.kwargs["params"]["size"] == 250


def test_paginate_explicit_page_size_overrides_default(session):
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 1}}
    session.request.return_value = _resp(200, page0)
    c = make_client(session)
    list(c.paginate("/api/3/sites", page_size=100))
    assert session.request.call_args.kwargs["params"]["size"] == 100


def test_get_uses_per_call_timeout_when_provided(monkeypatch):
    """Per-call timeout overrides the client default for that request only."""
    from rapid7_healthcheck.client import Rapid7Client
    captured: dict = {}

    class _FakeSession:
        def request(self, **kwargs):
            captured.update(kwargs)
            class _R:
                status_code = 200
                def json(self): return {}
                @property
                def text(self): return ""
            return _R()

    c = Rapid7Client(
        base_url="https://r7.example",
        api_key="k",
        timeout_seconds=60,
        session=_FakeSession(),
    )
    c.get("/api/3", timeout=180)
    assert captured["timeout"] == 180

    c.get("/api/3")
    assert captured["timeout"] == 60


def test_paginate_propagates_timeout_to_every_page(monkeypatch):
    """Per-call timeout reaches every _request call inside paginate."""
    from rapid7_healthcheck.client import Rapid7Client
    timeouts: list = []

    class _FakeSession:
        def __init__(self):
            self._page = 0
        def request(self, **kwargs):
            timeouts.append(kwargs["timeout"])
            page = self._page
            self._page += 1
            class _R:
                status_code = 200
                def json(self):
                    return {
                        "resources": [{"id": page}],
                        "page": {"totalPages": 3},
                    }
                @property
                def text(self): return ""
            return _R()

    c = Rapid7Client(
        base_url="https://r7.example",
        api_key="k",
        timeout_seconds=60,
        parallel_pages=1,
        session=_FakeSession(),
    )
    list(c.paginate("/api/3/agents", timeout=180))
    assert timeouts == [180, 180, 180]


def test_paginate_log_is_at_debug_level(caplog):
    """The 'paginating' log line must be at DEBUG so default-run output
    isn't dominated by per-call pagination chatter. The new ProgressReporter
    handles the user-facing progress story; this log is for post-mortem."""
    from rapid7_healthcheck.client import Rapid7Client

    class _FakeSession:
        def __init__(self):
            self._page = 0
        def request(self, **kwargs):
            page = self._page
            self._page += 1
            class _R:
                status_code = 200
                def json(self):
                    # Force the parallel-batch branch:
                    # totalPages > 1 and parallel_pages > 1.
                    return {
                        "resources": [{"id": page}],
                        "page": {"totalPages": 4},
                    }
                @property
                def text(self): return ""
            return _R()

    c = Rapid7Client(
        base_url="https://r7.example",
        api_key="k",
        timeout_seconds=60,
        parallel_pages=2,
        session=_FakeSession(),
    )
    import logging
    with caplog.at_level(logging.DEBUG, logger="rapid7_healthcheck.client"):
        list(c.paginate("/api/3/agents"))

    paginating_records = [
        r for r in caplog.records
        if "paginating" in r.getMessage().lower()
    ]
    assert paginating_records, "no 'paginating' log emitted"
    for r in paginating_records:
        assert r.levelno == logging.DEBUG, (
            f"'paginating' log expected at DEBUG, got {r.levelname}: {r.getMessage()}"
        )
