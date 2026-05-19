"""Tests for _extract_diagnostics regex coverage across v3 (/api/3) and
v4 (/v4/integration) error message formats."""
from __future__ import annotations

from rapid7_healthcheck.audit import _extract_diagnostics
from rapid7_healthcheck.client import Rapid7ClientError
from rapid7_healthcheck.cloud_client import CloudClientError


def test_v3_path_matches_at_form():
    e = Rapid7ClientError("auth failed (401) at /api/3/sites", status_code=401)
    path, code = _extract_diagnostics(e)
    assert path == "/api/3/sites"
    assert code == 401


def test_v3_path_matches_from_form():
    e = Rapid7ClientError(
        "HTTP 500 from GET /api/3/scan_engines: <body>", status_code=500,
    )
    path, code = _extract_diagnostics(e)
    assert path == "/api/3/scan_engines"
    assert code == 500


def test_v3_path_matches_on_form():
    e = Rapid7ClientError(
        "network error after 4 attempt(s) on GET /api/3/assets: timeout",
    )
    path, code = _extract_diagnostics(e)
    assert path == "/api/3/assets"
    assert code is None


def test_v4_path_matches_at_form():
    """The "at" message form (`...at /path...`) is produced by client.py
    (v3 auth) only; cloud_client.py never emits this shape today. Pinned
    anyway so that if a future v4 error path adopts the "at" form, the
    regex is already ready for it."""
    e = CloudClientError(
        "cloud auth failed (401) at /v4/integration/assets", status_code=401,
    )
    path, code = _extract_diagnostics(e)
    assert path == "/v4/integration/assets"
    assert code == 401


def test_v4_path_matches_from_form():
    e = CloudClientError(
        "HTTP 500 from POST /v4/integration/assets: <body>", status_code=500,
    )
    path, code = _extract_diagnostics(e)
    assert path == "/v4/integration/assets"
    assert code == 500


def test_v4_path_matches_on_form():
    e = CloudClientError(
        "network error after 4 attempt(s) on POST /v4/integration/assets: timeout",
    )
    path, code = _extract_diagnostics(e)
    assert path == "/v4/integration/assets"
    assert code is None


def test_v4_engine_path_matches():
    """Real-world v4 paths beyond /v4/integration/assets."""
    e = CloudClientError(
        "HTTP 502 from GET /v4/integration/scan/engine: <body>", status_code=502,
    )
    path, code = _extract_diagnostics(e)
    assert path == "/v4/integration/scan/engine"
    assert code == 502


def test_non_rapid7_error_returns_none():
    e = ValueError("something else")
    assert _extract_diagnostics(e) == (None, None)


def test_unmatched_message_returns_none_path():
    e = Rapid7ClientError("some other error message format", status_code=500)
    path, code = _extract_diagnostics(e)
    assert path is None
    assert code == 500
