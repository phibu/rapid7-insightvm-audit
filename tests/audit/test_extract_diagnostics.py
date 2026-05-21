from __future__ import annotations

from rapid7_healthcheck.audit import _extract_diagnostics
from rapid7_healthcheck.client import Rapid7ClientError


def test_extracts_path_from_verbless_from_message():
    """cloud_client.py raises 'non-JSON response from {path}: ...' with no
    HTTP verb between 'from' and the path. _extract_diagnostics must still
    pull the path out."""
    err = Rapid7ClientError(
        "non-JSON response from /v4/integration/assets: Expecting value",
        status_code=500,
    )
    path, status = _extract_diagnostics(err)
    assert path == "/v4/integration/assets"
    assert status == 500


def test_extracts_path_from_verbed_from_message_still_works():
    """The existing 'from GET /api/3/...' shape must keep working."""
    err = Rapid7ClientError(
        "request failed from GET /api/3/sites: timeout", status_code=504,
    )
    path, status = _extract_diagnostics(err)
    assert path == "/api/3/sites"
    assert status == 504
