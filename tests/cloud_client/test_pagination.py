from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from rapid7_healthcheck.cloud_client import CloudClient


def _mock_response(status: int, json_body: dict, headers: dict | None = None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_body
    resp.headers = headers or {}
    resp.text = ""
    return resp


def test_paginate_uses_v4_envelope_data_field():
    session = MagicMock()
    session.request.side_effect = [
        _mock_response(200, {
            "data": [{"id": 1}, {"id": 2}],
            "metadata": {"number": 0, "size": 2, "totalPages": 2, "totalResources": 3},
            "links": [],
        }),
        _mock_response(200, {
            "data": [{"id": 3}],
            "metadata": {"number": 1, "size": 2, "totalPages": 2, "totalResources": 3},
            "links": [],
        }),
    ]
    client = CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
        session=session,
    )
    results = list(client.paginate("/v4/integration/scan/engine"))
    assert results == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert session.request.call_count == 2


def test_paginate_single_page_does_not_request_more():
    session = MagicMock()
    session.request.return_value = _mock_response(200, {
        "data": [{"id": 1}],
        "metadata": {"number": 0, "size": 250, "totalPages": 1, "totalResources": 1},
        "links": [],
    })
    client = CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
        session=session,
    )
    results = list(client.paginate("/v4/integration/scan/engine"))
    assert results == [{"id": 1}]
    assert session.request.call_count == 1


def test_paginate_zero_pages_yields_nothing():
    session = MagicMock()
    session.request.return_value = _mock_response(200, {
        "data": [],
        "metadata": {"number": 0, "size": 250, "totalPages": 0, "totalResources": 0},
        "links": [],
    })
    client = CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
        session=session,
    )
    results = list(client.paginate("/v4/integration/scan/engine"))
    assert results == []


def test_post_one_returns_first_page_for_total_resources_reads():
    session = MagicMock()
    session.request.return_value = _mock_response(200, {
        "data": [{"id": "a"}],
        "metadata": {"number": 0, "size": 1, "totalPages": 17, "totalResources": 17},
        "links": [],
    })
    client = CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
        session=session,
    )
    body = client.post_one("/v4/integration/assets", json_body={"asset": "x"})
    assert body["metadata"]["totalResources"] == 17
    assert session.request.call_count == 1


def test_request_sends_x_api_key_header():
    session = MagicMock()
    session.request.return_value = _mock_response(200, {
        "data": [], "metadata": {"totalPages": 0}, "links": [],
    })
    client = CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="my-secret",
        session=session,
    )
    client.get("/v4/integration/scan/engine")
    sent_headers = session.request.call_args.kwargs["headers"]
    assert sent_headers["X-Api-Key"] == "my-secret"
