from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Iterable, Iterator

import pytest

from rapid7_healthcheck.config import (
    AppConfig,
    AssetCoverageThresholds,
    DataQualityThresholds,
    Rapid7Config,
    ReportConfig,
    ScanActivityThresholds,
    ScanEngineThresholds,
    Thresholds,
)


class FakeRapid7Client:
    """Test double matching the surface used by checks.

    Routes are registered via `set_get`, `set_paginate`, `set_post`, `set_paginate_post`.
    Routing key is (method_kind, path) where method_kind is "get"/"paginate"/"post"/"paginate_post".
    Path matching is exact.
    """

    def __init__(self) -> None:
        self._get: dict[str, dict] = {}
        self._get_raises: dict[str, BaseException] = {}
        self._post: dict[str, dict] = {}
        self._paginate: dict[str, list[dict]] = {}
        self._paginate_post: dict[str, list[dict]] = {}
        self._post_one_responses: dict[str, dict] = {}
        self.calls: list[tuple[str, str, dict | None, dict | None]] = []

    def set_get(self, path: str, body: dict) -> None:
        self._get[path] = body

    def set_get_raises(self, path: str, exc: BaseException) -> None:
        self._get_raises[path] = exc

    def set_post(self, path: str, body: dict) -> None:
        self._post[path] = body

    def set_paginate(self, path: str, resources: Iterable[dict]) -> None:
        self._paginate[path] = list(resources)

    def set_paginate_post(self, path: str, resources: Iterable[dict]) -> None:
        self._paginate_post[path] = list(resources)

    def set_post_one(self, path: str, response: dict) -> None:
        self._post_one_responses[path] = response

    def post_one(self, path: str, *, json_body: dict, params: dict | None = None) -> dict:
        self.calls.append(("post_one", path, params, json_body))
        return self._post_one_responses.get(path, {"resources": [], "page": {"totalResources": 0}})

    def connect(self) -> None:
        return None

    def get(self, path: str, params: dict | None = None) -> dict:
        self.calls.append(("get", path, params, None))
        if path in self._get_raises:
            raise self._get_raises[path]
        if path not in self._get:
            raise AssertionError(f"unexpected GET {path}")
        return self._get[path]

    def post(self, path: str, json_body: dict, params: dict | None = None) -> dict:
        self.calls.append(("post", path, params, json_body))
        if path not in self._post:
            raise AssertionError(f"unexpected POST {path}")
        return self._post[path]

    def paginate(self, path: str, params: dict | None = None, page_size: int = 500) -> Iterator[dict]:
        self.calls.append(("paginate", path, params, None))
        if path not in self._paginate:
            raise AssertionError(f"unexpected paginate {path}")
        yield from self._paginate[path]

    def paginate_post(
        self,
        path: str,
        json_body: dict,
        params: dict | None = None,
        page_size: int = 500,
    ) -> Iterator[dict]:
        self.calls.append(("paginate_post", path, params, json_body))
        if path not in self._paginate_post:
            raise AssertionError(f"unexpected paginate_post {path}")
        yield from self._paginate_post[path]


@pytest.fixture
def fake_client() -> FakeRapid7Client:
    return FakeRapid7Client()


def _default_config() -> AppConfig:
    return AppConfig(
        rapid7=Rapid7Config(
            base_url="https://us.api.insight.rapid7.com",
            verify_tls=True,
            request_timeout_seconds=30,
            max_retries=3,
        ),
        report=ReportConfig(
            output_dir="./reports",
            filename_pattern="rapid7-health-{timestamp}.html",
            title="Rapid7 InsightVM Environment Health Check",
        ),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(
                last_contact_warn_hours=2,
                last_contact_fail_hours=24,
            ),
            scan_activity=ScanActivityThresholds(
                recent_window_days=7,
                stuck_scan_hours=24,
                site_no_scan_days=14,
            ),
            asset_coverage=AssetCoverageThresholds(
                stale_asset_days=30,
                flag_unscanned_assets=True,
                never_scanned_days=90,
            ),
            data_quality=DataQualityThresholds(
                flag_missing_os=True,
                flag_empty_sites=True,
            ),
        ),
        checks={
            "scan_engines": True,
            "scan_activity": True,
            "asset_coverage": True,
            "data_quality": True,
        },
    )


@pytest.fixture
def app_config() -> AppConfig:
    return _default_config()


@pytest.fixture
def app_config_factory() -> Callable[..., AppConfig]:
    def make(**overrides: Any) -> AppConfig:
        cfg = _default_config()
        return replace(cfg, **overrides)

    return make
