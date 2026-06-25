# Cloud Drift Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third audit category -- Cloud Drift -- that reconciles the on-prem Security Console (v3) with the InsightVM Cloud Integrations API (v4), shipping three v0 rules behind an opt-in `cloud_integration:` config block.

**Architecture:** New `CloudClient` peer to `Rapid7Client` with its own minimal read-only allowlist (`GET` + `POST /v4/integration/assets` only). New `CloudDriftAuditCheck` orchestrator with its own `_CLOUD_RULE_REGISTRY`, sibling to `ConfigurationAuditCheck` and `UserPermissionAuditCheck`. New `CloudSnapshot` holds both clients for cross-referencing. Whole category produces a single `skipped` `CheckResult` when `cloud_integration` is absent or disabled.

**Tech Stack:** Python 3.11+, `requests`, `dataclasses`, `pytest`. Read-only invariants enforced via verb/path allowlists in `CloudClient._request`.

**Spec:** [`docs/superpowers/specs/2026-05-07-cloud-drift-audit-design.md`](../specs/2026-05-07-cloud-drift-audit-design.md)

---

## Conventions used by every task

- Pytest is run from the repo root: `pytest <path> -v`.
- All new modules use `from __future__ import annotations` at the top.
- Rule IDs use the `cd.` prefix to keep them in a separate namespace from `op.*` (operational) and audit rules.
- Severity defaults: every v0 rule defaults to `warn` per spec; per-finding severity may upgrade to `fail` on hard sync failures (rule `cd.console_asset_count_drift` only).
- Commits are atomic: one task = one commit. Commit messages use the existing `feat:` / `test:` / `docs:` / `chore:` prefixes seen in `git log`.

---

## Task 1: CloudClientError + minimal CloudClient skeleton (no network)

**Files:**
- Create: `src/rapid7_healthcheck/cloud_client.py`
- Test: `tests/cloud_client/__init__.py` (empty), `tests/cloud_client/test_read_only_enforcement.py`

- [ ] **Step 1: Write the failing tests for verb/path allowlist enforcement**

Create `tests/cloud_client/__init__.py` (empty file).

Create `tests/cloud_client/test_read_only_enforcement.py`:

```python
from __future__ import annotations

import pytest

from rapid7_healthcheck.cloud_client import (
    CloudClient,
    ReadOnlyViolationError,
)


@pytest.fixture
def client() -> CloudClient:
    return CloudClient(
        base_url="https://us.api.insight.rapid7.com/vm/",
        api_key="dummy",
    )


def test_allowed_verbs_constant_is_get_and_post_only():
    from rapid7_healthcheck.cloud_client import _ALLOWED_VERBS
    assert _ALLOWED_VERBS == frozenset({"GET", "POST"})


def test_allowed_post_paths_is_assets_only():
    from rapid7_healthcheck.cloud_client import _ALLOWED_POST_PATHS
    assert _ALLOWED_POST_PATHS == frozenset({"/v4/integration/assets"})


def test_post_to_disallowed_path_raises_before_network(client):
    # /v4/integration/scan would START a scan -- never permit.
    with pytest.raises(ReadOnlyViolationError) as exc:
        client.post("/v4/integration/scan", json_body={})
    assert "/v4/integration/scan" in str(exc.value)


def test_post_to_scan_stop_path_raises(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/scan/123/stop", json_body={})


def test_post_to_engine_config_path_raises(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/scan/engine/5/configuration", json_body={})


def test_post_to_sites_raises_until_a_rule_needs_it(client):
    # /v4/integration/sites is read-safe but not in the allowlist (YAGNI).
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/sites", json_body={})


def test_post_to_vulnerabilities_raises_until_a_rule_needs_it(client):
    with pytest.raises(ReadOnlyViolationError):
        client.post("/v4/integration/vulnerabilities", json_body={})


def test_client_has_no_put_method(client):
    assert not hasattr(client, "put")


def test_client_has_no_patch_method(client):
    assert not hasattr(client, "patch")


def test_client_has_no_delete_method(client):
    assert not hasattr(client, "delete")
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pytest tests/cloud_client/test_read_only_enforcement.py -v`
Expected: ImportError / ModuleNotFoundError on `rapid7_healthcheck.cloud_client`.

- [ ] **Step 3: Implement minimal CloudClient with allowlist enforcement**

Create `src/rapid7_healthcheck/cloud_client.py`:

```python
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterator
from urllib.parse import urljoin

import requests

from rapid7_healthcheck import __version__
from rapid7_healthcheck.client import (
    Rapid7AuthError,
    Rapid7ClientError,
    ReadOnlyViolationError,
    _summarize_params,
)

logger = logging.getLogger(__name__)


class CloudClientError(Rapid7ClientError):
    """HTTP or network failure interacting with the InsightVM Cloud
    Integrations API (v4).

    Subclass of `Rapid7ClientError` so the existing `_extract_diagnostics`
    helper in `audit/__init__.py` can pull `status_code` off the same
    exception type without code changes. Path extraction in
    `_extract_diagnostics` won't match v4 paths (its regex is
    `/api/3/...`-only); error_path on cloud-rule failures will be `None`,
    which is acceptable -- error_status_code carries the same diagnostic
    weight.
    """


_RETRY_STATUS = {429, 502, 503, 504}

_ALLOWED_VERBS = frozenset({"GET", "POST"})

# Minimal v4 read-only allowlist. Every entry is a search endpoint
# whose filter criteria travel in the request body. Mutator endpoints
# (POST /v4/integration/scan, POST /v4/integration/scan/{id}/stop,
# POST /v4/integration/scan/engine/{id}/configuration, DELETE on the
# same) are deliberately omitted. POST /v4/integration/sites and
# POST /v4/integration/vulnerabilities are read-safe but not needed
# by v0 rules -- re-add when a rule requires them.
_ALLOWED_POST_PATHS = frozenset({"/v4/integration/assets"})


class CloudClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        parallel_pages: int = 1,
        default_page_size: int = 250,
        session: requests.Session | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("CloudClient requires api_key")
        if not (1 <= parallel_pages <= 16):
            raise ValueError(
                f"parallel_pages must be in range [1, 16]; got {parallel_pages}"
            )
        if not (1 <= default_page_size <= 500):
            raise ValueError(
                f"default_page_size must be in range [1, 500]; got {default_page_size}"
            )
        self._base_url = base_url.rstrip("/")
        self._verify = verify_tls
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._parallel_pages = parallel_pages
        self._default_page_size = default_page_size
        self._session = session or requests.Session()
        self._headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": f"rapid7-healthcheck/{__version__}",
            "X-Api-Key": api_key,
        }

    # --- Public HTTP helpers ---

    def get(self, path: str, params: dict | None = None, *, timeout: int | None = None) -> dict:
        return self._request("GET", path, params=params, timeout=timeout)

    def post(self, path: str, json_body: dict, params: dict | None = None) -> dict:
        return self._request("POST", path, params=params, json_body=json_body)

    def post_one(
        self,
        path: str,
        *,
        json_body: dict,
        params: dict | None = None,
        timeout: int | None = None,
    ) -> dict:
        """Issue a single POST and return the parsed response.

        Useful when the caller only needs `metadata.totalResources` and the
        first page of resources. The path must be in `_ALLOWED_POST_PATHS`.
        """
        return self._request(
            "POST", path, params=params, json_body=json_body, timeout=timeout
        )

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int | None = None,
        parallel_pages: int | None = None,
        *,
        timeout: int | None = None,
    ) -> Iterator[dict]:
        yield from self._paginate(
            "GET", path,
            params=params,
            page_size=page_size if page_size is not None else self._default_page_size,
            parallel_pages=parallel_pages if parallel_pages is not None else self._parallel_pages,
            timeout=timeout,
        )

    # --- Internals ---

    def _paginate(
        self,
        method: str,
        path: str,
        *,
        params: dict | None,
        page_size: int,
        parallel_pages: int = 1,
        json_body: dict | None = None,
        timeout: int | None = None,
    ) -> Iterator[dict]:
        # v4 envelope is {data, metadata, links}; metadata.totalPages drives loop.
        page0_params = dict(params or {})
        page0_params["page"] = 0
        page0_params["size"] = page_size
        body0 = self._request(method, path, params=page0_params, json_body=json_body, timeout=timeout)
        for resource in body0.get("data", []):
            yield resource

        meta = body0.get("metadata", {})
        total_pages = int(meta.get("totalPages", 0))
        if total_pages <= 1:
            return

        if parallel_pages <= 1:
            for page_num in range(1, total_pages):
                page_params = dict(params or {})
                page_params["page"] = page_num
                page_params["size"] = page_size
                body = self._request(method, path, params=page_params, json_body=json_body, timeout=timeout)
                for resource in body.get("data", []):
                    yield resource
            return

        logger.debug(
            "paginating %s with %d pages, parallel=%d",
            path, total_pages, parallel_pages,
        )
        remaining = list(range(1, total_pages))
        with ThreadPoolExecutor(max_workers=parallel_pages) as executor:
            try:
                while remaining:
                    batch = remaining[:parallel_pages]
                    remaining = remaining[parallel_pages:]
                    futures = {}
                    for page_num in batch:
                        page_params = dict(params or {})
                        page_params["page"] = page_num
                        page_params["size"] = page_size
                        fut = executor.submit(
                            self._request, method, path,
                            params=page_params, json_body=json_body, timeout=timeout,
                        )
                        futures[page_num] = fut

                    results: dict[int, dict] = {}
                    fut_to_page = {fut: pn for pn, fut in futures.items()}
                    for fut in as_completed(futures.values()):
                        results[fut_to_page[fut]] = fut.result()

                    for page_num in batch:
                        for resource in results[page_num].get("data", []):
                            yield resource
            except BaseException:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: int | None = None,
    ) -> dict:
        # Read-only enforcement runs before any network I/O.
        if method not in _ALLOWED_VERBS:
            raise ReadOnlyViolationError(
                f"refusing non-read verb {method!r}; allowed: {sorted(_ALLOWED_VERBS)}"
            )
        if method == "POST" and path not in _ALLOWED_POST_PATHS:
            raise ReadOnlyViolationError(
                f"POST not allowed on {path!r}; "
                f"allowlist: {sorted(_ALLOWED_POST_PATHS)}"
            )

        url = self._base_url + path if path.startswith("/") else urljoin(self._base_url + "/", path)
        attempt = 0
        last_error: Exception | None = None
        while attempt <= self._max_retries:
            logger.debug("→ %s %s%s", method, path, _summarize_params(params))
            try:
                start = time.monotonic()
                resp = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    headers=self._headers,
                    timeout=timeout if timeout is not None else self._timeout,
                    verify=self._verify,
                )
                elapsed_ms = int((time.monotonic() - start) * 1000)
                logger.debug("← %s %s %d in %dms", method, path, resp.status_code, elapsed_ms)
            except requests.RequestException as e:
                last_error = e
                logger.debug("✗ %s %s network error: %s", method, path, e)
                if attempt >= self._max_retries:
                    raise CloudClientError(
                        f"network error after {attempt + 1} attempt(s) "
                        f"on {method} {path}: {e}"
                    ) from e
                time.sleep(2 ** attempt)
                attempt += 1
                continue

            if resp.status_code in (401, 403):
                logger.warning(
                    "✗ %s %s %d: auth failed", method, path, resp.status_code,
                )
                raise Rapid7AuthError(
                    f"cloud auth failed ({resp.status_code}); check R7_CLOUD_API_KEY and base_url",
                    status_code=resp.status_code,
                )
            if resp.status_code in _RETRY_STATUS:
                if attempt >= self._max_retries:
                    raise CloudClientError(
                        f"{resp.status_code} after {attempt + 1} attempts: {resp.text[:1500]}",
                        status_code=resp.status_code,
                    )
                delay = self._retry_delay(resp, attempt)
                logger.debug(
                    "retry %d/%d for %s %s after %.1fs (status %d)",
                    attempt + 1, self._max_retries, method, path, delay, resp.status_code,
                )
                time.sleep(delay)
                attempt += 1
                continue
            if resp.status_code >= 400:
                logger.warning(
                    "✗ %s %s %d: %s", method, path, resp.status_code,
                    resp.text[:200] if resp.text else "<empty body>",
                )
                raise CloudClientError(
                    f"HTTP {resp.status_code} from {method} {path}: {resp.text[:1500]}",
                    status_code=resp.status_code,
                )
            try:
                return resp.json()
            except ValueError as e:
                raise CloudClientError(f"non-JSON response from {path}: {e}") from e

        raise CloudClientError(f"exhausted retries; last error: {last_error}")

    @staticmethod
    def _retry_delay(resp: requests.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return float(2 ** attempt)
```

Re-export `ReadOnlyViolationError` from this module so consumers can `from rapid7_healthcheck.cloud_client import ReadOnlyViolationError` without dipping into `client.py`. This is what the test imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/cloud_client/test_read_only_enforcement.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/cloud_client.py tests/cloud_client/__init__.py tests/cloud_client/test_read_only_enforcement.py
git commit -m "feat(cloud-drift): CloudClient with read-only allowlist (GET + POST /v4/integration/assets)"
```

---

## Task 2: CloudClient pagination handles v4 envelope

**Files:**
- Test: `tests/cloud_client/test_pagination.py`

- [ ] **Step 1: Write the failing pagination test**

Create `tests/cloud_client/test_pagination.py`:

```python
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
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/cloud_client/test_pagination.py -v`
Expected: 5 passed (the implementation from Task 1 already supports this -- these tests pin the v4 envelope contract).

- [ ] **Step 3: Commit**

```bash
git add tests/cloud_client/test_pagination.py
git commit -m "test(cloud-client): pin v4 envelope (data/metadata) pagination contract"
```

---

## Task 3: CloudIntegrationConfig in config schema

**Files:**
- Modify: `src/rapid7_healthcheck/config.py`
- Test: extend an existing config test file or create `tests/test_config_cloud_integration.py`

- [ ] **Step 1: Write the failing config-validation tests**

Create `tests/test_config_cloud_integration.py`:

```python
from __future__ import annotations

import pytest

from rapid7_healthcheck.config import (
    CloudIntegrationConfig,
    ConfigError,
    _build_cloud_integration_config,
)


def test_default_when_section_missing():
    cfg = _build_cloud_integration_config(None)
    assert isinstance(cfg, CloudIntegrationConfig)
    assert cfg.enabled is False
    assert cfg.base_url == ""
    assert cfg.api_key_env == "R7_CLOUD_API_KEY"
    assert cfg.timeout_seconds == 30
    assert cfg.max_retries == 3
    assert cfg.parallel_pages == 1


def test_full_block_parses():
    cfg = _build_cloud_integration_config({
        "enabled": True,
        "base_url": "https://us.api.insight.rapid7.com/vm/",
        "api_key_env": "MY_KEY",
        "timeout_seconds": 60,
        "max_retries": 5,
        "parallel_pages": 4,
    })
    assert cfg.enabled is True
    assert cfg.base_url == "https://us.api.insight.rapid7.com/vm/"
    assert cfg.api_key_env == "MY_KEY"
    assert cfg.timeout_seconds == 60
    assert cfg.max_retries == 5
    assert cfg.parallel_pages == 4


def test_unknown_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        _build_cloud_integration_config({"enabled": True, "wat": "no"})


def test_enabled_without_base_url_rejected():
    with pytest.raises(ConfigError, match="base_url"):
        _build_cloud_integration_config({"enabled": True})


def test_base_url_must_be_https():
    with pytest.raises(ConfigError, match="https://"):
        _build_cloud_integration_config({
            "enabled": True,
            "base_url": "http://us.api.insight.rapid7.com/vm/",
        })


def test_disabled_with_no_base_url_is_fine():
    cfg = _build_cloud_integration_config({"enabled": False})
    assert cfg.enabled is False
    assert cfg.base_url == ""


def test_parallel_pages_range_enforced():
    with pytest.raises(ConfigError, match="parallel_pages"):
        _build_cloud_integration_config({
            "enabled": True,
            "base_url": "https://us.api.insight.rapid7.com/vm/",
            "parallel_pages": 99,
        })
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_config_cloud_integration.py -v`
Expected: ImportError on `CloudIntegrationConfig`.

- [ ] **Step 3: Add CloudIntegrationConfig + validator to config.py**

In `src/rapid7_healthcheck/config.py`, after the `UserAuditConfig` dataclass (around line 132 currently), add:

```python
@dataclass(frozen=True)
class CloudIntegrationConfig:
    """Connection settings for the InsightVM Cloud Integrations API (v4).

    Disabled-by-default; when enabled, the env var named in `api_key_env`
    must hold a valid Insight Platform API key (separate from the console
    key used for v3). The `cloud_drift` audit category self-skips when
    `enabled` is False or the env var is missing.
    """
    enabled: bool
    base_url: str
    api_key_env: str
    timeout_seconds: int
    max_retries: int
    parallel_pages: int


def _default_cloud_integration() -> CloudIntegrationConfig:
    return CloudIntegrationConfig(
        enabled=False,
        base_url="",
        api_key_env="R7_CLOUD_API_KEY",
        timeout_seconds=30,
        max_retries=3,
        parallel_pages=1,
    )
```

Add the validator function (place it adjacent to `_build_user_audit_config`):

```python
def _build_cloud_integration_config(data: dict | None) -> CloudIntegrationConfig:
    """Validator for the optional `cloud_integration:` block.

    Mirrors `_build_audit_config` semantics: missing block = defaults
    (disabled), unknown keys reject, type checks per field. When
    `enabled: true`, `base_url` becomes required and must be HTTPS.
    """
    if data is None:
        return _default_cloud_integration()
    _validate_dict_schema(
        data,
        expected={
            "enabled", "base_url", "api_key_env",
            "timeout_seconds", "max_retries", "parallel_pages",
        },
        required=set(),
        name="cloud_integration",
    )
    if not isinstance(data.get("enabled"), bool):
        raise ConfigError("cloud_integration.enabled: expected bool")
    enabled = data["enabled"]

    base_url = data.get("base_url", "")
    if enabled:
        if not isinstance(base_url, str) or not base_url:
            raise ConfigError(
                "cloud_integration.base_url: required when enabled is true"
            )
        if not base_url.startswith("https://"):
            raise ConfigError("cloud_integration.base_url must start with https://")
    elif not isinstance(base_url, str):
        raise ConfigError("cloud_integration.base_url: expected str")

    api_key_env = data.get("api_key_env", "R7_CLOUD_API_KEY")
    if not isinstance(api_key_env, str) or not api_key_env:
        raise ConfigError("cloud_integration.api_key_env: expected non-empty str")

    timeout_seconds = data.get("timeout_seconds", 30)
    _check_scalar("timeout_seconds", timeout_seconds, int, "cloud_integration")

    max_retries = data.get("max_retries", 3)
    _check_scalar("max_retries", max_retries, int, "cloud_integration")

    parallel_pages = data.get("parallel_pages", 1)
    _check_scalar("parallel_pages", parallel_pages, int, "cloud_integration")
    if not (1 <= parallel_pages <= 16):
        raise ConfigError(
            f"cloud_integration.parallel_pages must be in range [1, 16]; got {parallel_pages}"
        )

    return CloudIntegrationConfig(
        enabled=enabled,
        base_url=base_url,
        api_key_env=api_key_env,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        parallel_pages=parallel_pages,
    )
```

Extend `AppConfig` (around line 142):

```python
@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict
    audit: AuditConfig = field(default_factory=_default_audit)
    user_audit: UserAuditConfig = field(default_factory=_default_user_audit)
    cloud_integration: CloudIntegrationConfig = field(default_factory=_default_cloud_integration)
```

Extend `_build_app_config` (around line 540): add `"cloud_integration"` to `expected_root` and to the `optional` set (`expected_root - required_root`), and add a line before the final `return`:

```python
expected_root = {"rapid7", "report", "thresholds", "checks", "audit", "user_audit", "cloud_integration", "cloud_drift"}
# ...
required_root = expected_root - {"audit", "user_audit", "cloud_integration", "cloud_drift"}
# ...
cloud_integration = _build_cloud_integration_config(data.get("cloud_integration"))
return AppConfig(
    rapid7=rapid7,
    report=report,
    thresholds=thresholds,
    checks=checks,
    audit=audit,
    user_audit=user_audit,
    cloud_integration=cloud_integration,
)
```

(`cloud_drift` validator comes in Task 4 -- for now `_build_app_config` accepts it as a known root key but reads nothing; add a placeholder that raises if present until Task 4 lands. Easiest approach: include `"cloud_drift"` in `expected_root` only in Task 4 to avoid a half-step. Reverse the change here -- keep `expected_root` to just `+ "cloud_integration"` for now.)

**Corrected change for `_build_app_config`:**

```python
expected_root = {"rapid7", "report", "thresholds", "checks", "audit", "user_audit", "cloud_integration"}
# ...
required_root = expected_root - {"audit", "user_audit", "cloud_integration"}
# ...
cloud_integration = _build_cloud_integration_config(data.get("cloud_integration"))
return AppConfig(
    rapid7=rapid7,
    report=report,
    thresholds=thresholds,
    checks=checks,
    audit=audit,
    user_audit=user_audit,
    cloud_integration=cloud_integration,
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config_cloud_integration.py -v`
Expected: 7 passed.

Run the full existing config test suite to make sure nothing regressed:

Run: `pytest tests/test_config.py -v`
Expected: all existing tests pass (the new optional block doesn't change any required-key behavior).

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config_cloud_integration.py
git commit -m "feat(config): add optional cloud_integration block (disabled by default)"
```

---

## Task 4: CloudDriftConfig in config schema

**Files:**
- Modify: `src/rapid7_healthcheck/config.py`
- Test: `tests/test_config_cloud_drift.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_cloud_drift.py`:

```python
from __future__ import annotations

import pytest

from rapid7_healthcheck.config import (
    CloudDriftConfig,
    ConfigError,
    _build_cloud_drift_config,
)


def test_default_when_section_missing():
    cfg = _build_cloud_drift_config(None)
    assert isinstance(cfg, CloudDriftConfig)
    assert cfg.rules == {}


def test_full_block_parses_three_rules():
    cfg = _build_cloud_drift_config({
        "rules": {
            "cd.console_asset_count_drift": {
                "enabled": True,
                "severity": "warn",
                "tolerance_percent": 5,
            },
            "cd.scan_engine_cloud_registration": {
                "enabled": True,
                "severity": "warn",
                "last_seen_max_age_hours": 24,
                "ignore_engines": ["lab-engine"],
            },
            "cd.stale_assessment_cohort": {
                "enabled": True,
                "severity": "warn",
                "stale_after_days": 30,
                "max_stale_percent": 10,
                "max_stale_count": None,
            },
        },
    })
    assert set(cfg.rules.keys()) == {
        "cd.console_asset_count_drift",
        "cd.scan_engine_cloud_registration",
        "cd.stale_assessment_cohort",
    }
    drift = cfg.rules["cd.console_asset_count_drift"]
    assert drift.enabled is True
    assert drift.severity == "warn"
    assert drift.knobs["tolerance_percent"] == 5


def test_unknown_rule_id_rejected():
    with pytest.raises(ConfigError, match="unknown rule id"):
        _build_cloud_drift_config({
            "rules": {"cd.bogus": {"enabled": True, "severity": "warn"}},
        })


def test_invalid_severity_rejected():
    with pytest.raises(ConfigError, match="severity"):
        _build_cloud_drift_config({
            "rules": {
                "cd.console_asset_count_drift": {
                    "enabled": True, "severity": "critical",
                },
            },
        })


def test_unknown_top_level_key_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        _build_cloud_drift_config({"rules": {}, "wat": True})
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_config_cloud_drift.py -v`
Expected: ImportError on `CloudDriftConfig`.

- [ ] **Step 3: Add CloudDriftConfig + validator + valid-rule-id set**

In `src/rapid7_healthcheck/config.py`, near the existing `_VALID_USER_AUDIT_RULE_IDS` (around line 98), add:

```python
_VALID_CLOUD_DRIFT_RULE_IDS = {
    "cd.console_asset_count_drift",
    "cd.scan_engine_cloud_registration",
    "cd.stale_assessment_cohort",
}
```

After `UserAuditConfig` and `_default_user_audit`, add:

```python
@dataclass(frozen=True)
class CloudDriftConfig:
    """Rule-bearing config for the Cloud Drift audit category.

    Independent of `cloud_integration:` so users can author rule
    overrides before wiring the connection. The `CloudDriftAuditCheck`
    self-skips when `cloud_integration` is disabled regardless of what
    this block contains.
    """
    rules: dict  # str -> RuleConfig


def _default_cloud_drift() -> CloudDriftConfig:
    return CloudDriftConfig(rules={})
```

After `_build_user_audit_config`, add:

```python
def _build_cloud_drift_config(data: dict | None) -> CloudDriftConfig:
    """Validator for the optional `cloud_drift:` block.

    Mirrors `_build_user_audit_config` rule-validation logic against
    `_VALID_CLOUD_DRIFT_RULE_IDS`. Has no top-level `enabled`/`full_scan`/
    `sample_size` keys -- sampling does not apply to cloud-drift rules
    (they read aggregate counts) and the category-level enable lives in
    `checks.cloud_drift_audit` like every other check.
    """
    if data is None:
        return _default_cloud_drift()
    _validate_dict_schema(
        data,
        expected={"rules"},
        required=set(),
        name="cloud_drift",
    )
    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ConfigError("cloud_drift.rules: expected mapping")
    rules: dict[str, RuleConfig] = {}
    for rule_id, rule_body in raw_rules.items():
        if rule_id not in _VALID_CLOUD_DRIFT_RULE_IDS:
            raise ConfigError(f"cloud_drift.rules: unknown rule id '{rule_id}'")
        if not isinstance(rule_body, dict):
            raise ConfigError(f"cloud_drift.rules.{rule_id}: expected mapping")
        if not isinstance(rule_body.get("enabled"), bool):
            raise ConfigError(f"cloud_drift.rules.{rule_id}.enabled: expected bool")
        sev = rule_body.get("severity")
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(
                f"cloud_drift.rules.{rule_id}.severity: must be one of {sorted(_VALID_SEVERITIES)}"
            )
        knobs = {k: v for k, v in rule_body.items() if k not in ("enabled", "severity")}
        rules[rule_id] = RuleConfig(enabled=rule_body["enabled"], severity=sev, knobs=knobs)
    return CloudDriftConfig(rules=rules)
```

Extend `AppConfig`:

```python
@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict
    audit: AuditConfig = field(default_factory=_default_audit)
    user_audit: UserAuditConfig = field(default_factory=_default_user_audit)
    cloud_integration: CloudIntegrationConfig = field(default_factory=_default_cloud_integration)
    cloud_drift: CloudDriftConfig = field(default_factory=_default_cloud_drift)
```

Extend `_build_app_config`:

```python
expected_root = {"rapid7", "report", "thresholds", "checks", "audit", "user_audit", "cloud_integration", "cloud_drift"}
# ...
required_root = expected_root - {"audit", "user_audit", "cloud_integration", "cloud_drift"}
# ...

# Default-on for the cloud_drift_audit check, mirroring the audit/user_permission_audit pattern.
if "cloud_drift_audit" not in checks:
    checks = dict(checks)
    checks["cloud_drift_audit"] = True

audit = _build_audit_config(data.get("audit"))
user_audit = _build_user_audit_config(data.get("user_audit"))
cloud_integration = _build_cloud_integration_config(data.get("cloud_integration"))
cloud_drift = _build_cloud_drift_config(data.get("cloud_drift"))
return AppConfig(
    rapid7=rapid7,
    report=report,
    thresholds=thresholds,
    checks=checks,
    audit=audit,
    user_audit=user_audit,
    cloud_integration=cloud_integration,
    cloud_drift=cloud_drift,
)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_config_cloud_drift.py tests/test_config.py tests/test_config_cloud_integration.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config_cloud_drift.py
git commit -m "feat(config): add cloud_drift rule config block"
```

---

## Task 5: CloudSnapshot with lazy v3+v4 accessors

**Files:**
- Create: `src/rapid7_healthcheck/audit/cloud_drift/__init__.py` (skeleton -- orchestrator comes in Task 9, but the package needs to exist)
- Create: `src/rapid7_healthcheck/audit/cloud_drift/snapshot.py`
- Create: `src/rapid7_healthcheck/audit/cloud_drift/rules/__init__.py` (empty)
- Test: `tests/audit/cloud_drift/__init__.py` (empty), `tests/audit/cloud_drift/test_snapshot.py`

- [ ] **Step 1: Write the failing snapshot tests**

Create `tests/audit/cloud_drift/__init__.py` (empty).

Create `tests/audit/cloud_drift/test_snapshot.py`:

```python
from __future__ import annotations

from unittest.mock import MagicMock

from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot


def _v3_first_page(total: int) -> dict:
    return {
        "resources": [],
        "page": {"number": 0, "size": 1, "totalPages": 1 if total else 0, "totalResources": total},
    }


def _v4_assets_response(total: int) -> dict:
    return {
        "data": [],
        "metadata": {"number": 0, "size": 1, "totalPages": 1 if total else 0, "totalResources": total},
        "links": [],
    }


def test_cloud_assets_total_reads_metadata_total_resources():
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(42)
    v3 = MagicMock()
    snap = CloudSnapshot(v3_client=v3, cloud_client=v4)
    assert snap.cloud_assets_total() == 42
    v4.post_one.assert_called_once_with(
        "/v4/integration/assets",
        json_body={},
        params={"page": 0, "size": 1},
    )


def test_cloud_assets_total_is_cached():
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(7)
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)
    snap.cloud_assets_total()
    snap.cloud_assets_total()
    assert v4.post_one.call_count == 1


def test_console_assets_total_reads_v3_page_total_resources():
    v3 = MagicMock()
    v3.get.return_value = _v3_first_page(99)
    snap = CloudSnapshot(v3_client=v3, cloud_client=MagicMock())
    assert snap.console_assets_total() == 99
    v3.get.assert_called_once_with("/api/3/assets", params={"page": 0, "size": 1})


def test_cloud_assets_stale_uses_filter_dsl_with_iso_threshold():
    from datetime import datetime, timezone
    v4 = MagicMock()
    v4.post_one.return_value = _v4_assets_response(11)
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)

    threshold = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert snap.cloud_assets_stale(threshold) == 11
    body = v4.post_one.call_args.kwargs["json_body"]
    assert body == {
        "asset": "last_assessed_for_vulnerabilities < '2026-01-01T00:00:00Z'",
    }


def test_cloud_engines_paginates_get():
    v4 = MagicMock()
    v4.paginate.return_value = iter([
        {"id": "a", "name": "engine-a", "last_seen": "2026-05-07T00:00:00Z"},
        {"id": "b", "name": "engine-b", "last_seen": None},
    ])
    snap = CloudSnapshot(v3_client=MagicMock(), cloud_client=v4)
    engines = snap.cloud_engines()
    assert len(engines) == 2
    assert engines[0]["name"] == "engine-a"
    v4.paginate.assert_called_once_with("/v4/integration/scan/engine")


def test_console_engines_returns_v3_resources_list():
    v3 = MagicMock()
    v3.get.return_value = {"resources": [{"id": 1, "name": "console-a"}]}
    snap = CloudSnapshot(v3_client=v3, cloud_client=MagicMock())
    engines = snap.console_engines()
    assert engines == [{"id": 1, "name": "console-a"}]
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/audit/cloud_drift/test_snapshot.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement CloudSnapshot**

Create `src/rapid7_healthcheck/audit/cloud_drift/__init__.py` with a minimal package docstring (orchestrator + side-effect imports come in Task 9):

```python
"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default -- the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``.
"""

from __future__ import annotations
```

Create `src/rapid7_healthcheck/audit/cloud_drift/rules/__init__.py` (empty).

Create `src/rapid7_healthcheck/audit/cloud_drift/snapshot.py`:

```python
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _format_threshold(dt: datetime) -> str:
    """Format a datetime as ``YYYY-MM-DDTHH:MM:SSZ`` for the v4 filter DSL.

    Naive datetimes are interpreted as UTC. Aware datetimes in non-UTC
    zones are converted to UTC. Microseconds are dropped -- v4's filter
    parser accepts millisecond precision but the rules don't need it.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class CloudSnapshot:
    """Lazy data container for cloud-drift rules.

    Holds *both* the v3 client (``Rapid7Client``) and the v4 client
    (``CloudClient``) so rules can ask cross-API reconciliation
    questions. Each accessor caches its first result.

    Sampling does not apply: every cloud-drift rule reads aggregate
    counts (``totalResources``) or small per-engine lookups, so
    ``audit.sample_size`` and ``full_scan`` are deliberately ignored.
    """

    def __init__(self, *, v3_client: Any, cloud_client: Any) -> None:
        self._v3 = v3_client
        self._cloud = cloud_client
        self._cloud_assets_total: int | None = None
        self._console_assets_total: int | None = None
        self._cloud_engines: list[dict] | None = None
        self._console_engines: list[dict] | None = None

    def cloud_assets_total(self) -> int:
        if self._cloud_assets_total is None:
            body = self._cloud.post_one(
                "/v4/integration/assets",
                json_body={},
                params={"page": 0, "size": 1},
            )
            self._cloud_assets_total = int(body.get("metadata", {}).get("totalResources", 0))
        return self._cloud_assets_total

    def console_assets_total(self) -> int:
        if self._console_assets_total is None:
            body = self._v3.get("/api/3/assets", params={"page": 0, "size": 1})
            self._console_assets_total = int(body.get("page", {}).get("totalResources", 0))
        return self._console_assets_total

    def cloud_assets_stale(self, since: datetime) -> int:
        """Count of cloud assets where last_assessed_for_vulnerabilities < since."""
        body = self._cloud.post_one(
            "/v4/integration/assets",
            json_body={
                "asset": f"last_assessed_for_vulnerabilities < '{_format_threshold(since)}'",
            },
            params={"page": 0, "size": 1},
        )
        return int(body.get("metadata", {}).get("totalResources", 0))

    def cloud_engines(self) -> list[dict]:
        if self._cloud_engines is None:
            self._cloud_engines = list(self._cloud.paginate("/v4/integration/scan/engine"))
        return self._cloud_engines

    def console_engines(self) -> list[dict]:
        if self._console_engines is None:
            body = self._v3.get("/api/3/scan_engines")
            self._console_engines = list(body.get("resources", []))
        return self._console_engines
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/audit/cloud_drift/test_snapshot.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/audit/cloud_drift/__init__.py src/rapid7_healthcheck/audit/cloud_drift/snapshot.py src/rapid7_healthcheck/audit/cloud_drift/rules/__init__.py tests/audit/cloud_drift/__init__.py tests/audit/cloud_drift/test_snapshot.py
git commit -m "feat(cloud-drift): CloudSnapshot with lazy v3+v4 accessors"
```

---

## Task 6: Rule cd.console_asset_count_drift

**Files:**
- Create: `src/rapid7_healthcheck/audit/cloud_drift/rules/console_asset_count_drift.py`
- Create: `tests/audit/cloud_drift/rules/__init__.py` (empty)
- Test: `tests/audit/cloud_drift/rules/test_console_asset_count_drift.py`

The decorator `@register_cloud_rule` does not exist yet (it lands in Task 9 with the orchestrator). To keep this task self-contained, the rule file imports the decorator from `audit.cloud_drift` and the file `audit/cloud_drift/__init__.py` must export it. Add the decorator to the package now (without the orchestrator) so this task can register cleanly. The orchestrator in Task 9 reuses the same registry.

- [ ] **Step 1: Add the registry + decorator to `audit/cloud_drift/__init__.py`**

Replace the placeholder `audit/cloud_drift/__init__.py` content with:

```python
"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default -- the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``.
"""

from __future__ import annotations

from rapid7_healthcheck.audit import Rule

_CLOUD_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_cloud_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a cloud-drift rule. Mirror of
    ``audit.register`` and ``audit.user_permission.register_user_rule``
    but for the third audit category.
    """
    _CLOUD_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls
```

(`CloudDriftAuditCheck` joins this file in Task 9, along with the side-effect imports of all three rule modules.)

- [ ] **Step 2: Write the failing rule tests**

Create `tests/audit/cloud_drift/rules/__init__.py` (empty).

Create `tests/audit/cloud_drift/rules/test_console_asset_count_drift.py`:

```python
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift.rules.console_asset_count_drift import (
    ConsoleAssetCountDriftRule,
)


def _snapshot(*, console_total: int, cloud_total: int) -> MagicMock:
    s = MagicMock()
    s.console_assets_total.return_value = console_total
    s.cloud_assets_total.return_value = cloud_total
    return s


def test_within_tolerance_passes():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1020)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "pass"
    assert result.findings == []
    assert result.summary["console_total"] == 1000
    assert result.summary["cloud_total"] == 1020


def test_outside_tolerance_warns():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "drift" in result.findings[0].message.lower()


def test_console_zero_cloud_nonzero_fails():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=0, cloud_total=500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "fail"
    assert result.findings[0].severity == "fail"
    assert "sync" in result.findings[0].message.lower() or "broken" in result.findings[0].message.lower()


def test_cloud_zero_console_nonzero_fails():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=500, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "fail"
    assert result.findings[0].severity == "fail"


def test_both_zero_passes():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=0, cloud_total=0)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    assert result.status == "pass"


def test_default_tolerance_is_5_percent():
    rule = ConsoleAssetCountDriftRule()
    # 4% diff -> pass; 6% diff -> warn (with default tolerance of 5)
    snap_pass = _snapshot(console_total=1000, cloud_total=1040)
    snap_warn = _snapshot(console_total=1000, cloud_total=1060)
    assert rule.run(snap_pass, "warn", False, 500, {}).status == "pass"
    assert rule.run(snap_warn, "warn", False, 500, {}).status == "warn"


def test_summary_includes_drift_percent():
    rule = ConsoleAssetCountDriftRule()
    snap = _snapshot(console_total=1000, cloud_total=1500)
    result = rule.run(snap, "warn", False, 500, {"tolerance_percent": 5})
    # 500 / 1500 = 33.33%
    assert pytest.approx(result.summary["drift_percent"], abs=0.01) == 33.33


def test_rule_is_registered():
    from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY
    assert "cd.console_asset_count_drift" in _CLOUD_RULE_REGISTRY
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_console_asset_count_drift.py -v`
Expected: ImportError on the rule module.

- [ ] **Step 4: Implement the rule**

Create `src/rapid7_healthcheck/audit/cloud_drift/rules/console_asset_count_drift.py`:

```python
from __future__ import annotations

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_TOLERANCE_PERCENT = 5


@register_cloud_rule
class ConsoleAssetCountDriftRule:
    rule_id = "cd.console_asset_count_drift"
    rule_name = "Console / Cloud Asset Count Drift"
    description = (
        "Compares the asset count visible to the on-prem Security Console "
        "(/api/3/assets) against the count visible to the Insight Platform "
        "Cloud Integrations API (/v4/integration/assets). Healthy "
        "console-to-cloud sync keeps these within a small percentage; "
        "large divergence usually indicates broken connector configuration. "
        "If exactly one side reports 0 assets and the other reports any "
        "non-zero count, the finding is upgraded to fail -- that is a "
        "broken sync, not a skew."
    )
    default_severity = "warn"
    expensive = False
    sources: list[str] = []  # populated during implementation, see plan §"Source URLs"

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        tolerance = float(rule_config.get("tolerance_percent", _DEFAULT_TOLERANCE_PERCENT))
        console_total = snapshot.console_assets_total()
        cloud_total = snapshot.cloud_assets_total()

        findings: list[Finding] = []
        drift_percent = 0.0

        if console_total == 0 and cloud_total == 0:
            # No assets on either side -- vacuously consistent.
            pass
        elif console_total == 0 or cloud_total == 0:
            findings.append(Finding(
                severity="fail",
                message=(
                    f"Asset-count sync is broken: console reports "
                    f"{console_total} assets, cloud reports {cloud_total}. "
                    f"Verify the InsightVM data collector connection."
                ),
                details={
                    "console_total": console_total,
                    "cloud_total": cloud_total,
                    "broken_sync": True,
                },
            ))
        else:
            denom = max(console_total, cloud_total)
            drift_percent = abs(console_total - cloud_total) * 100.0 / denom
            if drift_percent > tolerance:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Console/cloud asset-count drift {drift_percent:.2f}% "
                        f"exceeds tolerance {tolerance:.2f}% "
                        f"(console={console_total}, cloud={cloud_total})."
                    ),
                    details={
                        "console_total": console_total,
                        "cloud_total": cloud_total,
                        "drift_percent": drift_percent,
                        "tolerance_percent": tolerance,
                    },
                ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "console_total": console_total,
                "cloud_total": cloud_total,
                "drift_percent": round(drift_percent, 2),
                "tolerance_percent": tolerance,
            },
            sources=list(self.sources),
        )
```

Note on `sources`: the spec defers picking real Rapid7 doc URLs to implementation (Open Question 4). Land the rule with `sources = []` and add a backlog entry in Task 13 to fill the URLs once Rapid7's cloud-integration docs page can be confirmed.

- [ ] **Step 5: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_console_asset_count_drift.py -v`
Expected: 8 passed.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/audit/cloud_drift/__init__.py src/rapid7_healthcheck/audit/cloud_drift/rules/console_asset_count_drift.py tests/audit/cloud_drift/rules/__init__.py tests/audit/cloud_drift/rules/test_console_asset_count_drift.py
git commit -m "feat(cloud-drift): add cd.console_asset_count_drift rule"
```

---

## Task 7: Rule cd.scan_engine_cloud_registration

**Files:**
- Create: `src/rapid7_healthcheck/audit/cloud_drift/rules/scan_engine_cloud_registration.py`
- Test: `tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from rapid7_healthcheck.audit.cloud_drift.rules.scan_engine_cloud_registration import (
    ScanEngineCloudRegistrationRule,
)


def _now_iso(offset_hours: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=offset_hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _snapshot(console_engines: list[dict], cloud_engines: list[dict]) -> MagicMock:
    s = MagicMock()
    s.console_engines.return_value = console_engines
    s.cloud_engines.return_value = cloud_engines
    return s


def test_all_engines_present_and_recent_passes():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(1)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "pass"


def test_engine_missing_from_cloud_fails():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "engine-b"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "fail"
    fail = [f for f in result.findings if f.severity == "fail"]
    assert len(fail) == 1
    assert "engine-b" in fail[0].message


def test_engine_present_but_stale_warns():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(48)}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "warn"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "stale" in result.findings[0].message.lower() or "last_seen" in result.findings[0].message


def test_ignored_engine_skipped():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}, {"id": 2, "name": "lab-only"}],
        cloud_engines=[{"name": "engine-a", "last_seen": _now_iso(0)}],
    )
    result = rule.run(snap, "warn", False, 500, {"ignore_engines": ["lab-only"]})
    assert result.status == "pass"


def test_cloud_engine_without_last_seen_treated_as_stale():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[{"id": 1, "name": "engine-a"}],
        cloud_engines=[{"name": "engine-a", "last_seen": None}],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.status == "warn"


def test_summary_counts():
    rule = ScanEngineCloudRegistrationRule()
    snap = _snapshot(
        console_engines=[
            {"id": 1, "name": "engine-a"},
            {"id": 2, "name": "engine-b"},
            {"id": 3, "name": "engine-c"},
        ],
        cloud_engines=[
            {"name": "engine-a", "last_seen": _now_iso(0)},
            {"name": "engine-b", "last_seen": _now_iso(48)},
        ],
    )
    result = rule.run(snap, "warn", False, 500, {"last_seen_max_age_hours": 24})
    assert result.summary["console_engines"] == 3
    assert result.summary["cloud_engines"] == 2
    assert result.summary["missing_from_cloud"] == 1
    assert result.summary["stale_in_cloud"] == 1
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement the rule**

Create `src/rapid7_healthcheck/audit/cloud_drift/rules/scan_engine_cloud_registration.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_LAST_SEEN_MAX_AGE_HOURS = 24


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    # v4 formats are "YYYY-MM-DDTHH:MM:SSZ" or "...Z"-suffixed with millis.
    try:
        # fromisoformat tolerates +00:00 but not "Z" before Python 3.11; the
        # project targets 3.11+ so the "Z" replace below covers both forms.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@register_cloud_rule
class ScanEngineCloudRegistrationRule:
    rule_id = "cd.scan_engine_cloud_registration"
    rule_name = "Scan Engine Cloud Registration"
    description = (
        "Cross-references the on-prem console scan engine list "
        "(/api/3/scan_engines) with the cloud-registered engines "
        "(/v4/integration/scan/engine). Engines that exist in the "
        "console but never registered with Insight Platform cannot "
        "service cloud-driven workflows (Insight Agent assessment, "
        "Cloud Risk Insights). Engines registered but with a stale "
        "last_seen indicate the cloud-platform connection is degraded. "
        "Match key is engine name; configure ignore_engines to exempt "
        "deliberately on-prem-only scanners."
    )
    default_severity = "warn"
    expensive = False
    sources: list[str] = []  # filled during implementation; see plan §"Source URLs"

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        max_age_hours = int(rule_config.get(
            "last_seen_max_age_hours", _DEFAULT_LAST_SEEN_MAX_AGE_HOURS,
        ))
        ignore = set(rule_config.get("ignore_engines", []) or [])

        console_engines = snapshot.console_engines()
        cloud_engines = snapshot.cloud_engines()
        cloud_by_name = {e.get("name"): e for e in cloud_engines if e.get("name")}

        threshold = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        findings: list[Finding] = []
        missing_from_cloud = 0
        stale_in_cloud = 0

        for engine in console_engines:
            name = engine.get("name")
            if not name or name in ignore:
                continue
            cloud = cloud_by_name.get(name)
            if cloud is None:
                missing_from_cloud += 1
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Console scan engine '{name}' is not registered with "
                        f"Insight Platform. It cannot service cloud-driven "
                        f"workflows (agent assessment, Cloud Risk Insights). "
                        f"Register it via Security Console → Administration → "
                        f"Scan Engines, or add to ignore_engines if intentional."
                    ),
                    details={
                        "engine_name": name,
                        "console_engine_id": engine.get("id"),
                        "missing_from_cloud": True,
                    },
                ))
                continue

            last_seen = _parse_iso(cloud.get("last_seen"))
            if last_seen is None or last_seen < threshold:
                stale_in_cloud += 1
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"Cloud-registered engine '{name}' has stale last_seen "
                        f"({cloud.get('last_seen') or 'never'}); threshold is "
                        f"{max_age_hours}h. The Insight Platform connection is "
                        f"likely down or the engine is offline."
                    ),
                    details={
                        "engine_name": name,
                        "console_engine_id": engine.get("id"),
                        "last_seen": cloud.get("last_seen"),
                        "max_age_hours": max_age_hours,
                    },
                ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "console_engines": len(console_engines),
                "cloud_engines": len(cloud_engines),
                "missing_from_cloud": missing_from_cloud,
                "stale_in_cloud": stale_in_cloud,
                "max_age_hours": max_age_hours,
                "ignore_engines": sorted(ignore),
            },
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/audit/cloud_drift/rules/scan_engine_cloud_registration.py tests/audit/cloud_drift/rules/test_scan_engine_cloud_registration.py
git commit -m "feat(cloud-drift): add cd.scan_engine_cloud_registration rule"
```

---

## Task 8: Rule cd.stale_assessment_cohort

**Files:**
- Create: `src/rapid7_healthcheck/audit/cloud_drift/rules/stale_assessment_cohort.py`
- Test: `tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py`:

```python
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift.rules.stale_assessment_cohort import (
    StaleAssessmentCohortRule,
)


def _snapshot(*, total: int, stale: int) -> MagicMock:
    s = MagicMock()
    s.cloud_assets_total.return_value = total
    s.cloud_assets_stale.return_value = stale
    return s


def test_no_stale_passes():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=0)
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "pass"


def test_below_percent_threshold_passes():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=50)  # 5%
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "pass"


def test_above_percent_threshold_warns():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=200)  # 20%
    result = rule.run(snap, "warn", False, 500, {"stale_after_days": 30, "max_stale_percent": 10})
    assert result.status == "warn"
    assert "20" in result.findings[0].message  # the percent shows up in the message


def test_above_count_threshold_warns():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=10000, stale=600)  # 6% -- under default percent threshold
    result = rule.run(
        snap, "warn", False, 500,
        {"stale_after_days": 30, "max_stale_percent": 10, "max_stale_count": 500},
    )
    assert result.status == "warn"


def test_max_stale_count_null_ignored():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=10000, stale=200)  # 2%
    result = rule.run(
        snap, "warn", False, 500,
        {"stale_after_days": 30, "max_stale_percent": 10, "max_stale_count": None},
    )
    assert result.status == "pass"


def test_total_zero_passes_without_division_error():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=0, stale=0)
    result = rule.run(snap, "warn", False, 500, {})
    assert result.status == "pass"
    assert result.summary["stale_percent"] == 0.0


def test_summary_includes_stale_percent():
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=1000, stale=250)
    result = rule.run(snap, "warn", False, 500, {})
    assert pytest.approx(result.summary["stale_percent"]) == 25.0
    assert result.summary["stale_count"] == 250
    assert result.summary["total_count"] == 1000


def test_threshold_datetime_passed_to_snapshot():
    """stale_after_days must be converted to a UTC datetime threshold."""
    rule = StaleAssessmentCohortRule()
    snap = _snapshot(total=100, stale=0)
    rule.run(snap, "warn", False, 500, {"stale_after_days": 30})
    args, kwargs = snap.cloud_assets_stale.call_args
    threshold = args[0] if args else kwargs["since"]
    # threshold should be ~30 days ago, not "today" -- sanity check the math
    from datetime import datetime, timezone, timedelta
    expected = datetime.now(timezone.utc) - timedelta(days=30)
    assert abs((threshold - expected).total_seconds()) < 60
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement the rule**

Create `src/rapid7_healthcheck/audit/cloud_drift/rules/stale_assessment_cohort.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.audit import RuleResult
from rapid7_healthcheck.audit.cloud_drift import register_cloud_rule
from rapid7_healthcheck.checks import Finding


_DEFAULT_STALE_AFTER_DAYS = 30
_DEFAULT_MAX_STALE_PERCENT = 10.0


@register_cloud_rule
class StaleAssessmentCohortRule:
    rule_id = "cd.stale_assessment_cohort"
    rule_name = "Stale Assessment Cohort"
    description = (
        "Counts cloud-visible assets whose last_assessed_for_vulnerabilities "
        "is older than stale_after_days, using the v4 search-criteria DSL "
        "for filter pushdown (one query, no full pagination). Flags when "
        "the cohort exceeds either max_stale_percent of total cloud assets "
        "or max_stale_count (whichever is set). A growing stale cohort "
        "usually indicates scan windows are too narrow, scan engines are "
        "overloaded, or sites are missing from the active scan rotation."
    )
    default_severity = "warn"
    expensive = False
    sources: list[str] = []  # filled during implementation; see plan §"Source URLs"

    def run(self, snapshot, severity, full_scan, sample_size, rule_config) -> RuleResult:
        stale_after_days = int(rule_config.get("stale_after_days", _DEFAULT_STALE_AFTER_DAYS))
        max_stale_percent = float(rule_config.get("max_stale_percent", _DEFAULT_MAX_STALE_PERCENT))
        max_stale_count = rule_config.get("max_stale_count", None)

        threshold = datetime.now(timezone.utc) - timedelta(days=stale_after_days)
        stale_count = snapshot.cloud_assets_stale(threshold)
        total_count = snapshot.cloud_assets_total()

        stale_percent = (stale_count * 100.0 / total_count) if total_count > 0 else 0.0

        findings: list[Finding] = []
        if total_count > 0:
            triggered_by: list[str] = []
            if stale_percent > max_stale_percent:
                triggered_by.append(
                    f"{stale_percent:.2f}% > max_stale_percent={max_stale_percent:.2f}%"
                )
            if max_stale_count is not None and stale_count > int(max_stale_count):
                triggered_by.append(
                    f"{stale_count} > max_stale_count={int(max_stale_count)}"
                )
            if triggered_by:
                findings.append(Finding(
                    severity=severity,
                    message=(
                        f"{stale_count} of {total_count} cloud assets "
                        f"({stale_percent:.2f}%) have not been assessed for "
                        f"vulnerabilities in {stale_after_days} days "
                        f"({'; '.join(triggered_by)}). Verify scan rotation "
                        f"and engine throughput."
                    ),
                    details={
                        "stale_count": stale_count,
                        "total_count": total_count,
                        "stale_percent": stale_percent,
                        "stale_after_days": stale_after_days,
                        "max_stale_percent": max_stale_percent,
                        "max_stale_count": max_stale_count,
                    },
                ))

        if any(f.severity == "fail" for f in findings):
            status = "fail"
        elif any(f.severity == "warn" for f in findings):
            status = "warn"
        else:
            status = "pass"

        return RuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=self.description,
            severity=severity,
            status=status,
            findings=findings,
            summary={
                "stale_count": stale_count,
                "total_count": total_count,
                "stale_percent": round(stale_percent, 2),
                "stale_after_days": stale_after_days,
                "max_stale_percent": max_stale_percent,
                "max_stale_count": max_stale_count,
            },
            sources=list(self.sources),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/audit/cloud_drift/rules/stale_assessment_cohort.py tests/audit/cloud_drift/rules/test_stale_assessment_cohort.py
git commit -m "feat(cloud-drift): add cd.stale_assessment_cohort rule"
```

---

## Task 9: CloudDriftAuditCheck orchestrator

**Files:**
- Modify: `src/rapid7_healthcheck/audit/cloud_drift/__init__.py`
- Test: `tests/audit/cloud_drift/test_orchestrator.py`

- [ ] **Step 1: Write the failing orchestrator tests**

Create `tests/audit/cloud_drift/test_orchestrator.py`:

```python
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rapid7_healthcheck.audit.cloud_drift import CloudDriftAuditCheck
from rapid7_healthcheck.config import (
    AppConfig,
    CloudDriftConfig,
    CloudIntegrationConfig,
    Rapid7Config,
    ReportConfig,
    RuleConfig,
    Thresholds,
    AssetCoverageThresholds,
    DataQualityThresholds,
    ScanActivityThresholds,
    ScanEngineThresholds,
)


def _minimal_thresholds() -> Thresholds:
    return Thresholds(
        scan_engines=ScanEngineThresholds(last_contact_warn_hours=4, last_contact_fail_hours=24),
        scan_activity=ScanActivityThresholds(recent_window_days=14, stuck_scan_hours=24, site_no_scan_days=30),
        asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=True, never_scanned_days=90),
        data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=True),
    )


def _config(*, cloud_enabled: bool, rules_enabled: bool = True) -> AppConfig:
    return AppConfig(
        rapid7=Rapid7Config(
            base_url="https://console.example/",
            verify_tls=True,
            request_timeout_seconds=30,
            max_retries=3,
        ),
        report=ReportConfig(output_dir="reports", filename_pattern="r-{timestamp}.html", title="t"),
        thresholds=_minimal_thresholds(),
        checks={"cloud_drift_audit": True},
        cloud_integration=CloudIntegrationConfig(
            enabled=cloud_enabled,
            base_url="https://us.api.insight.rapid7.com/vm/" if cloud_enabled else "",
            api_key_env="R7_CLOUD_API_KEY",
            timeout_seconds=30,
            max_retries=3,
            parallel_pages=1,
        ),
        cloud_drift=CloudDriftConfig(rules={
            "cd.console_asset_count_drift": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
            "cd.scan_engine_cloud_registration": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
            "cd.stale_assessment_cohort": RuleConfig(enabled=rules_enabled, severity="warn", knobs={}),
        }),
    )


def test_skipped_when_cloud_integration_disabled():
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=False)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=None)
    assert result.status == "skipped"
    assert "cloud_integration" in result.summary["reason"]
    assert result.rule_results == []


def test_skipped_when_cloud_client_is_none_even_if_enabled():
    """Defense in depth: orchestrator never builds a snapshot without both clients."""
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=None)
    assert result.status == "skipped"


def test_runs_three_rules_when_enabled(monkeypatch):
    from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot

    # Stub each accessor to return safe values so all three rules pass.
    monkeypatch.setattr(CloudSnapshot, "console_assets_total", lambda self: 1000)
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_total", lambda self: 1000)
    monkeypatch.setattr(CloudSnapshot, "console_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_stale", lambda self, since: 0)

    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    assert result.status == "pass"
    assert result.rule_results is not None
    assert len(result.rule_results) == 3
    assert {r.rule_id for r in result.rule_results} == {
        "cd.console_asset_count_drift",
        "cd.scan_engine_cloud_registration",
        "cd.stale_assessment_cohort",
    }


def test_disabled_rules_appear_as_skipped(monkeypatch):
    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True, rules_enabled=False)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    assert result.status == "pass"  # all skipped → pass
    assert all(r.status == "skipped" for r in result.rule_results)


def test_rule_exception_isolated(monkeypatch):
    from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot
    monkeypatch.setattr(CloudSnapshot, "console_assets_total", lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_total", lambda self: 0)
    monkeypatch.setattr(CloudSnapshot, "console_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_engines", lambda self: [])
    monkeypatch.setattr(CloudSnapshot, "cloud_assets_stale", lambda self, since: 0)

    check = CloudDriftAuditCheck()
    cfg = _config(cloud_enabled=True)
    result = check.run(client=MagicMock(), config=cfg, cloud_client=MagicMock())
    # The drift rule errors; the other two still run.
    drift = next(r for r in result.rule_results if r.rule_id == "cd.console_asset_count_drift")
    assert drift.status == "error"
    assert "boom" in drift.error
    others = [r for r in result.rule_results if r.rule_id != "cd.console_asset_count_drift"]
    assert all(r.status == "pass" for r in others)
    # Whole check rolls up to fail because one rule errored.
    assert result.status == "fail"
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/audit/cloud_drift/test_orchestrator.py -v`
Expected: ImportError on `CloudDriftAuditCheck`.

- [ ] **Step 3: Implement the orchestrator**

Replace `src/rapid7_healthcheck/audit/cloud_drift/__init__.py` with the full version (registry + decorator from Task 6 plus orchestrator and side-effect imports):

```python
"""Cloud Drift audit category.

Sibling to ``rapid7_healthcheck.audit`` (Configuration Audit) and
``rapid7_healthcheck.audit.user_permission`` (User & Permission Audit).
Reconciles the on-prem Security Console (v3) against the InsightVM
Cloud Integrations API (v4).

Disabled by default -- the entire category self-skips when the
``cloud_integration`` config block is absent or has ``enabled: false``,
or when the cloud client could not be constructed (e.g. missing key).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rapid7_healthcheck.audit import (
    Rule,
    RuleResult,
    _extract_diagnostics,
    _flatten_findings,
    _rollup_audit_status,
)
from rapid7_healthcheck.audit.cloud_drift.snapshot import CloudSnapshot
from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.config import AppConfig

logger = logging.getLogger(__name__)


_CLOUD_RULE_REGISTRY: dict[str, type[Rule]] = {}


def register_cloud_rule(rule_cls: type[Rule]) -> type[Rule]:
    """Decorator: registers a cloud-drift rule. Mirror of
    ``audit.register`` and ``audit.user_permission.register_user_rule``
    but for the third audit category.
    """
    _CLOUD_RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    return rule_cls


class CloudDriftAuditCheck:
    name = "Cloud Drift Audit"
    description = (
        "Reconciles the on-prem Security Console with the InsightVM "
        "Cloud Integrations API (v4). Requires Insight Platform "
        "credentials in addition to the console API key; the entire "
        "category self-skips when cloud_integration is not configured."
    )

    def run(
        self,
        client: Any,
        config: AppConfig,
        progress=None,
        *,
        cloud_client: Any = None,
    ) -> CheckResult:
        start = time.monotonic()

        if not config.cloud_integration.enabled or cloud_client is None:
            return CheckResult(
                name=self.name,
                description=self.description,
                status="skipped",
                findings=[Finding(
                    severity="info",
                    message=(
                        "Cloud Drift audit skipped: cloud_integration is "
                        "disabled or the Insight Platform API key is not "
                        "configured. Set cloud_integration.enabled=true and "
                        "populate the env var named in cloud_integration."
                        "api_key_env to enable."
                    ),
                    details={"reason": "cloud_integration disabled or cloud_client unavailable"},
                )],
                summary={"reason": "cloud_integration disabled or cloud_client unavailable"},
                duration_ms=int((time.monotonic() - start) * 1000),
                rule_results=[],
            )

        snapshot = CloudSnapshot(v3_client=client, cloud_client=cloud_client)

        rule_results: list[RuleResult] = []
        total_rules = len(_CLOUD_RULE_REGISTRY)
        for rule_idx, (rule_id, rule_cls) in enumerate(_CLOUD_RULE_REGISTRY.items(), start=1):
            rule_cfg = config.cloud_drift.rules.get(rule_id)
            if rule_cfg is None or not rule_cfg.enabled:
                rule_results.append(RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_cls.rule_name,
                    description=rule_cls.description,
                    severity="info",
                    status="skipped",
                    sources=list(rule_cls.sources),
                ))
                if progress is not None:
                    skipped_label = f"cloud-drift: {rule_id} (skipped)"
                    progress.step(rule_idx, total_rules, skipped_label)
                    progress.done(rule_idx, total_rules, skipped_label, duration_ms=0)
                continue
            label = f"cloud-drift: {rule_id}"
            if progress is not None:
                progress.step(rule_idx, total_rules, label)
            rule_start = time.monotonic()
            try:
                try:
                    # full_scan / sample_size are passed for protocol compatibility
                    # but cloud-drift rules ignore them (see CloudSnapshot docstring).
                    result = rule_cls().run(
                        snapshot,
                        rule_cfg.severity,
                        False,
                        500,
                        rule_cfg.knobs,
                    )
                    result.duration_ms = int((time.monotonic() - rule_start) * 1000)
                    rule_results.append(result)
                except Exception as e:
                    logger.exception("cloud-drift rule %s raised", rule_id)
                    error_path, error_status_code = _extract_diagnostics(e)
                    rule_results.append(RuleResult(
                        rule_id=rule_id,
                        rule_name=rule_cls.rule_name,
                        description=rule_cls.description,
                        severity=rule_cfg.severity,
                        status="error",
                        sources=list(rule_cls.sources),
                        error=str(e),
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                        error_path=error_path,
                        error_status_code=error_status_code,
                    ))
            finally:
                if progress is not None:
                    progress.done(
                        rule_idx, total_rules, label,
                        duration_ms=int((time.monotonic() - rule_start) * 1000),
                    )

        return CheckResult(
            name=self.name,
            description=self.description,
            status=_rollup_audit_status(rule_results),
            findings=_flatten_findings(rule_results),
            summary={
                "rules_total": len(rule_results),
                "rules_pass": sum(1 for r in rule_results if r.status == "pass"),
                "rules_warn": sum(1 for r in rule_results if r.status == "warn"),
                "rules_fail": sum(1 for r in rule_results if r.status == "fail"),
                "rules_error": sum(1 for r in rule_results if r.status == "error"),
                "rules_skipped": sum(1 for r in rule_results if r.status == "skipped"),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
            rule_results=rule_results,
        )


# Side-effect imports: register all 3 cloud-drift rules at package-import time.
# Adding a new rule = one new file under `audit/cloud_drift/rules/` + one line here.
from rapid7_healthcheck.audit.cloud_drift.rules import (  # noqa: E402,F401
    console_asset_count_drift,
    scan_engine_cloud_registration,
    stale_assessment_cohort,
)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/audit/cloud_drift -v`
Expected: all cloud-drift tests pass (snapshot, three rules, orchestrator).

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/audit/cloud_drift/__init__.py tests/audit/cloud_drift/test_orchestrator.py
git commit -m "feat(cloud-drift): orchestrator with register_cloud_rule + skipped-when-disabled"
```

---

## Task 10: Wire CloudDriftAuditCheck into __main__.py

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py`
- Test: `tests/test_main_cloud_wiring.py`

The orchestrator's `run` signature accepts an optional `cloud_client` keyword argument. The dispatcher in `_run_checks` currently dispatches `configuration_audit` and `user_permission_audit` without `cloud_client`; this task adds a third branch.

- [ ] **Step 1: Write the failing wiring tests**

Create `tests/test_main_cloud_wiring.py`:

```python
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from rapid7_healthcheck.__main__ import _build_cloud_client_or_none
from rapid7_healthcheck.cloud_client import CloudClient
from rapid7_healthcheck.config import CloudIntegrationConfig


def _ci(enabled: bool, api_key_env: str = "R7_CLOUD_API_KEY") -> CloudIntegrationConfig:
    return CloudIntegrationConfig(
        enabled=enabled,
        base_url="https://us.api.insight.rapid7.com/vm/" if enabled else "",
        api_key_env=api_key_env,
        timeout_seconds=30,
        max_retries=3,
        parallel_pages=1,
    )


def test_disabled_returns_none(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    client, error = _build_cloud_client_or_none(_ci(enabled=False))
    assert client is None
    assert error is None


def test_enabled_with_key_returns_client(monkeypatch):
    monkeypatch.setenv("R7_CLOUD_API_KEY", "secret")
    client, error = _build_cloud_client_or_none(_ci(enabled=True))
    assert isinstance(client, CloudClient)
    assert error is None


def test_enabled_without_key_returns_error(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    client, error = _build_cloud_client_or_none(_ci(enabled=True))
    assert client is None
    assert error is not None
    assert "R7_CLOUD_API_KEY" in error


def test_enabled_with_custom_env_var_name(monkeypatch):
    monkeypatch.delenv("R7_CLOUD_API_KEY", raising=False)
    monkeypatch.setenv("MY_CUSTOM_KEY", "x")
    client, error = _build_cloud_client_or_none(_ci(enabled=True, api_key_env="MY_CUSTOM_KEY"))
    assert isinstance(client, CloudClient)
    assert error is None
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_main_cloud_wiring.py -v`
Expected: ImportError on `_build_cloud_client_or_none`.

- [ ] **Step 3: Add the helper + register the orchestrator + thread cloud_client through dispatch**

In `src/rapid7_healthcheck/__main__.py`:

Add the import after the existing audit imports (around line 18):

```python
from rapid7_healthcheck.audit.cloud_drift import CloudDriftAuditCheck
from rapid7_healthcheck.cloud_client import CloudClient
```

Extend `_REGISTRY` (around line 43):

```python
_REGISTRY: dict[str, type[Check]] = {
    "scan_engines": ScanEnginesCheck,
    "scan_activity": ScanActivityCheck,
    "asset_coverage": AssetCoverageCheck,
    "data_quality": DataQualityCheck,
    "configuration_audit": ConfigurationAuditCheck,
    "user_permission_audit": UserPermissionAuditCheck,
    "cloud_drift_audit": CloudDriftAuditCheck,
}
```

Add the helper function near the top of the file (after `_setup_logging`):

```python
def _build_cloud_client_or_none(
    cloud_integration,
) -> tuple["CloudClient | None", str | None]:
    """Construct a CloudClient if cloud_integration is enabled and the
    env var holds a key; otherwise return ``(None, error_or_None)``.

    The ``error`` string (when non-None) is logged and surfaced to the
    user as a startup error: enabling cloud integration without the key
    is a config mistake, so we exit 3 in __main__ rather than silently
    skipping the audit category.
    """
    if not cloud_integration.enabled:
        return None, None
    key = os.environ.get(cloud_integration.api_key_env)
    if not key:
        return None, (
            f"cloud_integration.enabled=true but env var "
            f"{cloud_integration.api_key_env} is not set"
        )
    client = CloudClient(
        base_url=cloud_integration.base_url,
        api_key=key,
        timeout_seconds=cloud_integration.timeout_seconds,
        max_retries=cloud_integration.max_retries,
        parallel_pages=cloud_integration.parallel_pages,
    )
    return client, None
```

In `run()`, after the existing `client.connect()` succeeds and before `_run_checks`, build the cloud client:

```python
cloud_client, cloud_error = _build_cloud_client_or_none(cfg.cloud_integration)
if cloud_error is not None:
    logger.error("config error: %s", cloud_error)
    return EXIT_STARTUP
```

Modify `_run_checks` to accept and thread `cloud_client`. Change its signature:

```python
def _run_checks(
    client: Any,
    cfg: AppConfig,
    progress: "ProgressReporter | None" = None,
    *,
    cloud_client: Any = None,
) -> list[CheckResult]:
```

Inside the loop, change the dispatch branch:

```python
if name in ("configuration_audit", "user_permission_audit"):
    results.append(instance.run(client, cfg, progress=progress))
elif name == "cloud_drift_audit":
    results.append(instance.run(client, cfg, progress=progress, cloud_client=cloud_client))
else:
    results.append(instance.run(client, cfg, snapshot=snapshot))
```

Update the call site in `run()`:

```python
results = _run_checks(client, cfg, progress=progress, cloud_client=cloud_client)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_main_cloud_wiring.py -v`
Expected: 4 passed.

Run the full suite to catch any regression:

Run: `pytest -v`
Expected: all tests pass. Existing test_main tests should be unaffected because `cloud_integration` defaults to disabled and `_build_cloud_client_or_none` returns `(None, None)`.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py tests/test_main_cloud_wiring.py
git commit -m "feat(cloud-drift): wire CloudDriftAuditCheck into __main__"
```

---

## Task 11: Example config block

**Files:**
- Modify: `docs/examples/config.yaml`
- Modify: `.env.example`

- [ ] **Step 1: Append cloud_integration + cloud_drift sections to docs/examples/config.yaml**

After the existing `user_audit:` block in `docs/examples/config.yaml`, append:

```yaml

# ---------------------------------------------------------------------------
# Cloud Drift Audit (optional). Reconciles the on-prem Security Console
# with the Insight Platform Cloud Integrations API (v4). Disabled by
# default -- requires a separate Insight Platform API key.
# ---------------------------------------------------------------------------
cloud_integration:
  enabled: false
  # Pick the region matching your Insight Platform tenant. See
  # https://insight.help.rapid7.com/docs/api-overview for the region list.
  base_url: "https://us.api.insight.rapid7.com/vm/"
  api_key_env: "R7_CLOUD_API_KEY"
  timeout_seconds: 30
  max_retries: 3
  parallel_pages: 1

cloud_drift:
  rules:
    cd.console_asset_count_drift:
      enabled: true
      severity: warn
      tolerance_percent: 5
    cd.scan_engine_cloud_registration:
      enabled: true
      severity: warn
      last_seen_max_age_hours: 24
      ignore_engines: []
    cd.stale_assessment_cohort:
      enabled: true
      severity: warn
      stale_after_days: 30
      max_stale_percent: 10
      max_stale_count: null

# Both blocks above are independently configurable. Cloud-drift rule
# overrides can be authored before the connection is wired; the entire
# audit category self-skips with a clear message when
# cloud_integration.enabled is false or the env var is missing.
```

If the existing `checks:` block does not include `cloud_drift_audit`, also append it under that block (or rely on the `_build_app_config` default-on, but the example should be explicit). Locate the existing `checks:` block in the example and add `cloud_drift_audit: true` next to `configuration_audit: true` and `user_permission_audit: true`.

- [ ] **Step 2: Update .env.example**

Append to `.env.example`:

```bash
# Optional: Insight Platform API key, separate from R7_API_KEY. Required
# only when cloud_integration.enabled=true in config.yaml.
R7_CLOUD_API_KEY=
```

- [ ] **Step 3: Sanity-check the example loads**

Run: `python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); print('OK', c.cloud_integration, c.cloud_drift)"`
Expected: prints `OK CloudIntegrationConfig(enabled=False, ...) CloudDriftConfig(rules={...})` without raising.

- [ ] **Step 4: Commit**

```bash
git add docs/examples/config.yaml .env.example
git commit -m "docs(cloud-drift): example config block + R7_CLOUD_API_KEY in .env.example"
```

---

## Task 12: README + SECURITY + CLAUDE updates

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a "Cloud Drift Audit" section to README**

Locate the existing "User & Permission Audit" section in `README.md`. Append, after it, a new section. The section should include:

- A one-paragraph intro describing what the category does (cross-reference console v3 with cloud v4) and that it is disabled by default and requires a separate Insight Platform API key.
- The three-rule table:

```markdown
### Cloud Drift Audit rules

| Rule ID | What it checks | Default severity | Source |
|---|---|---|---|
| `cd.console_asset_count_drift` | Console asset count vs. cloud asset count, flagged when divergence exceeds `tolerance_percent` (default 5%). One side at zero with the other non-zero upgrades to fail. | warn | _filled in implementation_ |
| `cd.scan_engine_cloud_registration` | Console-known engines that are missing from the Insight Platform engine list (fail) or have stale `last_seen` (warn, default 24 h). | warn | _filled in implementation_ |
| `cd.stale_assessment_cohort` | Cloud assets with `last_assessed_for_vulnerabilities` older than `stale_after_days` (default 30), flagged when the cohort exceeds `max_stale_percent` or `max_stale_count`. | warn | _filled in implementation_ |
```

- A subsection "Enabling Cloud Drift Audit" with the four required steps:
  1. Generate an Insight Platform API key in the [Insight platform key management page](https://insight.rapid7.com).
  2. Set `R7_CLOUD_API_KEY` in your environment (or `.env`).
  3. In `config.yaml`, set `cloud_integration.enabled: true` and pick the right `base_url` for your region.
  4. Optional: tune `cloud_drift.rules.*` thresholds.

- [ ] **Step 2: Add a "Cloud Drift Audit dependencies" subsection in README's exit-code table area**

No changes to the exit-code table -- startup failures (missing key when enabled) already exit 3, which is documented. But add a one-liner near the exit-code table:

```markdown
> Cloud Drift Audit, when enabled, requires `R7_CLOUD_API_KEY` to be set; missing key exits with `3` (startup error). When disabled, the category is invisible -- same behavior as a disabled check.
```

- [ ] **Step 3: Extend SECURITY.md's read-only contract section**

Locate the existing read-only contract description in `SECURITY.md`. Add a paragraph:

```markdown
### Cloud Drift Audit (v4 client)

When the Cloud Drift audit is enabled, a second HTTP client (`CloudClient`)
talks to the InsightVM Cloud Integrations API at
`https://{region}.api.insight.rapid7.com/vm/`. The same read-only contract
applies, with a separate, equally explicit allowlist:

- Verbs: `GET` and `POST` only.
- POST paths: `/v4/integration/assets` only (search endpoint with filter
  criteria in the request body).
- Endpoints deliberately excluded from the allowlist:
  - `POST /v4/integration/scan` (starts a scan)
  - `POST /v4/integration/scan/{id}/stop` (stops a running scan)
  - `POST /v4/integration/scan/engine/{id}/configuration` (mutates engine config)
  - `DELETE /v4/integration/scan/engine/{id}/configuration` (removes engine config)
  - `POST /v4/integration/sites` and `POST /v4/integration/vulnerabilities` (read-safe but unused; YAGNI)

Mutator endpoints are unreachable from the tool: invoking them raises
`ReadOnlyViolationError` before any HTTP request is sent.
```

- [ ] **Step 4: Extend CLAUDE.md's read-only safety section**

In the existing "Read-only safety" block in `CLAUDE.md`, add this paragraph at the end:

```markdown
**Cloud client (v4):** `cloud_client.py` is a peer to `client.py` for
the InsightVM Cloud Integrations API. Same allowlist discipline:
`_ALLOWED_VERBS = {"GET", "POST"}` and `_ALLOWED_POST_PATHS` is
`{"/v4/integration/assets"}`. **Never** add the v4 mutator paths
(`/v4/integration/scan`, `/v4/integration/scan/{id}/stop`,
`/v4/integration/scan/engine/{id}/configuration`) to the allowlist.
The pre-commit grep extends to this file: any `client.put`, `client.patch`,
`client.delete`, or new path in `_ALLOWED_POST_PATHS` requires a deliberate
review and a CHANGELOG entry.
```

In the "API reference" section of `CLAUDE.md`, add:

```markdown
The v4 Cloud Integrations API spec is committed at [docs/research/api-v4.json](docs/research/api-v4.json).
Cross-check v4 calls against this file the same way you cross-check v3.
The v4 base path is `/vm/v4/integration/...` and the response envelope
is `{data, metadata, links}` -- note `data` (not `resources`) and
`metadata.totalResources` (not `page.totalResources`).
```

- [ ] **Step 5: Verify nothing breaks**

Run: `pytest -v`
Expected: all tests pass (docs changes only).

- [ ] **Step 6: Commit**

```bash
git add README.md SECURITY.md CLAUDE.md
git commit -m "docs(cloud-drift): README/SECURITY/CLAUDE updates for v4 client + new audit category"
```

---

## Task 13: Backlog entry for source URLs

**Files:**
- Modify: `backlog.md` (gitignored -- local file)

- [ ] **Step 1: Append entry**

Add a section to `backlog.md` for the next minor version (e.g. `0.5.1`):

```markdown
## 0.5.1 -- Cloud Drift follow-ups

- minor -- `audit/cloud_drift/rules/*.py`: every v0 rule ships with `sources = []`.
  Pick real Rapid7 doc URLs (cloud-console sync architecture, engine
  cloud registration guidance, assessment-staleness recommendations)
  and populate the lists. Surface in README rule table at the same time.
- cleanup -- `cloud_client.py`: cursor pagination support deferred from 0.5.0.
  Current rules read totalResources only, so cursor isn't needed; revisit
  when a future rule iterates the asset list.
- minor -- `audit/cloud_drift/rules/scan_engine_cloud_registration.py`:
  matching engines by name only is the conservative v0 cross-key. If
  real-world data shows name divergence between v3 and v4, add fallback
  to host_name == address.
```

- [ ] **Step 2: No commit** (file is gitignored).

---

## Task 14: End-to-end verification + final commit hygiene

**Files:** none (verification + cleanup)

- [ ] **Step 1: Run the entire test suite**

Run: `pytest -v`
Expected: all tests pass. Note the new test count vs. before this work; it should grow by ~40 tests across the new `cloud_client/` and `audit/cloud_drift/` directories.

- [ ] **Step 2: Verify the read-only contract via grep**

Run: `git grep -nE 'PUT|PATCH|DELETE|client\.(put|patch|delete)|cloud_client\.(put|patch|delete)' src/`
Expected: zero matches (the only allowed allowlist additions are documented in the existing `_ALLOWED_POST_PATHS` constants).

Run: `git grep -nE '/v4/integration/scan(/|$)|/v4/integration/scan/.*?/stop|/v4/integration/scan/engine/.*?/configuration' src/`
Expected: zero matches except inside docstrings/comments that document the *exclusion* (cloud_client.py, SECURITY.md, CLAUDE.md). No code reference to mutator paths.

- [ ] **Step 3: Smoke-test the example config loads**

Run: `python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); assert c.cloud_integration.enabled is False; assert len(c.cloud_drift.rules) == 3; print('OK')"`
Expected: prints `OK`.

- [ ] **Step 4: Verify package imports register all 3 cloud-drift rules**

Run: `python -c "from rapid7_healthcheck.audit.cloud_drift import _CLOUD_RULE_REGISTRY; assert set(_CLOUD_RULE_REGISTRY.keys()) == {'cd.console_asset_count_drift', 'cd.scan_engine_cloud_registration', 'cd.stale_assessment_cohort'}; print('OK')"`
Expected: prints `OK`.

- [ ] **Step 5: No commit needed.** Verification only.

---

## Out of scope for this plan (deliberate)

- **Server-side delta** via `comparisonTime` / `currentTime`. Spec §"Non-goals". Existing client-side state-blob delta is sufficient.
- **Vulnerability-definition reconciliation** between v3 and v4. Low signal-to-noise.
- **Migrating existing rules to v4.** Spec rejected this -- most existing rules cannot be ported because v4 lacks the underlying data (templates, schedules, credentials, engine pools, users, roles).
- **Cursor pagination on CloudClient.** No v0 rule needs it; deferred to backlog.
- **Source URL backfill.** Deferred to backlog (Task 13) so a real implementation pass can pick the right Rapid7 doc URLs against the live docs site.

---

## Self-review checklist (run before committing the plan itself)

- [x] Each spec section has a corresponding task or is in "Out of scope"
- [x] Every task lists exact files to create / modify
- [x] Every code step shows the actual code, not "implement…"
- [x] All `pytest` commands have an expected outcome
- [x] All commit messages are concrete
- [x] Type and method names are consistent across tasks (`CloudClient.post_one`, `CloudSnapshot.cloud_assets_total`, `register_cloud_rule`, `_CLOUD_RULE_REGISTRY`, `cd.*` rule IDs)
- [x] Sources for rules are explicitly deferred (Task 13) rather than fudged in the plan
- [x] Read-only invariant has its own verification step (Task 14, Step 2)
