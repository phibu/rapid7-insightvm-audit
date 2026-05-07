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
    which is acceptable — error_status_code carries the same diagnostic
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
# by v0 rules — re-add when a rule requires them.
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
        if max_retries < 0:
            raise ValueError(
                f"max_retries must be non-negative; got {max_retries}"
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
