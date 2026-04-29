from __future__ import annotations

import logging
import time
from typing import Any, Iterator
from urllib.parse import urljoin

import requests

from rapid7_healthcheck import __version__

logger = logging.getLogger(__name__)


class Rapid7ClientError(Exception):
    """HTTP or network failure interacting with the Rapid7 API."""


class Rapid7AuthError(Rapid7ClientError):
    """401 or 403 from the Rapid7 API; do not retry."""


class ReadOnlyViolationError(Rapid7ClientError):
    """Raised when a caller tries to issue a non-read HTTP request.

    The tool is read-only by contract: only GET, plus POST to a small
    explicit allowlist of search-shaped endpoints (Rapid7 v3 requires POST
    for some search endpoints because the filter criteria travel in the
    request body). Any other verb or any unallowlisted POST path raises
    this error before the request is sent.
    """


_RETRY_STATUS = {429, 502, 503, 504}

# Read-only invariant: only these HTTP verbs are permitted, ever.
_ALLOWED_VERBS = frozenset({"GET", "POST"})

# POST is reserved for Rapid7 search endpoints whose filter criteria must
# travel in the request body. The set is intentionally tiny: extending it
# requires a deliberate code edit and review.
_ALLOWED_POST_PATHS = frozenset({"/api/3/assets/search"})


class Rapid7Client:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        verify_tls: bool = True,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        session: requests.Session | None = None,
    ) -> None:
        if (api_key is None) == (basic_auth is None):
            raise ValueError(
                "Rapid7Client requires exactly one of api_key or basic_auth"
            )
        self._base_url = base_url.rstrip("/")
        self._basic_auth = basic_auth
        self._verify = verify_tls
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._session = session or requests.Session()
        self._headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": f"rapid7-healthcheck/{__version__}",
        }
        if api_key is not None:
            self._headers["X-Api-Key"] = api_key

    def connect(self) -> None:
        """Validate base URL and credentials by hitting /api/3."""
        self.get("/api/3")

    # --- Public HTTP helpers ---

    def get(self, path: str, params: dict | None = None) -> dict:
        return self._request("GET", path, params=params)

    def post(self, path: str, json_body: dict, params: dict | None = None) -> dict:
        return self._request("POST", path, params=params, json_body=json_body)

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        page_size: int = 500,
    ) -> Iterator[dict]:
        yield from self._paginate("GET", path, params=params, page_size=page_size)

    def paginate_post(
        self,
        path: str,
        json_body: dict,
        params: dict | None = None,
        page_size: int = 500,
    ) -> Iterator[dict]:
        yield from self._paginate(
            "POST", path, params=params, page_size=page_size, json_body=json_body
        )

    # --- Internals ---

    def _paginate(
        self,
        method: str,
        path: str,
        *,
        params: dict | None,
        page_size: int,
        json_body: dict | None = None,
    ) -> Iterator[dict]:
        page = 0
        while True:
            page_params = dict(params or {})
            page_params["page"] = page
            page_params["size"] = page_size
            body = self._request(method, path, params=page_params, json_body=json_body)
            for resource in body.get("resources", []):
                yield resource
            # If `page.totalPages` is missing or 0, treat as a single-page (or empty) response and stop.
            meta = body.get("page", {})
            total_pages = int(meta.get("totalPages", 0))
            if page + 1 >= total_pages:
                return
            page += 1

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        # Read-only enforcement. Runs before any network I/O so a violation
        # never reaches the customer's console.
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
            try:
                start = time.monotonic()
                resp = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    headers=self._headers,
                    auth=self._basic_auth,
                    timeout=self._timeout,
                    verify=self._verify,
                )
                elapsed_ms = int((time.monotonic() - start) * 1000)
                logger.debug("%s %s -> %s (%d ms)", method, path, resp.status_code, elapsed_ms)
            except requests.RequestException as e:
                last_error = e
                logger.debug("%s %s network error: %s", method, path, e)
                if attempt >= self._max_retries:
                    raise Rapid7ClientError(f"network error: {e}") from e
                time.sleep(2 ** attempt)
                attempt += 1
                continue

            if resp.status_code in (401, 403):
                raise Rapid7AuthError(
                    f"auth failed ({resp.status_code}); check R7_API_KEY and base_url"
                )
            if resp.status_code in _RETRY_STATUS:
                if attempt >= self._max_retries:
                    raise Rapid7ClientError(
                        f"{resp.status_code} after {attempt + 1} attempts: {resp.text[:200]}"
                    )
                delay = self._retry_delay(resp, attempt)
                time.sleep(delay)
                attempt += 1
                continue
            if resp.status_code >= 400:
                raise Rapid7ClientError(
                    f"HTTP {resp.status_code} from {method} {path}: {resp.text[:200]}"
                )
            try:
                return resp.json()
            except ValueError as e:
                raise Rapid7ClientError(f"non-JSON response from {path}: {e}") from e

        # Unreachable, but keep the type checker happy.
        raise Rapid7ClientError(f"exhausted retries; last error: {last_error}")

    @staticmethod
    def _retry_delay(resp: requests.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return float(2 ** attempt)
