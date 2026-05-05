from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterator
from urllib.parse import urljoin

import requests

from rapid7_healthcheck import __version__

logger = logging.getLogger(__name__)


class Rapid7ClientError(Exception):
    """HTTP or network failure interacting with the Rapid7 API.

    `status_code` carries the HTTP status when the failure was driven by
    a server response (4xx / 5xx). It is `None` for failures that
    happened before the response was received (network errors), for 2xx
    responses with unparseable bodies, and for read-only invariant
    violations raised before any HTTP call. Callers branching on HTTP
    status MUST inspect `status_code` rather than substring-matching the
    error message — message text includes the request path and up to
    1500 chars of response body, so substring matching is brittle.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


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

_SENSITIVE_PARAM_SUBSTRINGS = ("key", "token", "secret", "password", "auth")
_PARAM_SUMMARY_MAX_LEN = 200


def _summarize_params(params: dict | None) -> str:
    """Format a params dict as `?k1=v1&k2=v2` for log lines.

    Sanitizer: any key whose lowercased name contains one of
    {"key", "token", "secret", "password", "auth"} has its value replaced
    with "***" — defense-in-depth against a future endpoint accidentally
    accepting a credential as a query param.

    Output is capped at 200 chars to keep log lines scannable; if the cap
    is hit, the trailing portion is replaced with "...".
    """
    if not params:
        return ""
    parts: list[str] = []
    for k, v in params.items():
        key_lower = str(k).lower()
        if any(s in key_lower for s in _SENSITIVE_PARAM_SUBSTRINGS):
            parts.append(f"{k}=***")
        else:
            parts.append(f"{k}={v}")
    body = "&".join(parts)
    if len(body) > _PARAM_SUMMARY_MAX_LEN - 1:  # -1 for the leading "?"
        body = body[:_PARAM_SUMMARY_MAX_LEN - 4] + "..."
    return "?" + body


class Rapid7Client:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        verify_tls: bool = True,
        timeout_seconds: int = 60,
        max_retries: int = 3,
        parallel_pages: int = 1,
        default_page_size: int = 250,
        session: requests.Session | None = None,
    ) -> None:
        if (api_key is None) == (basic_auth is None):
            raise ValueError(
                "Rapid7Client requires exactly one of api_key or basic_auth"
            )
        if not (1 <= parallel_pages <= 16):
            raise ValueError(
                f"parallel_pages must be in range [1, 16]; got {parallel_pages}"
            )
        if not (1 <= default_page_size <= 500):
            raise ValueError(
                f"default_page_size must be in range [1, 500]; got {default_page_size}"
            )
        self._base_url = base_url.rstrip("/")
        self._basic_auth = basic_auth
        self._verify = verify_tls
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._parallel_pages = parallel_pages
        self._default_page_size = default_page_size
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
        page_size: int | None = None,
        parallel_pages: int | None = None,
    ) -> Iterator[dict]:
        yield from self._paginate(
            "GET", path,
            params=params,
            page_size=page_size if page_size is not None else self._default_page_size,
            parallel_pages=parallel_pages if parallel_pages is not None else self._parallel_pages,
        )

    def paginate_post(
        self,
        path: str,
        json_body: dict,
        params: dict | None = None,
        page_size: int | None = None,
        parallel_pages: int | None = None,
    ) -> Iterator[dict]:
        yield from self._paginate(
            "POST", path,
            params=params,
            page_size=page_size if page_size is not None else self._default_page_size,
            json_body=json_body,
            parallel_pages=parallel_pages if parallel_pages is not None else self._parallel_pages,
        )

    def post_one(
        self,
        path: str,
        *,
        json_body: dict,
        params: dict | None = None,
    ) -> dict:
        """Issue a single POST to a search endpoint and return the parsed response.

        Unlike `paginate_post`, this does not iterate pages — useful when the
        caller only needs `page.totalResources` and the first page of resources
        (e.g. for count-with-examples summaries). The path must be in the
        read-only POST allowlist (`_ALLOWED_POST_PATHS`).
        """
        return self._request("POST", path, params=params, json_body=json_body)

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
    ) -> Iterator[dict]:
        # Phase 1: probe page 0 sequentially. We need totalPages before
        # we can dispatch any parallel work.
        page0_params = dict(params or {})
        page0_params["page"] = 0
        page0_params["size"] = page_size
        body0 = self._request(method, path, params=page0_params, json_body=json_body)
        for resource in body0.get("resources", []):
            yield resource

        meta = body0.get("page", {})
        total_pages = int(meta.get("totalPages", 0))
        if total_pages <= 1:
            return

        # Sequential fast path — preserve today's behavior bit-for-bit
        # when caller hasn't opted into parallelism.
        if parallel_pages <= 1:
            for page_num in range(1, total_pages):
                page_params = dict(params or {})
                page_params["page"] = page_num
                page_params["size"] = page_size
                body = self._request(method, path, params=page_params, json_body=json_body)
                for resource in body.get("resources", []):
                    yield resource
            return

        # Phase 2: parallel batches of size `parallel_pages`.
        logger.info(
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
                            params=page_params, json_body=json_body,
                        )
                        futures[page_num] = fut

                    # Collect results, then yield in page-index order.
                    results: dict[int, dict] = {}
                    for page_num, fut in futures.items():
                        results[page_num] = fut.result()  # raises if the future failed

                    for page_num in batch:
                        for resource in results[page_num].get("resources", []):
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
            logger.debug("→ %s %s%s", method, path, _summarize_params(params))
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
                logger.debug("← %s %s %d in %dms", method, path, resp.status_code, elapsed_ms)
            except requests.RequestException as e:
                last_error = e
                logger.debug("✗ %s %s network error: %s", method, path, e)
                if attempt >= self._max_retries:
                    raise Rapid7ClientError(
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
                    f"auth failed ({resp.status_code}); check R7_API_KEY and base_url",
                    status_code=resp.status_code,
                )
            if resp.status_code in _RETRY_STATUS:
                if attempt >= self._max_retries:
                    raise Rapid7ClientError(
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
                raise Rapid7ClientError(
                    f"HTTP {resp.status_code} from {method} {path}: {resp.text[:1500]}",
                    status_code=resp.status_code,
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
