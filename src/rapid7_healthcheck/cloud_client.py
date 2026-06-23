from __future__ import annotations

import requests

from rapid7_healthcheck import __version__
from rapid7_healthcheck.client import (
    ApiDialect,
    HttpTransport,
    Rapid7ClientError,
    ReadOnlyViolationError,  # noqa: F401  re-exported; tests import it from cloud_client
    _ALLOWED_VERBS,  # noqa: F401  re-exported; read-only tests import it from cloud_client
)


class CloudClientError(Rapid7ClientError):
    """HTTP or network failure interacting with the InsightVM Cloud
    Integrations API (v4).

    Subclass of `Rapid7ClientError` so the existing `_extract_diagnostics`
    helper in `audit/__init__.py` pulls `status_code` and `error_path`
    off the same exception type without code changes. Since 0.6.0 the
    `_ERROR_PATH_RE` regex matches both `/api/3/...` and
    `/v4/integration/...` path shapes; cloud-rule failure findings
    carry the same `error_path` diagnostic as v3 failures.
    """


# Minimal v4 read-only allowlist. Every entry is a search endpoint
# whose filter criteria travel in the request body. Mutator endpoints
# (POST /v4/integration/scan, POST /v4/integration/scan/{id}/stop,
# POST /v4/integration/scan/engine/{id}/configuration, DELETE on the
# same) are deliberately omitted. POST /v4/integration/sites and
# POST /v4/integration/vulnerabilities are read-safe but not needed
# by v0 rules — re-add when a rule requires them.
#
# Stays a named module-level constant so the pre-commit read-only grep
# and the static read-only tests can find it; it feeds V4_DIALECT below.
_ALLOWED_POST_PATHS = frozenset({"/v4/integration/assets"})


# The v4 Cloud Integrations API dialect: results in {data, metadata},
# X-Api-Key auth only, errors as CloudClientError.
V4_DIALECT = ApiDialect(
    resource_key="data",
    page_meta_key="metadata",
    allowed_post_paths=_ALLOWED_POST_PATHS,
    error_cls=CloudClientError,
    auth_hint="R7_CLOUD_API_KEY and base_url",
)


class CloudClient(HttpTransport):
    """Adapter for the v4 Cloud Integrations API (``/v4/integration/...``).

    Wires :data:`V4_DIALECT` onto :class:`HttpTransport`. The Cloud API
    accepts only ``X-Api-Key`` auth, so this adapter takes a single
    ``api_key``. Adds no transport behaviour; everything but construction
    is inherited.
    """

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
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": f"rapid7-healthcheck/{__version__}",
            "X-Api-Key": api_key,
        }
        super().__init__(
            base_url=base_url,
            headers=headers,
            auth=None,
            dialect=V4_DIALECT,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            parallel_pages=parallel_pages,
            default_page_size=default_page_size,
            session=session,
        )
