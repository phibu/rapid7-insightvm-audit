"""User & Permission audit data container.

`UserSnapshot` is the narrow, lazy-loading data container the User &
Permission audit reads through -- peer to `EnvSnapshot` (configuration /
template data) and `CloudSnapshot` (cross-API cloud-drift data), and the
third adapter at the `AuditCategory.build_snapshot` seam.

It holds only the user / RBAC slice. Unlike `EnvSnapshot`, it honours no
sampling (`full_scan` / `sample_size`): every user accessor paginates the
full population by design -- a sampled user count would be misleading -- so
the snapshot needs nothing but the v3 client. See CONTEXT.md "UserSnapshot".

Read-only contract: every accessor issues GETs only (`/api/3/users` and
friends). No verb here may become PUT/PATCH/DELETE -- this module is on the
pre-commit read-only grep target (see CLAUDE.md).
"""

from __future__ import annotations

import logging
from typing import Any

from rapid7_healthcheck.client import Rapid7ClientError

logger = logging.getLogger(__name__)


class UserSnapshot:
    """Lazy, fetch-once container for the User & Permission audit's data.

    Every accessor caches on first call and serves the cached value for the
    snapshot's lifetime. Construct one per category run via
    `UserSnapshot(client)`.
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._users: list[dict] | None = None
        self._users_endpoints_unavailable: bool = False
        self._authentication_sources: list[dict] | None = None
        self._user_2fa: dict[int, bool | None] = {}
        self._user_sites: dict[int, list[dict]] = {}
        self._user_asset_groups: dict[int, list[dict]] = {}

    def users(self) -> list[dict]:
        """All users from /api/3/users (Global Administrator only).

        Traps 404 -- some heavily restricted custom roles do not expose the
        users endpoint. On 404 we set `users_endpoints_unavailable` so the
        whole user-audit category can self-skip honestly rather than fail.
        Other errors propagate.
        """
        if self._users is None:
            try:
                self._users = list(self._client.paginate("/api/3/users"))
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    logger.info("users endpoint not available -- user audit will skip")
                    self._users = []
                    self._users_endpoints_unavailable = True
                else:
                    raise
        return self._users

    def is_users_endpoints_unavailable(self) -> bool:
        """True if /api/3/users returned 404 -- pure read of the cached flag.
        Callers should invoke `users()` first to prime the flag.
        """
        return self._users_endpoints_unavailable

    def authentication_sources(self) -> list[dict]:
        """Configured authentication sources (LDAP, SAML, Kerberos, normal).

        Used to detect SSO configuration. Each entry has an `external` flag
        -- `external: true` indicates a configured SSO source. Traps 404
        identically to `users()`: missing endpoint means we can't reason
        about SSO at all.
        """
        if self._authentication_sources is None:
            try:
                body = self._client.get("/api/3/authentication_sources")
                self._authentication_sources = list(body.get("resources", []))
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    logger.info("authentication_sources endpoint not available")
                    self._authentication_sources = []
                else:
                    raise
        return self._authentication_sources

    def user_2fa_enabled(self, user_id: int) -> bool | None:
        """Tri-state 2FA status for a user.

        Returns:
            True  -- 2FA is configured (the endpoint returned a non-empty key).
            False -- 2FA is NOT configured (the endpoint returned, but no key).
            None  -- endpoint unavailable on this console (404). Caller should
                    treat None as "cannot audit MFA on this console" and skip
                    the rule, not as a finding.
        """
        if user_id not in self._user_2fa:
            try:
                body = self._client.get(f"/api/3/users/{user_id}/2FA")
                key = body.get("key") if isinstance(body, dict) else None
                self._user_2fa[user_id] = bool(key)
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_2fa[user_id] = None
                else:
                    raise
        return self._user_2fa[user_id]

    def user_sites(self, user_id: int) -> list[dict]:
        """Sites a user has explicit access to (excluding `role.allSites`)."""
        if user_id not in self._user_sites:
            try:
                self._user_sites[user_id] = list(
                    self._client.paginate(f"/api/3/users/{user_id}/sites")
                )
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_sites[user_id] = []
                else:
                    raise
        return self._user_sites[user_id]

    def user_asset_groups(self, user_id: int) -> list[dict]:
        """Asset groups a user has explicit access to (excluding `role.allAssetGroups`)."""
        if user_id not in self._user_asset_groups:
            try:
                self._user_asset_groups[user_id] = list(
                    self._client.paginate(f"/api/3/users/{user_id}/asset_groups")
                )
            except Rapid7ClientError as e:
                if e.status_code == 404:
                    self._user_asset_groups[user_id] = []
                else:
                    raise
        return self._user_asset_groups[user_id]
