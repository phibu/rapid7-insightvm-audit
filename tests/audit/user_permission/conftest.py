from __future__ import annotations

import pytest


class FakeUserSnapshot:
    """Test double for `UserSnapshot`. Each accessor is backed by a settable
    store; tests register the data their rule consumes.

    Mirrors only the user-domain slice — six members — instead of the whole
    38-accessor EnvSnapshot. This is the testability payoff of extracting
    UserSnapshot: a user-rule test learns six methods, not thirty-eight.
    """

    def __init__(self) -> None:
        self._users: list[dict] = []
        self._users_endpoints_unavailable: bool = False
        self._authentication_sources: list[dict] = []
        self._user_2fa: dict[int, bool | None] = {}
        self._user_2fa_raises: dict[int, Exception] = {}
        self._user_sites: dict[int, list[dict]] = {}
        self._user_asset_groups: dict[int, list[dict]] = {}

    # ---- registration helpers used by tests ----

    def set_users(self, users: list[dict]) -> None:
        self._users = users

    def set_users_endpoints_unavailable(self, unavailable: bool) -> None:
        self._users_endpoints_unavailable = unavailable

    def set_authentication_sources(self, sources: list[dict]) -> None:
        self._authentication_sources = sources

    def set_user_2fa_enabled(self, user_id: int, enabled: bool | None) -> None:
        self._user_2fa[user_id] = enabled

    def set_user_2fa_raises(self, user_id: int, exc: Exception) -> None:
        """Configure user_2fa_enabled to raise `exc` for this user_id."""
        self._user_2fa_raises[user_id] = exc

    def set_user_sites(self, user_id: int, sites: list[dict]) -> None:
        self._user_sites[user_id] = sites

    def set_user_asset_groups(self, user_id: int, groups: list[dict]) -> None:
        self._user_asset_groups[user_id] = groups

    # ---- mirror of UserSnapshot's public API ----

    def users(self) -> list[dict]:
        return self._users

    def is_users_endpoints_unavailable(self) -> bool:
        return self._users_endpoints_unavailable

    def authentication_sources(self) -> list[dict]:
        return self._authentication_sources

    def user_2fa_enabled(self, user_id: int) -> bool | None:
        if user_id in self._user_2fa_raises:
            raise self._user_2fa_raises[user_id]
        return self._user_2fa.get(user_id, False)

    def user_sites(self, user_id: int) -> list[dict]:
        return self._user_sites.get(user_id, [])

    def user_asset_groups(self, user_id: int) -> list[dict]:
        return self._user_asset_groups.get(user_id, [])


@pytest.fixture
def fake_user_snapshot() -> FakeUserSnapshot:
    return FakeUserSnapshot()
