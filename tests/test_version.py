"""Regression guard for the version-drift bug.

Every release before 0.1.8 shipped a report stamped Version: 0.1.0
because src/rapid7_healthcheck/__init__.py carried a hardcoded
__version__ that was never bumped alongside pyproject.toml. The fix
sources __version__ from package metadata so pyproject.toml is the
single declaration.

If anyone reintroduces a hardcoded __version__ that disagrees with
pyproject.toml, this test fails.
"""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

import rapid7_healthcheck


def test_version_matches_package_metadata() -> None:
    assert rapid7_healthcheck.__version__ == _pkg_version("rapid7-insightvm-audit")
