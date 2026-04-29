"""rapid7-insightvm-audit — read-only audit + health check for InsightVM.

The package version is sourced from installed package metadata so
pyproject.toml is the single declaration. Hard-coded duplicates here
have caused report drift in the past (every release before 0.1.8
shipped a report stamped 0.1.0).
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("rapid7-insightvm-audit")
except PackageNotFoundError:  # not installed (e.g. running from a checkout without pip install -e)
    __version__ = "0.0.0+unknown"
