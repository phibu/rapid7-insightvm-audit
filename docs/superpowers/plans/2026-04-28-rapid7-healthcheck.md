# Rapid7 InsightVM Health Check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that runs read-only health checks against a Rapid7 InsightVM environment via the Insight Platform API and produces a self-contained HTML report.

**Architecture:** Small package with one module per concern: `client.py` (HTTP), `config.py` (YAML + dataclasses), `checks/*.py` (one per topic, isolated), `report.py` (Jinja2 → HTML), `__main__.py` (orchestrator + exit codes). Each check is independently testable with a fake client; the renderer is deterministic given a list of `CheckResult`.

**Tech Stack:** Python 3.11+, `requests`, `PyYAML`, `Jinja2`, `python-dotenv`, `pytest`. No async, no Pydantic, no Click. Spec: `docs/superpowers/specs/2026-04-28-rapid7-healthcheck-design.md`.

---

## File Map

**Created:**
- `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `.env.example`, `config.example.yaml`, `README.md`
- `rapid7_healthcheck/__init__.py` — `__version__`
- `rapid7_healthcheck/__main__.py` — CLI entry, orchestrator, exit codes
- `rapid7_healthcheck/config.py` — dataclasses + YAML loader + validation
- `rapid7_healthcheck/client.py` — `Rapid7Client`, errors, pagination, retry
- `rapid7_healthcheck/report.py` — Jinja2 renderer, file writer
- `rapid7_healthcheck/templates/report.html.j2` — single self-contained HTML template
- `rapid7_healthcheck/checks/__init__.py` — `Finding`, `CheckResult`, `Check` protocol, status rollup helper
- `rapid7_healthcheck/checks/scan_engines.py`
- `rapid7_healthcheck/checks/scan_activity.py`
- `rapid7_healthcheck/checks/asset_coverage.py`
- `rapid7_healthcheck/checks/data_quality.py`
- `tests/conftest.py` — `FakeRapid7Client`, sample fixture builders
- `tests/test_config.py`
- `tests/test_client.py`
- `tests/test_report.py`
- `tests/test_main.py` — orchestrator/exit codes
- `tests/checks/test_scan_engines.py`
- `tests/checks/test_scan_activity.py`
- `tests/checks/test_asset_coverage.py`
- `tests/checks/test_data_quality.py`

**No existing files to modify.** Greenfield project.

---

## Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `rapid7_healthcheck/__init__.py`
- Create: `rapid7_healthcheck/checks/__init__.py` (empty placeholder, replaced in Task 5)
- Create: `tests/__init__.py`
- Create: `tests/checks/__init__.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "rapid7-healthcheck"
version = "0.1.0"
description = "Read-only health check for a Rapid7 InsightVM environment"
requires-python = ">=3.11"
dependencies = [
    "requests>=2.32,<3",
    "PyYAML>=6.0,<7",
    "Jinja2>=3.1,<4",
    "python-dotenv>=1.0,<2",
]

[project.optional-dependencies]
dev = ["pytest>=8.0,<9"]

[tool.setuptools.packages.find]
include = ["rapid7_healthcheck*"]

[tool.setuptools.package-data]
rapid7_healthcheck = ["templates/*.j2"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create `requirements.txt`**

```
requests>=2.32,<3
PyYAML>=6.0,<7
Jinja2>=3.1,<4
python-dotenv>=1.0,<2
```

- [ ] **Step 3: Create `requirements-dev.txt`**

```
-r requirements.txt
pytest>=8.0,<9
```

- [ ] **Step 4: Create `.gitignore`**

```
__pycache__/
*.pyc
.venv/
.env
config.yaml
reports/
*.egg-info/
.pytest_cache/
build/
dist/
```

- [ ] **Step 5: Create `.env.example`**

```
# Copy this to .env and fill in your read-only Insight Platform API key
R7_API_KEY=replace-me
```

- [ ] **Step 6: Create `rapid7_healthcheck/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 7: Create empty placeholder packages**

Create `rapid7_healthcheck/checks/__init__.py` with the single line `# replaced in Task 5`.
Create `tests/__init__.py` empty.
Create `tests/checks/__init__.py` empty.

- [ ] **Step 8: Verify the package installs**

Run: `python -m venv .venv && .venv\Scripts\activate && pip install -e .[dev]`
Expected: install completes without errors.

- [ ] **Step 9: Verify pytest runs (zero tests)**

Run: `pytest -q`
Expected: `no tests ran`.

- [ ] **Step 10: Commit**

```bash
git init
git add .
git commit -m "chore: scaffold rapid7-healthcheck package"
```

---

## Task 2: Config dataclasses

**Files:**
- Create: `rapid7_healthcheck/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

```python
import textwrap
from pathlib import Path

import pytest

from rapid7_healthcheck.config import AppConfig, ConfigError, load_config


VALID_YAML = textwrap.dedent("""
    rapid7:
      base_url: https://us.api.insight.rapid7.com
      verify_tls: true
      request_timeout_seconds: 30
      max_retries: 3
    report:
      output_dir: ./reports
      filename_pattern: "rapid7-health-{timestamp}.html"
      title: "Rapid7 InsightVM Environment Health Check"
    thresholds:
      scan_engines:
        last_contact_warn_hours: 2
        last_contact_fail_hours: 24
      scan_activity:
        recent_window_days: 7
        stuck_scan_hours: 24
        site_no_scan_days: 14
      asset_coverage:
        stale_asset_days: 30
        flag_unscanned_assets: true
      data_quality:
        flag_missing_os: true
        flag_empty_sites: true
    checks:
      scan_engines: true
      scan_activity: true
      asset_coverage: true
      data_quality: true
""")


def write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_config_returns_typed_appconfig(tmp_path):
    cfg = load_config(write(tmp_path, VALID_YAML))
    assert isinstance(cfg, AppConfig)
    assert cfg.rapid7.base_url == "https://us.api.insight.rapid7.com"
    assert cfg.rapid7.verify_tls is True
    assert cfg.rapid7.request_timeout_seconds == 30
    assert cfg.rapid7.max_retries == 3
    assert cfg.report.output_dir == "./reports"
    assert cfg.thresholds.scan_engines.last_contact_warn_hours == 2
    assert cfg.thresholds.asset_coverage.flag_unscanned_assets is True
    assert cfg.checks["scan_engines"] is True


def test_unknown_key_raises(tmp_path):
    body = VALID_YAML + "\nunexpected_root: 1\n"
    with pytest.raises(ConfigError, match="unknown"):
        load_config(write(tmp_path, body))


def test_missing_required_section_raises(tmp_path):
    body = VALID_YAML.replace("rapid7:", "wrong_name:")
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, body))


def test_base_url_must_be_https(tmp_path):
    body = VALID_YAML.replace(
        "https://us.api.insight.rapid7.com",
        "http://us.api.insight.rapid7.com",
    )
    with pytest.raises(ConfigError, match="https"):
        load_config(write(tmp_path, body))


def test_unknown_nested_key_raises(tmp_path):
    body = VALID_YAML.replace(
        "verify_tls: true",
        "verify_tls: true\n  bogus: 1",
    )
    with pytest.raises(ConfigError, match="unknown"):
        load_config(write(tmp_path, body))


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.yaml")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_config.py -v`
Expected: import errors / module not found.

- [ ] **Step 3: Implement `config.py`**

Create `rapid7_healthcheck/config.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or has unknown keys."""


@dataclass(frozen=True)
class Rapid7Config:
    base_url: str
    verify_tls: bool
    request_timeout_seconds: int
    max_retries: int


@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str


@dataclass(frozen=True)
class ScanEngineThresholds:
    last_contact_warn_hours: int
    last_contact_fail_hours: int


@dataclass(frozen=True)
class ScanActivityThresholds:
    recent_window_days: int
    stuck_scan_hours: int
    site_no_scan_days: int


@dataclass(frozen=True)
class AssetCoverageThresholds:
    stale_asset_days: int
    flag_unscanned_assets: bool


@dataclass(frozen=True)
class DataQualityThresholds:
    flag_missing_os: bool
    flag_empty_sites: bool


@dataclass(frozen=True)
class Thresholds:
    scan_engines: ScanEngineThresholds
    scan_activity: ScanActivityThresholds
    asset_coverage: AssetCoverageThresholds
    data_quality: DataQualityThresholds


@dataclass(frozen=True)
class AppConfig:
    rapid7: Rapid7Config
    report: ReportConfig
    thresholds: Thresholds
    checks: dict[str, bool]


def _from_dict(cls: type, data: Any, path: str) -> Any:
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected mapping, got {type(data).__name__}")
    expected = {f.name for f in fields(cls)}
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {sorted(unknown)}")
    missing = expected - set(data.keys())
    if missing:
        raise ConfigError(f"{path}: missing required key(s): {sorted(missing)}")
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        value = data[f.name]
        sub_path = f"{path}.{f.name}" if path else f.name
        if is_dataclass(f.type) if isinstance(f.type, type) else False:
            kwargs[f.name] = _from_dict(f.type, value, sub_path)
        else:
            kwargs[f.name] = value
    return cls(**kwargs)


_NESTED = {
    "rapid7": Rapid7Config,
    "report": ReportConfig,
    "thresholds": Thresholds,
}
_THRESHOLD_NESTED = {
    "scan_engines": ScanEngineThresholds,
    "scan_activity": ScanActivityThresholds,
    "asset_coverage": AssetCoverageThresholds,
    "data_quality": DataQualityThresholds,
}


def _build_thresholds(data: Any) -> Thresholds:
    if not isinstance(data, dict):
        raise ConfigError("thresholds: expected mapping")
    expected = set(_THRESHOLD_NESTED.keys())
    unknown = set(data.keys()) - expected
    if unknown:
        raise ConfigError(f"thresholds: unknown key(s): {sorted(unknown)}")
    missing = expected - set(data.keys())
    if missing:
        raise ConfigError(f"thresholds: missing required key(s): {sorted(missing)}")
    return Thresholds(
        scan_engines=_from_dict(ScanEngineThresholds, data["scan_engines"], "thresholds.scan_engines"),
        scan_activity=_from_dict(ScanActivityThresholds, data["scan_activity"], "thresholds.scan_activity"),
        asset_coverage=_from_dict(AssetCoverageThresholds, data["asset_coverage"], "thresholds.asset_coverage"),
        data_quality=_from_dict(DataQualityThresholds, data["data_quality"], "thresholds.data_quality"),
    )


def _build_app_config(data: dict) -> AppConfig:
    expected_root = {"rapid7", "report", "thresholds", "checks"}
    unknown = set(data.keys()) - expected_root
    if unknown:
        raise ConfigError(f"unknown root key(s): {sorted(unknown)}")
    missing = expected_root - set(data.keys())
    if missing:
        raise ConfigError(f"missing required root key(s): {sorted(missing)}")

    rapid7 = _from_dict(Rapid7Config, data["rapid7"], "rapid7")
    if not rapid7.base_url.startswith("https://"):
        raise ConfigError("rapid7.base_url must start with https://")

    report = _from_dict(ReportConfig, data["report"], "report")
    thresholds = _build_thresholds(data["thresholds"])

    checks = data["checks"]
    if not isinstance(checks, dict) or not all(isinstance(v, bool) for v in checks.values()):
        raise ConfigError("checks: expected mapping of name -> bool")

    return AppConfig(rapid7=rapid7, report=report, thresholds=thresholds, checks=checks)


def load_config(path: Path | str) -> AppConfig:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"failed to parse YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    return _build_app_config(raw)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: 6 passed.

- [ ] **Step 5: Create `config.example.yaml`**

```yaml
rapid7:
  base_url: https://us.api.insight.rapid7.com
  verify_tls: true
  request_timeout_seconds: 30
  max_retries: 3

report:
  output_dir: ./reports
  filename_pattern: "rapid7-health-{timestamp}.html"
  title: "Rapid7 InsightVM Environment Health Check"

thresholds:
  scan_engines:
    last_contact_warn_hours: 2
    last_contact_fail_hours: 24
  scan_activity:
    recent_window_days: 7
    stuck_scan_hours: 24
    site_no_scan_days: 14
  asset_coverage:
    stale_asset_days: 30
    flag_unscanned_assets: true
  data_quality:
    flag_missing_os: true
    flag_empty_sites: true

checks:
  scan_engines: true
  scan_activity: true
  asset_coverage: true
  data_quality: true
```

- [ ] **Step 6: Commit**

```bash
git add rapid7_healthcheck/config.py tests/test_config.py config.example.yaml
git commit -m "feat: add typed YAML config loader with validation"
```

---

## Task 3: Errors and check primitives

**Files:**
- Create: `rapid7_healthcheck/checks/__init__.py` (replaces placeholder)

- [ ] **Step 1: Implement check primitives**

Replace `rapid7_healthcheck/checks/__init__.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from rapid7_healthcheck.config import AppConfig


Severity = Literal["info", "warn", "fail"]
Status = Literal["pass", "warn", "fail", "error", "skipped"]


@dataclass(frozen=True)
class Finding:
    severity: Severity
    message: str
    details: dict[str, Any] | None = None


@dataclass
class CheckResult:
    name: str
    description: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None


def rollup_status(findings: list[Finding]) -> Status:
    if any(f.severity == "fail" for f in findings):
        return "fail"
    if any(f.severity == "warn" for f in findings):
        return "warn"
    return "pass"


class Check(Protocol):
    name: str
    description: str

    def run(self, client: Any, config: AppConfig) -> CheckResult: ...
```

- [ ] **Step 2: Verify imports**

Run: `python -c "from rapid7_healthcheck.checks import Finding, CheckResult, rollup_status; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add rapid7_healthcheck/checks/__init__.py
git commit -m "feat: add CheckResult, Finding, and status rollup"
```

---

## Task 4: API client (auth, pagination, retry)

**Files:**
- Create: `rapid7_healthcheck/client.py`
- Test: `tests/test_client.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_client.py`:

```python
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from rapid7_healthcheck.client import (
    Rapid7AuthError,
    Rapid7Client,
    Rapid7ClientError,
)


def _resp(status: int, body: dict | None = None, headers: dict | None = None):
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.headers = headers or {}
    r.text = json.dumps(body) if body is not None else ""
    r.json.return_value = body or {}
    return r


@pytest.fixture
def session():
    s = MagicMock(spec=requests.Session)
    s.headers = {}
    return s


def make_client(session, **overrides):
    kwargs = dict(
        base_url="https://us.api.insight.rapid7.com",
        api_key="key",
        verify_tls=True,
        timeout_seconds=5,
        max_retries=2,
        session=session,
    )
    kwargs.update(overrides)
    return Rapid7Client(**kwargs)


def test_get_sends_x_api_key_header(session):
    session.request.return_value = _resp(200, {"ok": True})
    c = make_client(session)
    c.get("/api/3/sites")
    args, kwargs = session.request.call_args
    assert kwargs["headers"]["X-Api-Key"] == "key"
    assert kwargs["headers"]["Accept"] == "application/json"
    assert kwargs["url"] == "https://us.api.insight.rapid7.com/api/3/sites"
    assert kwargs["timeout"] == 5
    assert kwargs["verify"] is True


def test_paginate_yields_resources_across_pages(session):
    page0 = {"resources": [{"id": 1}, {"id": 2}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 3}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session)
    items = list(c.paginate("/api/3/sites", page_size=500))
    assert [i["id"] for i in items] == [1, 2, 3]
    # Verify pagination params
    first_call = session.request.call_args_list[0]
    assert first_call.kwargs["params"]["page"] == 0
    assert first_call.kwargs["params"]["size"] == 500


def test_401_raises_auth_error_no_retry(session):
    session.request.return_value = _resp(401, {"message": "bad key"})
    c = make_client(session)
    with pytest.raises(Rapid7AuthError):
        c.get("/api/3/sites")
    assert session.request.call_count == 1


def test_429_retries_with_retry_after(session, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: sleeps.append(s))
    session.request.side_effect = [
        _resp(429, headers={"Retry-After": "2"}),
        _resp(200, {"ok": True}),
    ]
    c = make_client(session, max_retries=2)
    c.get("/api/3/sites")
    assert sleeps == [2.0]


def test_503_retries_with_exponential_backoff(session, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: sleeps.append(s))
    session.request.side_effect = [
        _resp(503),
        _resp(503),
        _resp(200, {"ok": True}),
    ]
    c = make_client(session, max_retries=3)
    c.get("/api/3/sites")
    assert sleeps == [1.0, 2.0]


def test_max_retries_exhausted_raises(session, monkeypatch):
    monkeypatch.setattr("rapid7_healthcheck.client.time.sleep", lambda s: None)
    session.request.return_value = _resp(503)
    c = make_client(session, max_retries=2)
    with pytest.raises(Rapid7ClientError):
        c.get("/api/3/sites")


def test_4xx_other_than_auth_raises(session):
    session.request.return_value = _resp(400, {"message": "bad"})
    c = make_client(session)
    with pytest.raises(Rapid7ClientError) as exc:
        c.get("/api/3/sites")
    assert "400" in str(exc.value)


def test_connect_does_metadata_get(session):
    session.request.return_value = _resp(200, {"version": "3"})
    c = make_client(session)
    c.connect()
    args, kwargs = session.request.call_args
    assert kwargs["url"].endswith("/api/3")


def test_connect_auth_failure_raises_auth_error(session):
    session.request.return_value = _resp(401)
    c = make_client(session)
    with pytest.raises(Rapid7AuthError):
        c.connect()


def test_post_sends_json_body(session):
    session.request.return_value = _resp(200, {"resources": [], "page": {"number": 0, "totalPages": 1}})
    c = make_client(session)
    c.post("/api/3/assets/search", json_body={"filters": []})
    kwargs = session.request.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["json"] == {"filters": []}


def test_paginate_post_yields_across_pages(session):
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session)
    items = list(c.paginate_post("/api/3/assets/search", json_body={"filters": []}, page_size=500))
    assert [i["id"] for i in items] == [1, 2]


def test_zero_pages_returns_empty(session):
    session.request.return_value = _resp(200, {"resources": [], "page": {"number": 0, "totalPages": 0}})
    c = make_client(session)
    assert list(c.paginate("/api/3/sites")) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_client.py -v`
Expected: import errors.

- [ ] **Step 3: Implement `client.py`**

Create `rapid7_healthcheck/client.py`:

```python
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


_RETRY_STATUS = {429, 502, 503, 504}


class Rapid7Client:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool = True,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        session: requests.Session | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._verify = verify_tls
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._session = session or requests.Session()
        self._headers = {
            "X-Api-Key": api_key,
            "Accept": "application/json",
            "User-Agent": f"rapid7-healthcheck/{__version__}",
        }

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_client.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/client.py tests/test_client.py
git commit -m "feat: add Rapid7Client with pagination and retry"
```

---

## Task 5: Test fixtures (FakeRapid7Client)

**Files:**
- Create: `tests/conftest.py`

- [ ] **Step 1: Implement fake client and shared fixtures**

Create `tests/conftest.py`:

```python
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
        self._post: dict[str, dict] = {}
        self._paginate: dict[str, list[dict]] = {}
        self._paginate_post: dict[str, list[dict]] = {}
        self.calls: list[tuple[str, str, dict | None, dict | None]] = []

    def set_get(self, path: str, body: dict) -> None:
        self._get[path] = body

    def set_post(self, path: str, body: dict) -> None:
        self._post[path] = body

    def set_paginate(self, path: str, resources: Iterable[dict]) -> None:
        self._paginate[path] = list(resources)

    def set_paginate_post(self, path: str, resources: Iterable[dict]) -> None:
        self._paginate_post[path] = list(resources)

    def connect(self) -> None:
        return None

    def get(self, path: str, params: dict | None = None) -> dict:
        self.calls.append(("get", path, params, None))
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
```

- [ ] **Step 2: Verify fixtures import**

Run: `pytest --collect-only -q tests/test_config.py`
Expected: still collects 6 tests; no import errors from `conftest.py`.

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "test: add FakeRapid7Client and shared fixtures"
```

---

## Task 6: Scan Engines check

**Files:**
- Create: `rapid7_healthcheck/checks/scan_engines.py`
- Test: `tests/checks/test_scan_engines.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/checks/test_scan_engines.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.checks.scan_engines import ScanEnginesCheck


def _now_iso(offset_hours: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return t.isoformat().replace("+00:00", "Z")


def test_all_engines_healthy(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "engine-a", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},
                {"id": 2, "name": "engine-b", "status": "active",
                 "lastRefreshedDate": _now_iso(1), "sites": [11]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["engines_total"] == 2
    assert result.summary["engines_healthy"] == 2
    assert result.findings == []


def test_engine_warn_when_last_contact_exceeds_warn_hours(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "warm", "status": "active",
                 "lastRefreshedDate": _now_iso(3), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert any(f.severity == "warn" and "warm" in f.message for f in result.findings)
    assert result.summary["engines_warn"] == 1


def test_engine_fail_when_last_contact_exceeds_fail_hours(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "stale", "status": "active",
                 "lastRefreshedDate": _now_iso(48), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "fail"
    assert result.summary["engines_fail"] == 1


def test_inactive_engine_is_fail(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "off", "status": "inactive",
                 "lastRefreshedDate": _now_iso(0), "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "fail"


def test_engine_with_no_sites_is_warn(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "lonely", "status": "active",
                 "lastRefreshedDate": _now_iso(0), "sites": []},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert any("not paired" in f.message.lower() for f in result.findings)


def test_missing_last_refreshed_is_warn(fake_client, app_config):
    fake_client.set_get(
        "/api/3/scan_engines",
        {
            "resources": [
                {"id": 1, "name": "no-ts", "status": "active",
                 "lastRefreshedDate": None, "sites": [10]},
            ]
        },
    )
    result = ScanEnginesCheck().run(fake_client, app_config)
    assert result.status == "warn"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/checks/test_scan_engines.py -v`
Expected: import error.

- [ ] **Step 3: Implement the check**

Create `rapid7_healthcheck/checks/scan_engines.py`:

```python
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class ScanEnginesCheck:
    name = "Scan Engines"
    description = "Health and pairing status of all configured scan engines."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        thresholds = config.thresholds.scan_engines
        body = client.get("/api/3/scan_engines")
        engines = body.get("resources", [])
        now = datetime.now(timezone.utc)

        findings: list[Finding] = []
        warn_count = 0
        fail_count = 0

        for engine in engines:
            name = engine.get("name", f"id={engine.get('id')}")
            status = engine.get("status", "unknown")
            last_refreshed = _parse_iso(engine.get("lastRefreshedDate"))
            sites = engine.get("sites") or []

            if status == "inactive" or status == "unknown":
                findings.append(Finding(
                    severity="fail",
                    message=f"Engine '{name}' status is '{status}'",
                    details={"id": engine.get("id"), "status": status},
                ))
                fail_count += 1
                continue

            if last_refreshed is None:
                findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' has no lastRefreshedDate",
                    details={"id": engine.get("id")},
                ))
                warn_count += 1
                continue

            age_hours = (now - last_refreshed).total_seconds() / 3600.0
            if age_hours >= thresholds.last_contact_fail_hours:
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_fail_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
                fail_count += 1
            elif age_hours >= thresholds.last_contact_warn_hours:
                findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Engine '{name}' last contact {age_hours:.1f}h ago "
                        f"(threshold {thresholds.last_contact_warn_hours}h)"
                    ),
                    details={"id": engine.get("id"), "age_hours": round(age_hours, 1)},
                ))
                warn_count += 1

            if not sites:
                findings.append(Finding(
                    severity="warn",
                    message=f"Engine '{name}' is not paired with any sites",
                    details={"id": engine.get("id")},
                ))
                warn_count += 1

        total = len(engines)
        healthy = total - warn_count - fail_count
        # An engine can produce both an age finding and a pairing finding; healthy is bounded at >= 0.
        if healthy < 0:
            healthy = 0

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "engines_total": total,
                "engines_healthy": healthy,
                "engines_warn": warn_count,
                "engines_fail": fail_count,
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/checks/test_scan_engines.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/checks/scan_engines.py tests/checks/test_scan_engines.py
git commit -m "feat: add scan engines check"
```

---

## Task 7: Scan Activity check

**Files:**
- Create: `rapid7_healthcheck/checks/scan_activity.py`
- Test: `tests/checks/test_scan_activity.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/checks/test_scan_activity.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck


def _iso(days_ago: float = 0, hours_ago: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return t.isoformat().replace("+00:00", "Z")


def _site_scan(status: str, days_ago: float = 0, hours_ago: float = 0):
    return {"status": status, "startTime": _iso(days_ago, hours_ago), "id": 1}


def test_all_sites_healthy(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=1)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["sites_total"] == 1
    assert result.summary["sites_with_recent_scans"] == 1


def test_site_with_no_recent_scan_warns(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Stale"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=10)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    # 10 days > 7 (warn) but < 14 (fail) → warn
    assert result.status == "warn"


def test_site_with_no_scan_in_fail_window_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "VeryStale"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("finished", days_ago=30)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "fail"


def test_stuck_scan_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [_site_scan("running", hours_ago=48)], "page": {"totalPages": 1}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "fail"
    assert result.summary["stuck_scans_count"] == 1


def test_failed_scan_in_recent_window_warns(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {
            "resources": [
                _site_scan("finished", days_ago=1),
                _site_scan("failed", days_ago=2),
            ],
            "page": {"totalPages": 1},
        },
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert result.summary["failed_scans_count"] == 1


def test_site_with_zero_scans_fails(fake_client, app_config):
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Empty"}])
    fake_client.set_get(
        "/api/3/sites/1/scans",
        {"resources": [], "page": {"totalPages": 0}},
    )
    result = ScanActivityCheck().run(fake_client, app_config)
    # Never scanned at all → fail
    assert result.status == "fail"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/checks/test_scan_activity.py -v`
Expected: import error.

- [ ] **Step 3: Implement the check**

Create `rapid7_healthcheck/checks/scan_activity.py`:

```python
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


_FAILED_STATUSES = {"failed", "aborted", "stopped", "error"}
_MAX_FAILED_FINDINGS = 20


class ScanActivityCheck:
    name = "Scan Activity"
    description = "Recent scan success/failure, sites with no recent scans, and stuck scans."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.scan_activity
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(days=t.recent_window_days)
        fail_cutoff = now - timedelta(days=t.site_no_scan_days)
        stuck_cutoff = now - timedelta(hours=t.stuck_scan_hours)

        findings: list[Finding] = []
        sites_total = 0
        sites_with_recent = 0
        failed_count = 0
        stuck_count = 0
        failed_findings_emitted = 0

        for site in client.paginate("/api/3/sites"):
            sites_total += 1
            site_id = site.get("id")
            site_name = site.get("name", f"id={site_id}")
            body = client.get(
                f"/api/3/sites/{site_id}/scans",
                params={"sort": "startTime,DESC", "size": 20},
            )
            scans = body.get("resources", [])

            if not scans:
                findings.append(Finding(
                    severity="fail",
                    message=f"Site '{site_name}' has never been scanned",
                    details={"site_id": site_id},
                ))
                continue

            most_recent_finished = None
            for s in scans:
                start_time = _parse_iso(s.get("startTime"))
                status = (s.get("status") or "").lower()
                if start_time is None:
                    continue
                if status == "running" and start_time < stuck_cutoff:
                    age_h = (now - start_time).total_seconds() / 3600.0
                    findings.append(Finding(
                        severity="fail",
                        message=(
                            f"Site '{site_name}' has a scan running for {age_h:.1f}h "
                            f"(threshold {t.stuck_scan_hours}h)"
                        ),
                        details={"site_id": site_id, "scan_id": s.get("id"), "age_hours": round(age_h, 1)},
                    ))
                    stuck_count += 1
                if status in _FAILED_STATUSES and start_time >= recent_cutoff:
                    failed_count += 1
                    if failed_findings_emitted < _MAX_FAILED_FINDINGS:
                        findings.append(Finding(
                            severity="warn",
                            message=f"Site '{site_name}' had a {status} scan {start_time.isoformat()}",
                            details={"site_id": site_id, "scan_id": s.get("id"), "status": status},
                        ))
                        failed_findings_emitted += 1
                if status == "finished":
                    if most_recent_finished is None or start_time > most_recent_finished:
                        most_recent_finished = start_time

            if most_recent_finished is None:
                findings.append(Finding(
                    severity="fail",
                    message=f"Site '{site_name}' has no successful scans on record",
                    details={"site_id": site_id},
                ))
                continue

            if most_recent_finished < fail_cutoff:
                age_d = (now - most_recent_finished).days
                findings.append(Finding(
                    severity="fail",
                    message=(
                        f"Site '{site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.site_no_scan_days}d)"
                    ),
                    details={"site_id": site_id, "age_days": age_d},
                ))
            elif most_recent_finished < recent_cutoff:
                age_d = (now - most_recent_finished).days
                findings.append(Finding(
                    severity="warn",
                    message=(
                        f"Site '{site_name}' last scanned {age_d}d ago "
                        f"(threshold {t.recent_window_days}d)"
                    ),
                    details={"site_id": site_id, "age_days": age_d},
                ))
            else:
                sites_with_recent += 1

        if failed_count > failed_findings_emitted:
            findings.append(Finding(
                severity="warn",
                message=(
                    f"{failed_count - failed_findings_emitted} additional failed scans "
                    f"omitted from findings (capped at {_MAX_FAILED_FINDINGS})"
                ),
            ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "sites_total": sites_total,
                "sites_with_recent_scans": sites_with_recent,
                "failed_scans_count": failed_count,
                "stuck_scans_count": stuck_count,
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/checks/test_scan_activity.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/checks/scan_activity.py tests/checks/test_scan_activity.py
git commit -m "feat: add scan activity check"
```

---

## Task 8: Asset Coverage check

**Files:**
- Create: `rapid7_healthcheck/checks/asset_coverage.py`
- Test: `tests/checks/test_asset_coverage.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/checks/test_asset_coverage.py`:

```python
from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck


def _asset(host: str, asset_id: int = 1) -> dict:
    return {"id": asset_id, "hostName": host}


def test_all_assets_fresh(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    # second call (unscanned) — same path, but we'll re-set after first iteration via call hook
    # The check makes both calls in sequence; FakeRapid7Client serves the same list both times.
    # For this test we want an empty list both times.
    result = AssetCoverageCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["stale_count"] == 0
    assert result.summary["unscanned_count"] == 0


def test_stale_assets_warn(fake_client, app_config):
    # Replace fake client with one that returns different lists per body
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()

    # We need to differentiate the two POSTs. Override paginate_post with body-aware behavior.
    stale = [_asset(f"old-{i}", i) for i in range(3)]
    unscanned: list[dict] = []

    def paginate_post(path, json_body, params=None, page_size=500):
        fc.calls.append(("paginate_post", path, params, json_body))
        # Heuristic: filter referencing "is-empty" → unscanned, else stale
        text = str(json_body)
        if "is-empty" in text:
            yield from unscanned
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]

    result = AssetCoverageCheck().run(fc, app_config)
    assert result.status == "warn"
    assert result.summary["stale_count"] == 3


def test_unscanned_assets_fail(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    unscanned = [_asset(f"never-{i}", i) for i in range(2)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            yield from unscanned
        else:
            yield from []

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config)
    assert result.status == "fail"
    assert result.summary["unscanned_count"] == 2


def test_unscanned_check_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import AssetCoverageThresholds
    new_thresholds = replace(
        app_config.thresholds,
        asset_coverage=AssetCoverageThresholds(stale_asset_days=30, flag_unscanned_assets=False),
    )
    cfg = replace(app_config, thresholds=new_thresholds)

    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    fc.set_paginate_post("/api/3/assets/search", [])

    result = AssetCoverageCheck().run(fc, cfg)
    assert result.status == "pass"
    # Only the stale query should have run
    paginate_post_calls = [c for c in fc.calls if c[0] == "paginate_post"]
    assert len(paginate_post_calls) == 1


def test_top_10_examples_in_finding_details(fake_client, app_config):
    from tests.conftest import FakeRapid7Client
    fc = FakeRapid7Client()
    stale = [_asset(f"host-{i}", i) for i in range(25)]

    def paginate_post(path, json_body, params=None, page_size=500):
        text = str(json_body)
        if "is-empty" in text:
            yield from []
        else:
            yield from stale

    fc.paginate_post = paginate_post  # type: ignore[assignment]
    result = AssetCoverageCheck().run(fc, app_config)
    stale_finding = next(f for f in result.findings if "stale" in f.message.lower())
    assert stale_finding.details is not None
    examples = stale_finding.details["examples"]
    assert len(examples) == 10
    assert stale_finding.details["total"] == 25
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/checks/test_asset_coverage.py -v`
Expected: import error.

- [ ] **Step 3: Implement the check**

Create `rapid7_healthcheck/checks/asset_coverage.py`:

```python
from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class AssetCoverageCheck:
    name = "Asset Coverage"
    description = "Stale and never-scanned assets relative to configured thresholds."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.asset_coverage

        stale_filter = {
            "filters": [
                {
                    "field": "last-scan-date",
                    "operator": "is-earlier-than",
                    "value": t.stale_asset_days,
                }
            ],
            "match": "all",
        }
        stale = list(client.paginate_post("/api/3/assets/search", json_body=stale_filter))

        unscanned: list[dict] = []
        if t.flag_unscanned_assets:
            unscanned_filter = {
                "filters": [
                    {"field": "last-scan-date", "operator": "is-empty"}
                ],
                "match": "all",
            }
            unscanned = list(client.paginate_post("/api/3/assets/search", json_body=unscanned_filter))

        findings: list[Finding] = []
        if stale:
            findings.append(Finding(
                severity="warn",
                message=f"{len(stale)} stale asset(s) (no scan in last {t.stale_asset_days} days)",
                details={"total": len(stale), "examples": _example_hostnames(stale)},
            ))
        if unscanned:
            findings.append(Finding(
                severity="fail",
                message=f"{len(unscanned)} asset(s) have never been scanned",
                details={"total": len(unscanned), "examples": _example_hostnames(unscanned)},
            ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "stale_count": len(stale),
                "unscanned_count": len(unscanned),
                "total_assets": len(stale) + len(unscanned),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/checks/test_asset_coverage.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/checks/asset_coverage.py tests/checks/test_asset_coverage.py
git commit -m "feat: add asset coverage check"
```

---

## Task 9: Data Quality check

**Files:**
- Create: `rapid7_healthcheck/checks/data_quality.py`
- Test: `tests/checks/test_data_quality.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/checks/test_data_quality.py`:

```python
from __future__ import annotations

from dataclasses import replace

from rapid7_healthcheck.checks.data_quality import DataQualityCheck


def test_all_quality_good(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "pass"
    assert result.summary["missing_os_count"] == 0
    assert result.summary["empty_sites_count"] == 0


def test_missing_os_warns(fake_client, app_config):
    fake_client.set_paginate_post(
        "/api/3/assets/search",
        [{"id": 1, "hostName": "noos-1"}, {"id": 2, "hostName": "noos-2"}],
    )
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert result.summary["missing_os_count"] == 2


def test_empty_site_warns(fake_client, app_config):
    fake_client.set_paginate_post("/api/3/assets/search", [])
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Empty"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 0}})
    result = DataQualityCheck().run(fake_client, app_config)
    assert result.status == "warn"
    assert result.summary["empty_sites_count"] == 1


def test_missing_os_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import DataQualityThresholds
    new = replace(
        app_config.thresholds,
        data_quality=DataQualityThresholds(flag_missing_os=False, flag_empty_sites=True),
    )
    cfg = replace(app_config, thresholds=new)
    fake_client.set_paginate("/api/3/sites", [{"id": 1, "name": "Prod"}])
    fake_client.set_get("/api/3/sites/1/assets", {"resources": [], "page": {"totalResources": 5}})
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # paginate_post was never called
    assert not any(c[0] == "paginate_post" for c in fake_client.calls)


def test_empty_sites_skipped_when_disabled(fake_client, app_config):
    from rapid7_healthcheck.config import DataQualityThresholds
    new = replace(
        app_config.thresholds,
        data_quality=DataQualityThresholds(flag_missing_os=True, flag_empty_sites=False),
    )
    cfg = replace(app_config, thresholds=new)
    fake_client.set_paginate_post("/api/3/assets/search", [])
    result = DataQualityCheck().run(fake_client, cfg)
    assert result.status == "pass"
    # No site iteration
    assert not any(c[0] == "paginate" and c[1] == "/api/3/sites" for c in fake_client.calls)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/checks/test_data_quality.py -v`
Expected: import error.

- [ ] **Step 3: Implement the check**

Create `rapid7_healthcheck/checks/data_quality.py`:

```python
from __future__ import annotations

import time
from typing import Any

from rapid7_healthcheck.checks import CheckResult, Finding, rollup_status
from rapid7_healthcheck.config import AppConfig

_EXAMPLES_LIMIT = 10


def _example_hostnames(assets: list[dict]) -> list[str]:
    return [a.get("hostName") or a.get("ip") or f"id={a.get('id')}" for a in assets[:_EXAMPLES_LIMIT]]


class DataQualityCheck:
    name = "Data Quality"
    description = "Assets without OS fingerprint and sites with zero assets."

    def run(self, client: Any, config: AppConfig) -> CheckResult:
        start = time.monotonic()
        t = config.thresholds.data_quality
        findings: list[Finding] = []

        missing_os: list[dict] = []
        if t.flag_missing_os:
            missing_filter = {
                "filters": [{"field": "os-name", "operator": "is-empty"}],
                "match": "all",
            }
            missing_os = list(client.paginate_post("/api/3/assets/search", json_body=missing_filter))
            if missing_os:
                findings.append(Finding(
                    severity="warn",
                    message=f"{len(missing_os)} asset(s) have no OS fingerprint",
                    details={"total": len(missing_os), "examples": _example_hostnames(missing_os)},
                ))

        empty_sites: list[dict] = []
        if t.flag_empty_sites:
            for site in client.paginate("/api/3/sites"):
                site_id = site.get("id")
                body = client.get(f"/api/3/sites/{site_id}/assets", params={"size": 1})
                total = int(body.get("page", {}).get("totalResources", 0))
                if total == 0:
                    empty_sites.append(site)
            if empty_sites:
                findings.append(Finding(
                    severity="warn",
                    message=f"{len(empty_sites)} site(s) have zero assets",
                    details={
                        "total": len(empty_sites),
                        "examples": [s.get("name", f"id={s.get('id')}") for s in empty_sites[:_EXAMPLES_LIMIT]],
                    },
                ))

        return CheckResult(
            name=self.name,
            description=self.description,
            status=rollup_status(findings),
            findings=findings,
            summary={
                "missing_os_count": len(missing_os),
                "empty_sites_count": len(empty_sites),
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/checks/test_data_quality.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/checks/data_quality.py tests/checks/test_data_quality.py
git commit -m "feat: add data quality check"
```

---

## Task 10: Report renderer + template

**Files:**
- Create: `rapid7_healthcheck/templates/report.html.j2`
- Create: `rapid7_healthcheck/report.py`
- Test: `tests/test_report.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_report.py`:

```python
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rapid7_healthcheck.checks import CheckResult, Finding
from rapid7_healthcheck.report import ReportContext, render_report, write_report


def _ctx(results: list[CheckResult]) -> ReportContext:
    return ReportContext(
        title="Test Report",
        generated_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
        base_url_host="us.api.insight.rapid7.com",
        tool_version="0.1.0",
        config_path="config.yaml",
        results=results,
        thresholds_table=[("scan_engines.last_contact_warn_hours", "2")],
    )


def test_renders_pass_verdict_when_all_pass():
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert "Healthy" in html
    assert "Test Report" in html


def test_renders_warn_verdict_for_any_warn():
    r = CheckResult(
        name="X", description="x", status="warn",
        findings=[Finding(severity="warn", message="something")],
    )
    html = render_report(_ctx([r]))
    assert "Warnings" in html
    assert "something" in html


def test_renders_fail_verdict_for_any_fail():
    r = CheckResult(
        name="X", description="x", status="fail",
        findings=[Finding(severity="fail", message="boom")],
    )
    html = render_report(_ctx([r]))
    assert "Action required" in html


def test_error_status_includes_error_message():
    r = CheckResult(name="X", description="x", status="error", error="kaboom")
    html = render_report(_ctx([r]))
    assert "kaboom" in html


def test_skipped_status_explained():
    r = CheckResult(name="X", description="x", status="skipped")
    html = render_report(_ctx([r]))
    assert "skipped" in html.lower() or "disabled" in html.lower()


def test_no_external_resources():
    r = CheckResult(name="X", description="x", status="pass")
    html = render_report(_ctx([r]))
    assert "<script" not in html
    assert "https://cdn" not in html
    assert "//cdn" not in html


def test_write_report_uses_filename_pattern(tmp_path):
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    out = write_report(
        ctx,
        output_dir=tmp_path,
        filename_pattern="rapid7-health-{timestamp}.html",
    )
    assert out.parent == tmp_path
    assert out.name.startswith("rapid7-health-")
    assert out.suffix == ".html"
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_write_report_explicit_output_path(tmp_path):
    r = CheckResult(name="X", description="x", status="pass")
    ctx = _ctx([r])
    explicit = tmp_path / "fixed.html"
    out = write_report(ctx, explicit_path=explicit)
    assert out == explicit
    assert explicit.exists()


def test_finding_details_rendered_as_pretty_json():
    r = CheckResult(
        name="X", description="x", status="warn",
        findings=[Finding(severity="warn", message="m", details={"k": "v"})],
    )
    html = render_report(_ctx([r]))
    assert "\"k\":" in html
    assert "\"v\"" in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_report.py -v`
Expected: import error.

- [ ] **Step 3: Implement the template**

Create `rapid7_healthcheck/templates/report.html.j2`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
  :root {
    --bg: #ffffff;
    --fg: #1a1a1a;
    --muted: #666;
    --border: #ddd;
    --pass: #1f7a3a;
    --warn: #a86200;
    --fail: #a8331f;
    --skipped: #666;
    --pass-bg: #e8f5ec;
    --warn-bg: #fcf3e3;
    --fail-bg: #fbe9e7;
    --skipped-bg: #f0f0f0;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         color: var(--fg); background: var(--bg); margin: 2rem auto; max-width: 1100px; padding: 0 1.5rem; }
  h1 { margin: 0 0 0.5rem 0; font-size: 1.6rem; }
  .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
  .meta span { margin-right: 1.2rem; }
  .verdict { padding: 1rem 1.25rem; border-radius: 8px; font-weight: 600; font-size: 1.2rem; margin: 1rem 0 1.5rem; }
  .verdict.pass { background: var(--pass-bg); color: var(--pass); }
  .verdict.warn { background: var(--warn-bg); color: var(--warn); }
  .verdict.fail { background: var(--fail-bg); color: var(--fail); }
  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; }
  th, td { text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:nth-child(even) { background: #fafafa; }
  .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .badge.pass { background: var(--pass-bg); color: var(--pass); }
  .badge.warn { background: var(--warn-bg); color: var(--warn); }
  .badge.fail { background: var(--fail-bg); color: var(--fail); }
  .badge.error { background: var(--fail-bg); color: var(--fail); }
  .badge.skipped { background: var(--skipped-bg); color: var(--skipped); }
  section.check { margin: 2rem 0; page-break-inside: avoid; }
  section.check h2 { margin: 0 0 0.25rem 0; font-size: 1.2rem; }
  .check-desc { color: var(--muted); margin: 0 0 0.75rem 0; }
  .tiles { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.75rem 0 1rem; }
  .tile { background: #f6f6f6; border: 1px solid var(--border); padding: 0.4rem 0.7rem; border-radius: 6px; font-size: 0.85rem; }
  .tile b { display: block; font-size: 1rem; }
  .error-box { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--fail); padding: 0.75rem 1rem; border-radius: 6px; }
  .skipped-box { background: var(--skipped-bg); color: var(--skipped); border: 1px solid var(--border); padding: 0.75rem 1rem; border-radius: 6px; }
  details { margin: 0.25rem 0; }
  pre { background: #f4f4f4; padding: 0.5rem 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; }
  footer { color: var(--muted); font-size: 0.85rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }
  a { color: var(--fg); }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<div class="meta">
  <span><b>Generated:</b> {{ generated_at_local }} ({{ generated_at_utc }} UTC)</span>
  <span><b>Console:</b> {{ base_url_host }}</span>
  <span><b>Version:</b> {{ tool_version }}</span>
</div>

<div class="verdict {{ verdict_class }}">{{ verdict_label }}</div>

<h2>Summary</h2>
<table>
  <thead>
    <tr><th>Check</th><th>Status</th><th>Findings</th><th>Duration</th></tr>
  </thead>
  <tbody>
  {% for r in results %}
    <tr>
      <td><a href="#check-{{ loop.index }}">{{ r.name }}</a></td>
      <td><span class="badge {{ r.status }}">{{ r.status|upper }}</span></td>
      <td>{{ r.findings|length }} ({{ r.findings|selectattr('severity','equalto','fail')|list|length }} fail / {{ r.findings|selectattr('severity','equalto','warn')|list|length }} warn)</td>
      <td>{{ r.duration_ms }} ms</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

{% for r in results %}
<section class="check" id="check-{{ loop.index }}">
  <h2>{{ r.name }} <span class="badge {{ r.status }}">{{ r.status|upper }}</span></h2>
  <p class="check-desc">{{ r.description }}</p>

  {% if r.status == "error" %}
    <div class="error-box"><b>Check failed to run:</b> {{ r.error }}</div>
  {% elif r.status == "skipped" %}
    <div class="skipped-box">This check is disabled in <code>config.yaml</code>.</div>
  {% else %}
    {% if r.summary %}
    <div class="tiles">
      {% for k, v in r.summary.items() %}
        <div class="tile"><b>{{ v }}</b>{{ k }}</div>
      {% endfor %}
    </div>
    {% endif %}

    {% if r.findings %}
    <table>
      <thead><tr><th>Severity</th><th>Message</th></tr></thead>
      <tbody>
      {% for f in r.findings %}
        <tr>
          <td><span class="badge {{ 'fail' if f.severity == 'fail' else 'warn' if f.severity == 'warn' else 'pass' }}">{{ f.severity|upper }}</span></td>
          <td>
            {{ f.message }}
            {% if f.details %}
              <details><summary>details</summary><pre>{{ f.details_json }}</pre></details>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
      <p>No issues found.</p>
    {% endif %}
  {% endif %}
</section>
{% endfor %}

<footer>
  <p>Config: <code>{{ config_path }}</code></p>
  {% if thresholds_table %}
  <p>Thresholds applied:</p>
  <table>
    <thead><tr><th>Setting</th><th>Value</th></tr></thead>
    <tbody>
    {% for key, value in thresholds_table %}
      <tr><td><code>{{ key }}</code></td><td>{{ value }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
</footer>
</body>
</html>
```

- [ ] **Step 4: Implement the renderer**

Create `rapid7_healthcheck/report.py`:

```python
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rapid7_healthcheck.checks import CheckResult, Finding


_TEMPLATE_DIR = Path(__file__).parent / "templates"


@dataclass
class ReportContext:
    title: str
    generated_at: datetime
    base_url_host: str
    tool_version: str
    config_path: str
    results: list[CheckResult]
    thresholds_table: list[tuple[str, str]] = field(default_factory=list)


def _verdict(results: list[CheckResult]) -> tuple[str, str]:
    if any(r.status in ("fail", "error") for r in results):
        return ("fail", "Action required")
    if any(r.status == "warn" for r in results):
        return ("warn", "Warnings")
    return ("pass", "Healthy")


def _annotate_findings(results: list[CheckResult]) -> None:
    """Attach a pre-serialized JSON string for each finding's details."""
    for r in results:
        for f in r.findings:
            if f.details is not None:
                # Pre-serialize so the template stays simple and safe (autoescape escapes the string).
                object.__setattr__(f, "details_json", json.dumps(f.details, indent=2, default=str))
            else:
                object.__setattr__(f, "details_json", "")


def render_report(ctx: ReportContext) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    template = env.get_template("report.html.j2")
    _annotate_findings(ctx.results)
    verdict_class, verdict_label = _verdict(ctx.results)
    generated_at_utc = ctx.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return template.render(
        title=ctx.title,
        generated_at_utc=ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        generated_at_local=generated_at_utc,
        base_url_host=ctx.base_url_host,
        tool_version=ctx.tool_version,
        config_path=ctx.config_path,
        results=ctx.results,
        thresholds_table=ctx.thresholds_table,
        verdict_class=verdict_class,
        verdict_label=verdict_label,
    )


def write_report(
    ctx: ReportContext,
    *,
    output_dir: Path | None = None,
    filename_pattern: str | None = None,
    explicit_path: Path | None = None,
) -> Path:
    html = render_report(ctx)
    if explicit_path is not None:
        explicit_path.parent.mkdir(parents=True, exist_ok=True)
        explicit_path.write_text(html, encoding="utf-8")
        return explicit_path

    assert output_dir is not None and filename_pattern is not None
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = filename_pattern.replace("{timestamp}", timestamp)
    out = output_dir / filename
    out.write_text(html, encoding="utf-8")
    return out
```

Note on the `Finding` mutation: `Finding` is `frozen=True`, so `object.__setattr__` is used to attach the `details_json` attribute for templating. This is intentional and isolated to the renderer; downstream code does not rely on `Finding` immutability.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: 9 passed.

- [ ] **Step 6: Commit**

```bash
git add rapid7_healthcheck/templates/report.html.j2 rapid7_healthcheck/report.py tests/test_report.py
git commit -m "feat: add Jinja2 HTML report renderer"
```

---

## Task 11: Orchestrator and CLI (`__main__.py`)

**Files:**
- Create: `rapid7_healthcheck/__main__.py`
- Test: `tests/test_main.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_main.py`:

```python
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from rapid7_healthcheck.__main__ import (
    EXIT_FAIL,
    EXIT_HEALTHY,
    EXIT_STARTUP,
    EXIT_WARN,
    build_thresholds_table,
    pick_exit_code,
    run,
)
from rapid7_healthcheck.checks import CheckResult


def _write_config(tmp_path: Path, base_url: str = "https://us.api.insight.rapid7.com") -> Path:
    body = textwrap.dedent(f"""
        rapid7:
          base_url: {base_url}
          verify_tls: true
          request_timeout_seconds: 30
          max_retries: 3
        report:
          output_dir: {tmp_path / "reports"}
          filename_pattern: "rapid7-health-{{timestamp}}.html"
          title: "T"
        thresholds:
          scan_engines:
            last_contact_warn_hours: 2
            last_contact_fail_hours: 24
          scan_activity:
            recent_window_days: 7
            stuck_scan_hours: 24
            site_no_scan_days: 14
          asset_coverage:
            stale_asset_days: 30
            flag_unscanned_assets: true
          data_quality:
            flag_missing_os: true
            flag_empty_sites: true
        checks:
          scan_engines: false
          scan_activity: false
          asset_coverage: false
          data_quality: false
    """).strip()
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_pick_exit_code_healthy():
    assert pick_exit_code([CheckResult(name="x", description="d", status="pass")]) == EXIT_HEALTHY


def test_pick_exit_code_warn():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="warn"),
        CheckResult(name="y", description="d", status="pass"),
    ]) == EXIT_WARN


def test_pick_exit_code_fail():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="fail"),
    ]) == EXIT_FAIL


def test_pick_exit_code_error_treated_as_fail():
    assert pick_exit_code([
        CheckResult(name="x", description="d", status="error", error="boom"),
    ]) == EXIT_FAIL


def test_run_missing_api_key_returns_startup_exit(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.delenv("R7_API_KEY", raising=False)
    code = run(["--config", str(cfg)])
    assert code == EXIT_STARTUP


def test_run_with_all_checks_disabled_writes_skipped_report(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("R7_API_KEY", "k")

    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        instance = MockClient.return_value
        instance.connect.return_value = None
        code = run(["--config", str(cfg)])

    assert code == EXIT_HEALTHY
    reports = list((tmp_path / "reports").glob("rapid7-health-*.html"))
    assert len(reports) == 1
    html = reports[0].read_text(encoding="utf-8")
    assert "SKIPPED" in html


def test_run_explicit_output_path(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("R7_API_KEY", "k")
    out = tmp_path / "fixed.html"
    with patch("rapid7_healthcheck.__main__.Rapid7Client") as MockClient:
        MockClient.return_value.connect.return_value = None
        code = run(["--config", str(cfg), "--output", str(out)])
    assert code == EXIT_HEALTHY
    assert out.exists()


def test_run_bad_config_returns_startup_exit(tmp_path, monkeypatch):
    bad = tmp_path / "missing.yaml"
    monkeypatch.setenv("R7_API_KEY", "k")
    code = run(["--config", str(bad)])
    assert code == EXIT_STARTUP


def test_build_thresholds_table_includes_all_keys():
    from rapid7_healthcheck.config import (
        AppConfig, AssetCoverageThresholds, DataQualityThresholds,
        Rapid7Config, ReportConfig, ScanActivityThresholds,
        ScanEngineThresholds, Thresholds,
    )
    cfg = AppConfig(
        rapid7=Rapid7Config(base_url="https://x", verify_tls=True, request_timeout_seconds=30, max_retries=3),
        report=ReportConfig(output_dir=".", filename_pattern="x", title="t"),
        thresholds=Thresholds(
            scan_engines=ScanEngineThresholds(2, 24),
            scan_activity=ScanActivityThresholds(7, 24, 14),
            asset_coverage=AssetCoverageThresholds(30, True),
            data_quality=DataQualityThresholds(True, True),
        ),
        checks={"scan_engines": True, "scan_activity": True, "asset_coverage": True, "data_quality": True},
    )
    table = build_thresholds_table(cfg)
    keys = [k for k, _ in table]
    assert "scan_engines.last_contact_warn_hours" in keys
    assert "asset_coverage.stale_asset_days" in keys
    assert "data_quality.flag_empty_sites" in keys
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_main.py -v`
Expected: import error.

- [ ] **Step 3: Implement the orchestrator**

Create `rapid7_healthcheck/__main__.py`:

```python
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

from rapid7_healthcheck import __version__
from rapid7_healthcheck.checks import Check, CheckResult
from rapid7_healthcheck.checks.asset_coverage import AssetCoverageCheck
from rapid7_healthcheck.checks.data_quality import DataQualityCheck
from rapid7_healthcheck.checks.scan_activity import ScanActivityCheck
from rapid7_healthcheck.checks.scan_engines import ScanEnginesCheck
from rapid7_healthcheck.client import Rapid7AuthError, Rapid7Client, Rapid7ClientError
from rapid7_healthcheck.config import AppConfig, ConfigError, load_config
from rapid7_healthcheck.report import ReportContext, write_report


EXIT_HEALTHY = 0
EXIT_WARN = 1
EXIT_FAIL = 2
EXIT_STARTUP = 3
EXIT_INTERNAL = 4

logger = logging.getLogger("rapid7_healthcheck")


_REGISTRY: dict[str, type[Check]] = {
    "scan_engines": ScanEnginesCheck,
    "scan_activity": ScanActivityCheck,
    "asset_coverage": AssetCoverageCheck,
    "data_quality": DataQualityCheck,
}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rapid7-healthcheck")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    p.add_argument("--output", default=None, help="Override report output path")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    p.add_argument("--log-file", default=None, help="Also write logs to this file")
    return p.parse_args(argv)


def _setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def build_thresholds_table(cfg: AppConfig) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for section_name in ("scan_engines", "scan_activity", "asset_coverage", "data_quality"):
        section = getattr(cfg.thresholds, section_name)
        for f in fields(section):
            value = getattr(section, f.name)
            rows.append((f"{section_name}.{f.name}", str(value)))
    return rows


def pick_exit_code(results: list[CheckResult]) -> int:
    if any(r.status in ("fail", "error") for r in results):
        return EXIT_FAIL
    if any(r.status == "warn" for r in results):
        return EXIT_WARN
    return EXIT_HEALTHY


def _run_checks(client: Any, cfg: AppConfig) -> list[CheckResult]:
    results: list[CheckResult] = []
    for name, check_cls in _REGISTRY.items():
        enabled = cfg.checks.get(name, False)
        if not enabled:
            instance = check_cls()
            results.append(CheckResult(
                name=instance.name,
                description=instance.description,
                status="skipped",
            ))
            continue
        instance = check_cls()
        logger.info("running check: %s", instance.name)
        start = time.monotonic()
        try:
            results.append(instance.run(client, cfg))
        except Exception as e:  # per-check isolation
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception("check %s failed", instance.name)
            results.append(CheckResult(
                name=instance.name,
                description=instance.description,
                status="error",
                error=str(e),
                duration_ms=duration_ms,
            ))
    return results


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _setup_logging(args.verbose, args.log_file)
    load_dotenv(override=False)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("config error: %s", e)
        return EXIT_STARTUP

    api_key = os.environ.get("R7_API_KEY")
    if not api_key:
        logger.error("R7_API_KEY environment variable is not set")
        return EXIT_STARTUP

    if not cfg.rapid7.verify_tls:
        logger.warning("TLS verification disabled (verify_tls: false)")

    try:
        client = Rapid7Client(
            base_url=cfg.rapid7.base_url,
            api_key=api_key,
            verify_tls=cfg.rapid7.verify_tls,
            timeout_seconds=cfg.rapid7.request_timeout_seconds,
            max_retries=cfg.rapid7.max_retries,
        )
        client.connect()
    except Rapid7AuthError as e:
        logger.error("authentication failed: %s", e)
        return EXIT_STARTUP
    except Rapid7ClientError as e:
        logger.error("could not reach Rapid7 (%s); check base_url and network", e)
        return EXIT_STARTUP

    results = _run_checks(client, cfg)

    ctx = ReportContext(
        title=cfg.report.title,
        generated_at=datetime.now(timezone.utc),
        base_url_host=urlparse(cfg.rapid7.base_url).hostname or cfg.rapid7.base_url,
        tool_version=__version__,
        config_path=str(args.config),
        results=results,
        thresholds_table=build_thresholds_table(cfg),
    )

    if args.output:
        out = write_report(ctx, explicit_path=Path(args.output))
    else:
        out = write_report(
            ctx,
            output_dir=Path(cfg.report.output_dir),
            filename_pattern=cfg.report.filename_pattern,
        )

    print(out.resolve())
    return pick_exit_code(results)


def main() -> None:
    try:
        sys.exit(run())
    except Exception:
        logger.exception("internal error")
        sys.exit(EXIT_INTERNAL)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_main.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add rapid7_healthcheck/__main__.py tests/test_main.py
git commit -m "feat: add CLI orchestrator with exit codes"
```

---

## Task 12: README and end-to-end sanity

**Files:**
- Create: `README.md`

- [ ] **Step 1: Run the full test suite**

Run: `pytest -v`
Expected: all tests pass (config, client, report, main, four checks). No skipped tests.

- [ ] **Step 2: Smoke-test the CLI without an API key**

Run: `python -m rapid7_healthcheck --config config.example.yaml`
Expected: exit code 3, log message about missing `R7_API_KEY`. No report written.

- [ ] **Step 3: Smoke-test with all checks disabled**

Create `tmp_config.yaml` (copy of `config.example.yaml` with all four `checks:` flags set to `false`), then:

Run: `R7_API_KEY=dummy python -m rapid7_healthcheck --config tmp_config.yaml --output /tmp/r7.html` (Windows: `set R7_API_KEY=dummy && python -m rapid7_healthcheck --config tmp_config.yaml --output %TEMP%\r7.html`)
Expected: exit code 3 (real connect to `us.api.insight.rapid7.com` will fail with `dummy` key — that's fine; the goal here is to confirm the startup path runs end-to-end).

To get a successful end-to-end smoke test: temporarily replace `Rapid7Client` import in a throwaway script, OR run with a real key against the real environment. The unit tests already cover the success path with mocks, so this manual step is optional.

Delete `tmp_config.yaml` after.

- [ ] **Step 4: Create `README.md`**

```markdown
# Rapid7 InsightVM Health Check

Read-only health check for a Rapid7 InsightVM environment. Calls the Insight Platform API with a read-only API key and produces a single self-contained HTML report.

## Requirements

- Python 3.11+
- Network access to your Insight Platform region URL (e.g. `https://us.api.insight.rapid7.com`)
- A read-only Insight Platform API key

## Setup

1. Generate a read-only API key in the Insight Platform UI: **User → API Keys → New User Key**. Pin the role to read-only.
2. Clone this repo and create a virtualenv:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate     # Windows
   source .venv/bin/activate    # macOS/Linux
   pip install -e .
   ```

3. Configure:

   ```bash
   cp .env.example .env
   # edit .env and set R7_API_KEY=<your key>

   cp config.example.yaml config.yaml
   # edit config.yaml — at minimum set rapid7.base_url to the right region
   ```

   US data centres: `https://us.api.insight.rapid7.com`, `https://us2.api.insight.rapid7.com`, `https://us3.api.insight.rapid7.com`. Pick the one that matches your account.

## Usage

```bash
python -m rapid7_healthcheck
```

Optional flags:

- `--config <path>` — config file (default `./config.yaml`)
- `--output <path>` — write the report to a specific path (overrides the configured filename pattern)
- `--verbose` — DEBUG logging
- `--log-file <path>` — also write logs to a file

The CLI prints the absolute path of the written report on success.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Healthy — all checks pass |
| 1 | Warnings — at least one `warn`, no `fail`/`error` |
| 2 | Action required — at least one `fail` or `error` |
| 3 | Startup failure — bad config, missing API key, auth failed, network unreachable |
| 4 | Internal error in the tool |

## Scheduling

**Windows Task Scheduler (PowerShell):**

```powershell
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "-m rapid7_healthcheck --config C:\path\to\config.yaml" -WorkingDirectory "C:\path\to\Rapid7-HealthCheck"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "Rapid7 HealthCheck" -Action $action -Trigger $trigger
```

**cron (daily at 06:00):**

```
0 6 * * * cd /path/to/Rapid7-HealthCheck && /path/to/.venv/bin/python -m rapid7_healthcheck >> /var/log/rapid7-healthcheck.log 2>&1
```

## Tuning thresholds

All thresholds live in `config.yaml` under `thresholds:`. Every report footer prints the thresholds applied so it's obvious what to tune.

- `scan_engines.last_contact_warn_hours` / `last_contact_fail_hours` — how long without engine contact before warn/fail.
- `scan_activity.recent_window_days` — what counts as "recent".
- `scan_activity.site_no_scan_days` — when no scan in this window becomes a fail.
- `scan_activity.stuck_scan_hours` — a running scan older than this is flagged as stuck.
- `asset_coverage.stale_asset_days` — assets not scanned in this window are stale.
- `asset_coverage.flag_unscanned_assets` — also list assets that have never been scanned.
- `data_quality.flag_missing_os` / `flag_empty_sites` — toggle data quality sub-checks.

You can also disable an entire check by setting its toggle in `checks:` to `false` — it appears in the report as `SKIPPED`.

## Troubleshooting

- **401 / 403 at startup**: API key wrong, expired, or lacks read scopes. Re-issue the key.
- **Connection refused / DNS error at startup**: the `base_url` likely points to the wrong region or US data centre. Try `us2` / `us3` / `eu` etc.
- **All checks return `SKIPPED`**: every toggle in `checks:` is `false` in `config.yaml`.
- **Specific check shows `ERROR`**: the per-check exception message appears in the report. Run with `--verbose --log-file run.log` to capture the full traceback.

## Development

```bash
pip install -e .[dev]
pytest -v
```

## What this tool does NOT do

- Modify any state in Rapid7 (no scans started, no sites created).
- Check things the cloud API does not expose (license status, console build version, content/vuln-definitions update freshness).
- Send notifications. Pipe the exit code into your own notifier or watch the report directory.
```

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

- [ ] **Step 6: Final check — full suite green and clean working tree**

Run: `pytest -v && git status`
Expected: all tests pass; `git status` reports a clean tree.

---

## Self-review

**Spec coverage:** every spec section has at least one task — §3 inputs/outputs/exit codes (Task 11), §4 architecture (Tasks 3–11), §5 config (Task 2), §6 client (Task 4), §7 each check (Tasks 6–9), §8 report (Task 10), §9 logging (Task 11), §10 errors (Tasks 4 + 11), §11 layout (Task 1), §12 deps (Task 1), §13 tests (every implementation task), §14 README (Task 12).

**Placeholder scan:** no TODO/TBD strings in the plan. Every code step has complete code. Tests use real assertions, not pseudo-code.

**Type consistency:** `Finding` and `CheckResult` defined once in Task 3 and used unchanged in Tasks 6–11. `Rapid7Client` method names (`get`, `post`, `paginate`, `paginate_post`, `connect`) match between Task 4 (definition) and Task 5 (`FakeRapid7Client`) and Tasks 6–9 (consumers). `AppConfig`/`Thresholds` field names match between Task 2 (definition), Task 5 (fixture), and Tasks 6–9 (consumers). Exit-code constants (`EXIT_HEALTHY` etc.) are defined and used only in Task 11.

**Note on integration test:** the spec mentions an optional integration test (§13). It's not in the plan because it requires real credentials; the README explains how to invoke a real run end-to-end manually. If you want one wired up later, it's a 20-line addition in `tests/test_integration.py` that skips unless `R7_API_KEY` and `R7_BASE_URL` are set. Flagging here so it's not lost.
