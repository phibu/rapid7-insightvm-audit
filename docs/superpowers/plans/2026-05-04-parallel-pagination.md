# Parallel Pagination + Default Tuning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in parallel page fetching to `Rapid7Client.paginate` / `paginate_post` (default off), bump default page size 500→250, bump default request timeout 30s→60s. Read-only contract unchanged.

**Architecture:** Two-phase walk inside `_paginate`: Phase 1 fetches page 0 sequentially (probes `totalPages`), Phase 2 fetches pages 1..N-1 concurrently in batches via a `concurrent.futures.ThreadPoolExecutor` local to the call. In-order yield contract preserved by collecting futures into a `dict[int, list[dict]]` keyed on page index and yielding in page order. Sequential fast path when `parallel_pages == 1`. Configuration flows from `config.yaml` (`rapid7.parallel_pages`, `rapid7.page_size`) through `Rapid7Config` → `Rapid7Client.__init__` → `_paginate`. Per-call kwarg override available on `paginate` / `paginate_post`. Fail-fast on first error via `executor.shutdown(wait=False, cancel_futures=True)`.

**Tech Stack:** Python 3.11+, `requests` (existing), `concurrent.futures.ThreadPoolExecutor` (stdlib), `pytest`, `pyyaml`.

**Spec:** [docs/superpowers/specs/2026-05-04-parallel-pagination-design.md](../specs/2026-05-04-parallel-pagination-design.md)

---

## File map

| File | Why |
|------|-----|
| `src/rapid7_healthcheck/client.py` | Bump `timeout_seconds` default to 60. Add `parallel_pages` and `default_page_size` ctor kwargs. Rewrite `_paginate` with two-phase walk + parallel batch helper. Add `parallel_pages` kwarg to `paginate` / `paginate_post`. |
| `src/rapid7_healthcheck/config.py` | Add `parallel_pages` and `page_size` fields to `Rapid7Config`. Validator updates. Bump `request_timeout_seconds` example default to 60 (no schema change -- already int). |
| `src/rapid7_healthcheck/__main__.py` | Thread the two new config fields into `Rapid7Client(...)`. |
| `tests/test_client.py` | 3 new tests (in-order yield, fail-fast, sequential default). |
| `tests/test_config.py` | 2 new tests (validator bounds for `parallel_pages` + `page_size`, default-timeout assertion). |
| `docs/examples/config.yaml` | Add the two new keys with comments; bump `request_timeout_seconds: 30` → `60`. |
| `README.md` | Troubleshooting bullet on `parallel_pages` and updated timeout sentence. |
| `CLAUDE.md` | One-sentence note in Layer rules about `_paginate` thread-safety. |
| `CHANGELOG.md` | `[Unreleased]` entry covering all three changes; mark page_size + timeout default-bumps as user-visible. |

---

## Task 1: Add `Rapid7Config.parallel_pages` + `page_size` schema

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:18-25` (`Rapid7Config` dataclass)
- Modify: `src/rapid7_healthcheck/config.py:239-285` (`_build_rapid7_config` validator)
- Test: `tests/test_config.py`

- [ ] **Step 1: Write failing test for `parallel_pages` validation bounds**

Append to `tests/test_config.py`:

```python
def test_rapid7_parallel_pages_default_is_one(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml())  # uses existing helper if present; else inline
    cfg = load_config(str(cfg_path))
    assert cfg.rapid7.parallel_pages == 1


def test_rapid7_parallel_pages_accepts_six(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(parallel_pages=6))
    cfg = load_config(str(cfg_path))
    assert cfg.rapid7.parallel_pages == 6


def test_rapid7_parallel_pages_rejects_zero(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(parallel_pages=0))
    with pytest.raises(ConfigError, match="parallel_pages"):
        load_config(str(cfg_path))


def test_rapid7_parallel_pages_rejects_seventeen(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(parallel_pages=17))
    with pytest.raises(ConfigError, match="parallel_pages"):
        load_config(str(cfg_path))


def test_rapid7_parallel_pages_nine_warns(tmp_path, caplog):
    """Values >8 are accepted but emit a warning log line."""
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(parallel_pages=9))
    with caplog.at_level("WARNING"):
        cfg = load_config(str(cfg_path))
    assert cfg.rapid7.parallel_pages == 9
    assert any("8-parallel" in r.message for r in caplog.records)


def test_rapid7_page_size_default_is_250(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml())
    cfg = load_config(str(cfg_path))
    assert cfg.rapid7.page_size == 250


def test_rapid7_page_size_rejects_zero(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(page_size=0))
    with pytest.raises(ConfigError, match="page_size"):
        load_config(str(cfg_path))


def test_rapid7_page_size_rejects_501(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_minimal_config_yaml(page_size=501))
    with pytest.raises(ConfigError, match="page_size"):
        load_config(str(cfg_path))
```

If `_minimal_config_yaml` does not already exist in `tests/test_config.py`, add this helper at the top of the file (after imports):

```python
def _minimal_config_yaml(*, parallel_pages: int | None = None, page_size: int | None = None) -> str:
    extras = []
    if parallel_pages is not None:
        extras.append(f"  parallel_pages: {parallel_pages}")
    if page_size is not None:
        extras.append(f"  page_size: {page_size}")
    extras_str = ("\n" + "\n".join(extras)) if extras else ""
    return f"""\
rapid7:
  base_url: "https://example.test"
  verify_tls: true
  request_timeout_seconds: 60
  max_retries: 3{extras_str}
report:
  output_dir: "."
  filename_pattern: "report-{{ts}}.html"
  title: "Test"
checks:
  scan_engine_health: false
  scan_activity: false
  asset_coverage: false
  data_quality: false
  configuration_audit: false
thresholds:
  scan_engines:
    last_contact_warn_hours: 24
    last_contact_fail_hours: 72
  scan_activity:
    recent_window_days: 7
    stuck_scan_hours: 24
    site_no_scan_days: 30
  asset_coverage:
    stale_asset_days: 30
    flag_unscanned_assets: true
    never_scanned_days: 90
  data_quality:
    flag_missing_os: true
    flag_empty_sites: true
"""
```

(If a similar helper or fixture already exists, reuse it and add only the two kwargs.)

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_config.py -v -k "parallel_pages or page_size"`
Expected: FAIL with `AttributeError: 'Rapid7Config' object has no attribute 'parallel_pages'` (or similar) for the default tests, and `KeyError`/no-error for the rejection tests (since the validator doesn't know the keys yet).

- [ ] **Step 3: Add fields to `Rapid7Config` dataclass**

In `src/rapid7_healthcheck/config.py`, replace the `Rapid7Config` dataclass (lines 18-25):

```python
@dataclass(frozen=True)
class Rapid7Config:
    base_url: str
    verify_tls: bool
    request_timeout_seconds: int
    max_retries: int
    auth_mode: str = "api_key"
    parallel_pages: int = 1
    page_size: int = 250
```

- [ ] **Step 4: Update `_build_rapid7_config` validator**

In `src/rapid7_healthcheck/config.py`, locate `_build_rapid7_config` (currently around line 239). Update the function so:

1. The `allowed` keys set includes `"parallel_pages"` and `"page_size"`.
2. After the existing scalar checks, add bounds validation. The new block goes immediately before the `return Rapid7Config(...)` statement (around line 277):

```python
parallel_pages = data.get("parallel_pages", 1)
_check_scalar("parallel_pages", parallel_pages, int, "rapid7")
if not (1 <= parallel_pages <= 16):
    raise ConfigError(
        f"rapid7.parallel_pages must be in range [1, 16]; got {parallel_pages}"
    )
if parallel_pages > 8:
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "rapid7.parallel_pages=%d exceeds the documented InsightVM "
        "8-parallel-request limit; proceed at your own risk",
        parallel_pages,
    )

page_size = data.get("page_size", 250)
_check_scalar("page_size", page_size, int, "rapid7")
if not (1 <= page_size <= 500):
    raise ConfigError(
        f"rapid7.page_size must be in range [1, 500]; got {page_size}"
    )
```

Then update the `return Rapid7Config(...)` call to pass the new fields:

```python
return Rapid7Config(
    base_url=data["base_url"],
    verify_tls=data["verify_tls"],
    request_timeout_seconds=data["request_timeout_seconds"],
    max_retries=data["max_retries"],
    auth_mode=data.get("auth_mode", "api_key"),
    parallel_pages=parallel_pages,
    page_size=page_size,
)
```

If the existing `allowed = {...}` set in this function is explicit, add the two new keys to it. If `_validate_dict_schema` is used, ensure the optional-keys list includes them.

- [ ] **Step 5: Run tests and verify they pass**

Run: `pytest tests/test_config.py -v -k "parallel_pages or page_size"`
Expected: all 7 new tests PASS.

- [ ] **Step 6: Run full config test suite to check for regressions**

Run: `pytest tests/test_config.py -v`
Expected: every test passes, including pre-existing ones.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "feat(config): add rapid7.parallel_pages and rapid7.page_size

Adds two new optional config fields with validation:
- parallel_pages: int 1..16, default 1 (sequential, today's behavior)
- page_size: int 1..500, default 250 (down from 500 to ease timeouts)

No behavior change yet -- fields wired through Rapid7Config but the
client and __main__ still use today's hardcoded defaults. Follow-up
tasks thread these into Rapid7Client and _paginate.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Bump `Rapid7Client` default timeout 30→60 + accept new ctor kwargs

**Files:**
- Modify: `src/rapid7_healthcheck/client.py:88-115` (`Rapid7Client.__init__`)
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing test for new constructor defaults**

Append to `tests/test_client.py`:

```python
def test_client_default_timeout_is_60_seconds(session):
    """Default request timeout is 60s (was 30s in v0.2.7)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._timeout == 60


def test_client_default_parallel_pages_is_one(session):
    """Default parallel_pages is 1 (sequential -- preserves today's behavior)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._parallel_pages == 1


def test_client_default_page_size_is_250(session):
    """Default paginated page size is 250 (was 500 in v0.2.7)."""
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        session=session,
    )
    assert c._default_page_size == 250


def test_client_accepts_parallel_pages_kwarg(session):
    c = Rapid7Client(
        base_url="https://example.test",
        api_key="k",
        parallel_pages=6,
        session=session,
    )
    assert c._parallel_pages == 6
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_client.py -v -k "default_timeout or default_parallel or default_page_size or accepts_parallel_pages"`
Expected: FAIL -- `_timeout == 30`, `_parallel_pages` and `_default_page_size` attrs don't exist, ctor rejects `parallel_pages` kwarg.

- [ ] **Step 3: Update constructor signature and body**

In `src/rapid7_healthcheck/client.py`, replace `Rapid7Client.__init__` (currently lines 89-115) with:

```python
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
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_client.py -v -k "default_timeout or default_parallel or default_page_size or accepts_parallel_pages"`
Expected: all 4 new tests PASS.

- [ ] **Step 5: Run full client test suite**

Run: `pytest tests/test_client.py -v`
Expected: every test passes. The `make_client` helper passes `timeout_seconds=5` explicitly, so the default-60 change does not break existing tests.

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/client.py tests/test_client.py
git commit -m "feat(client): default timeout 30->60s; add parallel_pages + default_page_size kwargs

Bumps the baked-in request timeout default from 30s to 60s -- matches
the README troubleshooting guidance for hosted consoles where the old
default was too tight.

Adds two new constructor kwargs (parallel_pages, default_page_size)
both stored on the instance for use by _paginate. Defaults preserve
today's behavior: parallel_pages=1 (sequential), default_page_size=250
(down from 500). Bounds validated at construction.

No paginate() change yet -- that lands in the next task.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Implement parallel page fetching in `_paginate`

**Files:**
- Modify: `src/rapid7_healthcheck/client.py:129-188` (`paginate`, `paginate_post`, `_paginate`)
- Test: `tests/test_client.py`

This is the core change. We do all three: (1) `paginate` / `paginate_post` get a `parallel_pages: int | None = None` kwarg defaulting to instance value; (2) `_paginate` becomes two-phase; (3) Phase 2 uses a thread pool, in-order yield, fail-fast.

- [ ] **Step 1: Write failing test for in-order yield with scrambled completion**

Append to `tests/test_client.py`:

```python
import threading
import time as _time_mod


def test_parallel_paginate_yields_in_page_order(session):
    """Pages 0, 1, 2 -- page 1's response sleeps longest, page 2's shortest.
    Iterator must still yield resources in page-0, page-1, page-2 order."""
    page0 = {"resources": [{"id": "p0a"}, {"id": "p0b"}], "page": {"number": 0, "totalPages": 3}}
    page1 = {"resources": [{"id": "p1a"}], "page": {"number": 1, "totalPages": 3}}
    page2 = {"resources": [{"id": "p2a"}, {"id": "p2b"}], "page": {"number": 2, "totalPages": 3}}

    pages_by_number = {0: page0, 1: page1, 2: page2}
    sleep_by_number = {0: 0.0, 1: 0.05, 2: 0.0}

    def fake_request(*args, **kwargs):
        page_num = kwargs["params"]["page"]
        _time_mod.sleep(sleep_by_number[page_num])
        return _resp(200, pages_by_number[page_num])

    session.request.side_effect = fake_request
    c = make_client(session, parallel_pages=3)
    items = list(c.paginate("/api/3/sites"))
    assert [i["id"] for i in items] == ["p0a", "p0b", "p1a", "p2a", "p2b"]


def test_parallel_paginate_propagates_first_error(session):
    """Page 1 of 3 returns 500 -- _paginate must raise Rapid7ClientError
    and must not yield page 1's or page 2's resources. Page 0 is yielded
    via Phase 1 before any failure."""
    page0 = {"resources": [{"id": "p0"}], "page": {"number": 0, "totalPages": 3}}
    page2 = {"resources": [{"id": "p2"}], "page": {"number": 2, "totalPages": 3}}

    def fake_request(*args, **kwargs):
        page_num = kwargs["params"]["page"]
        if page_num == 0:
            return _resp(200, page0)
        if page_num == 1:
            return _resp(500, {"message": "server error"})
        if page_num == 2:
            return _resp(200, page2)
        raise AssertionError(f"unexpected page {page_num}")

    session.request.side_effect = fake_request
    c = make_client(session, parallel_pages=3, max_retries=0)

    yielded: list[dict] = []
    with pytest.raises(Rapid7ClientError) as exc_info:
        for item in c.paginate("/api/3/sites"):
            yielded.append(item)

    assert exc_info.value.status_code == 500
    assert yielded == [{"id": "p0"}]


def test_parallel_paginate_default_one_is_sequential(session, monkeypatch):
    """With parallel_pages=1, ThreadPoolExecutor must NOT be instantiated."""
    from concurrent.futures import ThreadPoolExecutor as _real_pool
    instances: list = []

    def spy_pool(*args, **kwargs):
        instances.append((args, kwargs))
        return _real_pool(*args, **kwargs)

    monkeypatch.setattr("rapid7_healthcheck.client.ThreadPoolExecutor", spy_pool)

    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session, parallel_pages=1)
    items = list(c.paginate("/api/3/sites"))
    assert [i["id"] for i in items] == [1, 2]
    assert instances == []  # executor never created


def test_parallel_paginate_per_call_kwarg_overrides_instance(session, monkeypatch):
    """Per-call parallel_pages kwarg overrides instance default."""
    from concurrent.futures import ThreadPoolExecutor as _real_pool
    instances: list = []

    def spy_pool(*args, max_workers=None, **kwargs):
        instances.append(max_workers)
        return _real_pool(*args, max_workers=max_workers, **kwargs)

    monkeypatch.setattr("rapid7_healthcheck.client.ThreadPoolExecutor", spy_pool)

    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 2}}
    page1 = {"resources": [{"id": 2}], "page": {"number": 1, "totalPages": 2}}
    session.request.side_effect = [_resp(200, page0), _resp(200, page1)]
    c = make_client(session, parallel_pages=1)  # instance default = 1
    items = list(c.paginate("/api/3/sites", parallel_pages=4))
    assert [i["id"] for i in items] == [1, 2]
    assert instances == [4]  # per-call kwarg won


def test_paginate_uses_default_page_size_when_unspecified(session):
    """paginate() without page_size= uses instance default_page_size (250)."""
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 1}}
    session.request.return_value = _resp(200, page0)
    c = make_client(session)  # default_page_size=250
    list(c.paginate("/api/3/sites"))
    assert session.request.call_args.kwargs["params"]["size"] == 250


def test_paginate_explicit_page_size_overrides_default(session):
    page0 = {"resources": [{"id": 1}], "page": {"number": 0, "totalPages": 1}}
    session.request.return_value = _resp(200, page0)
    c = make_client(session)
    list(c.paginate("/api/3/sites", page_size=100))
    assert session.request.call_args.kwargs["params"]["size"] == 100
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_client.py -v -k "parallel_paginate or default_page_size_when or explicit_page_size"`
Expected: FAIL -- `paginate` doesn't accept `parallel_pages`, `_paginate` is sequential and uses page_size=500 default.

- [ ] **Step 3: Add `ThreadPoolExecutor` import**

At the top of `src/rapid7_healthcheck/client.py`, add to the existing `from __future__` / stdlib imports:

```python
from concurrent.futures import ThreadPoolExecutor
```

Place it alphabetically among the stdlib imports (after `from typing import ...`).

- [ ] **Step 4: Update `paginate` and `paginate_post` signatures**

In `src/rapid7_healthcheck/client.py`, replace the `paginate` method (around lines 129-135) with:

```python
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
```

Replace `paginate_post` (around lines 137-146) with:

```python
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
```

- [ ] **Step 5: Rewrite `_paginate` with two-phase walk**

In `src/rapid7_healthcheck/client.py`, replace `_paginate` (currently lines 166-188) with:

```python
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

    # Sequential fast path -- preserve today's behavior bit-for-bit
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
```

- [ ] **Step 6: Run new tests and verify they pass**

Run: `pytest tests/test_client.py -v -k "parallel_paginate or default_page_size_when or explicit_page_size"`
Expected: all 7 new tests PASS.

- [ ] **Step 7: Run the full client test suite**

Run: `pytest tests/test_client.py -v`
Expected: every test passes. Pre-existing tests use `paginate(..., page_size=500)` explicitly so the default change doesn't bite them.

- [ ] **Step 8: Run the full project test suite**

Run: `pytest -q`
Expected: all 419 (or more) tests pass. Watch for regressions in audit / op-check tests that build a `Rapid7Client` directly without specifying `parallel_pages` / `default_page_size`.

- [ ] **Step 9: Commit**

```bash
git add src/rapid7_healthcheck/client.py tests/test_client.py
git commit -m "feat(client): parallel page fetching in _paginate (opt-in)

Two-phase walk inside _paginate: page 0 sequential (probes totalPages),
pages 1..N-1 in concurrent batches of size parallel_pages via a
ThreadPoolExecutor scoped to the call. In-order yield contract
preserved by collecting futures into a per-batch dict keyed on page
index. Sequential fast path when parallel_pages == 1 -- executor is
never instantiated, behavior bit-for-bit identical to v0.2.7.

paginate() and paginate_post() gain a parallel_pages kwarg defaulting
to None (= use instance default). page_size kwarg defaulting to None
(= use instance default_page_size = 250).

Fail-fast: any future raising calls executor.shutdown(cancel_futures=True)
and re-raises immediately. No silent partial results.

Read-only contract unchanged -- every page fetch goes through
_request, which checks _ALLOWED_VERBS / _ALLOWED_POST_PATHS before
network I/O.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Thread the new config fields through `__main__`

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py:212-220` (`Rapid7Client(...)` call)

- [ ] **Step 1: Inspect the existing client construction**

Open `src/rapid7_healthcheck/__main__.py` at line 212. The current call looks roughly like:

```python
client = Rapid7Client(
    base_url=cfg.rapid7.base_url,
    api_key=api_key,           # or basic_auth=...
    verify_tls=cfg.rapid7.verify_tls,
    timeout_seconds=cfg.rapid7.request_timeout_seconds,
    max_retries=cfg.rapid7.max_retries,
)
```

- [ ] **Step 2: Add the two new kwargs**

Update the call to pass the two new fields:

```python
client = Rapid7Client(
    base_url=cfg.rapid7.base_url,
    api_key=api_key,           # or basic_auth=...
    verify_tls=cfg.rapid7.verify_tls,
    timeout_seconds=cfg.rapid7.request_timeout_seconds,
    max_retries=cfg.rapid7.max_retries,
    parallel_pages=cfg.rapid7.parallel_pages,
    default_page_size=cfg.rapid7.page_size,
)
```

If `__main__` constructs the client in two branches (api_key vs basic_auth), update both.

- [ ] **Step 3: Run the project test suite**

Run: `pytest -q`
Expected: all tests pass. There's no `__main__` integration test that exercises this directly, but a broken kwarg name would surface as a config / smoke test failure.

- [ ] **Step 4: Manual smoke test (optional but recommended)**

If a real environment is available:
```bash
python -m rapid7_healthcheck --config docs/examples/config.yaml --verbose --log-file /tmp/r7-smoke.log
```
Expected: tool runs as before. With `parallel_pages: 1` (default), no `paginating ... parallel=K` log lines appear. The `← GET ... NNNms` lines should show timeout up to 60s.

If no real environment: skip this step.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py
git commit -m "feat(main): thread parallel_pages + page_size into Rapid7Client

Wires cfg.rapid7.parallel_pages and cfg.rapid7.page_size into the
client constructor. With the shipped defaults (1, 250) behavior is
unchanged from v0.2.7.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Update `docs/examples/config.yaml`

**Files:**
- Modify: `docs/examples/config.yaml:1-15` (the `rapid7:` block)

- [ ] **Step 1: Read the current rapid7 block**

The current block is:

```yaml
rapid7:
  base_url: "..."
  verify_tls: true
  # Per-request timeout. (max_retries+1) attempts -- exponential backoff between.
  # worst-case wait per call ≈ (max_retries + 1) * request_timeout_seconds.
  request_timeout_seconds: 30
  max_retries: 3
  # auth_mode: api_key  # default; reads R7_API_KEY from env / .env
  # auth_mode: basic    # use HTTP Basic Auth; reads R7_BASIC_USER + R7_BASIC_PASSWORD
```

(Adapt based on the actual file content.)

- [ ] **Step 2: Bump timeout default and add the two new keys**

Replace the block above with:

```yaml
rapid7:
  base_url: "..."
  verify_tls: true
  # Per-request timeout. (max_retries+1) attempts -- exponential backoff between.
  # worst-case wait per call ≈ (max_retries + 1) * request_timeout_seconds.
  # Default raised from 30s to 60s in 0.2.8 -- hosted consoles often need >30s
  # under load.
  request_timeout_seconds: 60
  max_retries: 3
  # auth_mode: api_key  # default; reads R7_API_KEY from env / .env
  # auth_mode: basic    # use HTTP Basic Auth; reads R7_BASIC_USER + R7_BASIC_PASSWORD

  # How many pages to fetch concurrently inside one paginated call against
  # /api/3/assets/search and similar endpoints. The InsightVM API documents
  # 8 parallel requests as the supported limit; values up to 16 are accepted
  # but emit a startup warning. Default 1 (sequential -- today's behavior);
  # bump to 6 to speed up large asset-search walks.
  parallel_pages: 1

  # Default page size for paginated calls. Range 1..500. Lowered from 500 to
  # 250 in 0.2.8 because /api/3/assets/search regularly times out at 500
  # against large filtered queries.
  page_size: 250
```

- [ ] **Step 3: Verify the config loads**

Run: `python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); print(c.rapid7)"`
Expected: prints a `Rapid7Config(...)` repr including `parallel_pages=1, page_size=250, request_timeout_seconds=60`.

- [ ] **Step 4: Commit**

```bash
git add docs/examples/config.yaml
git commit -m "docs(examples): document parallel_pages, page_size; bump timeout to 60s

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Update README + CLAUDE.md + CHANGELOG

**Files:**
- Modify: `README.md` (Troubleshooting section)
- Modify: `CLAUDE.md` (Layer rules section)
- Modify: `CHANGELOG.md` (`[Unreleased]` block)

- [ ] **Step 1: Update README troubleshooting**

Open `README.md`. Find the Troubleshooting section. Locate the existing bullet about `request_timeout_seconds` (added in v0.1.7). Replace it (and add a sibling) with:

```markdown
- **Slow runs / timeouts on `/api/3/assets/search`:** the default page size is
  250 (down from 500 in v0.2.8) and the default request timeout is 60s (up from
  30s). On hosted consoles or very large environments, raise
  `rapid7.request_timeout_seconds` to 120s and consider enabling parallel
  pagination via `rapid7.parallel_pages: 6`. The InsightVM API documents 8
  parallel requests as its supported ceiling; values up to 16 are accepted by
  the validator but emit a startup warning.
- **Network-error messages** include the request method, path, and total
  attempt count, e.g. `network error after 4 attempt(s) on GET /api/3/sites/47/assets: ReadTimeout(...)`.
  Use this to identify which endpoint stalled.
```

(Adapt the surrounding wording to match the existing README voice.)

- [ ] **Step 2: Update CLAUDE.md layer rules**

Open `CLAUDE.md`. Find the "Layer rules (do not violate)" section. After the bullet about `client.py` being the only HTTP module, add this sentence to that bullet:

```markdown
  `_paginate` may execute concurrent page fetches inside one call when
  `parallel_pages > 1`; `requests.Session` is documented thread-safe for
  read operations, so we share one session across worker threads without
  explicit locks. The read-only verb/path check in `_request` is stateless
  and runs per-call, so concurrency does not weaken the invariant.
```

- [ ] **Step 3: Update CHANGELOG `[Unreleased]`**

Open `CHANGELOG.md`. Under `## [Unreleased]`, add three sections (matching the Keep-a-Changelog style of the existing 0.2.7 entry):

```markdown
## [Unreleased]

### Added

- **Parallel page fetching for `/api/3/assets/search` walks (opt-in).**
  `Rapid7Client.paginate` and `paginate_post` gain a `parallel_pages` kwarg.
  When set above 1 (instance default driven by `rapid7.parallel_pages` in
  `config.yaml`), pages 1..N-1 are fetched concurrently in batches via a
  `ThreadPoolExecutor` scoped to the call. Page 0 is fetched sequentially
  to probe `totalPages`. In-order yield contract is preserved: callers see
  resources in strict page-0 → page-N order regardless of completion timing.
  Fail-fast on first error -- no silent partial results. Read-only contract
  unchanged. Default is 1 (sequential, today's behavior); operators tune via
  `config.yaml`. The InsightVM API documents 8 parallel requests as the
  supported limit; the validator caps at 16 and warns above 8.
- New `rapid7.parallel_pages` config field (int, range 1..16, default 1).
- New `rapid7.page_size` config field (int, range 1..500, default 250) --
  configurable default page size for paginated calls.

### Changed

- **`rapid7.request_timeout_seconds` default raised from 30s to 60s.** Matches
  the README troubleshooting guidance for hosted consoles where 30s was
  consistently too tight under load. Operators with explicit values in
  `config.yaml` are unaffected.
- **Default paginated page size lowered from 500 to 250.** Reduces server-side
  timeout pressure on `/api/3/assets/search` filtered walks. Total wall-clock
  is roughly equal (twice as many requests, each finishing twice as fast under
  the typical n²-ish search-cost curve). Override via `rapid7.page_size` or
  the per-call `page_size=` kwarg.
```

- [ ] **Step 4: Run the full test suite one more time**

Run: `pytest -q`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md CHANGELOG.md
git commit -m "docs: parallel_pages, page_size, timeout bump (Unreleased)

README troubleshooting bullet covers parallel_pages and the bumped
timeout default. CLAUDE.md layer-rules section notes _paginate's
thread-safety. CHANGELOG documents all three changes under
[Unreleased] for the upcoming 0.2.8 release.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Verification

**Files:** none (read-only verification)

- [ ] **Step 1: Confirm read-only invariant intact**

Run the static-scan invariant test:

```bash
pytest tests/test_readonly_invariant.py -v
```

Expected: every check passes. No new write verbs, no new POST paths.

- [ ] **Step 2: Confirm no `client.py` PUT/PATCH/DELETE leaked**

```bash
grep -nE "PUT|PATCH|DELETE|client\.(put|patch|delete)" src/
```

Expected: zero hits. (Per CLAUDE.md "Read-only safety" section.)

- [ ] **Step 3: Confirm full test suite green**

```bash
pytest -q
```

Expected: 419+ tests pass. No regressions.

- [ ] **Step 4: Confirm config example loads cleanly**

```bash
python -c "from rapid7_healthcheck.config import load_config; c = load_config('docs/examples/config.yaml'); assert c.rapid7.parallel_pages == 1 and c.rapid7.page_size == 250 and c.rapid7.request_timeout_seconds == 60; print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 5: Update `backlog.md`**

Remove any entries from `backlog.md` that this work resolved, if present. Otherwise no change.

- [ ] **Step 6: No commit needed**

This task is verification only. The branch is now ready for the 0.2.8 release flow (version bump in `pyproject.toml`, changelog `[Unreleased]` → `[0.2.8] - <date>`, tag, runtime zip, GitHub release per the CLAUDE.md release section).

---

## Done

After Task 7 the branch contains:
- 7 commits on top of v0.2.7 (one per task above; Task 1 + Task 2 + Task 3 are the meaningful ones)
- 0 new HTTP verbs, 0 new POST paths
- ~12 new tests (config + client)
- Defaults that ship safe (`parallel_pages: 1`)
- All docs (README, CLAUDE.md, CHANGELOG, example config) updated

Hand off to the user for the release flow per CLAUDE.md.
