# Configurable Log Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--log-format {plain,cmtrace,json}` CLI flag and `report.log_format` config field that selects the file-log format. Stderr stays plain.

**Architecture:** Three new `logging.Formatter` subclasses live in `src/rapid7_healthcheck/_log.py` alongside the existing `FlushingFileHandler`. `_setup_logging` selects one for the file handler via a small switch. `_resolve_log_file` makes its auto-derived path suffix format-aware (`.jsonl` for json; `.log` otherwise). `config.ReportConfig` gains a validated `log_format` field. CLI overrides config; config overrides default `"plain"`.

**Tech Stack:** Python 3.11+, stdlib `logging` and `json`, pytest. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-06-log-format-design.md](../specs/2026-05-06-log-format-design.md)

---

## File Structure

**Files modified:**

- `src/rapid7_healthcheck/_log.py` -- add `PlainFormatter`, `CMTraceFormatter`, `JsonFormatter`, `make_file_formatter()`. Existing `FlushingFileHandler` unchanged.
- `src/rapid7_healthcheck/config.py` -- extend `ReportConfig` dataclass with `log_format`; extend `_build_report_config` validator (lines 486-520).
- `src/rapid7_healthcheck/__main__.py` -- add `--log-format` argument; thread `log_format` through `_setup_logging` and `_resolve_log_file`; resolve effective format (CLI > config) before second logging-setup pass.
- `docs/examples/config.yaml` -- document the new `report.log_format` key.
- `tests/test_logging_setup.py` -- extend with format-aware path resolution and `_setup_logging` formatter selection.
- `tests/test_config.py` -- extend with `report.log_format` validation cases.

**Files created:**

- `tests/test_log_formatters.py` -- unit tests for the three formatter classes.

**Layer boundaries (do not violate):** All changes are inside the logging/config/CLI layer. No HTTP code is touched. The read-only verb allowlist in `client.py` is unaffected. No new module issues HTTP.

---

## Task 1: Add `PlainFormatter` (refactor existing format string)

**Files:**
- Modify: `src/rapid7_healthcheck/_log.py`
- Test: `tests/test_log_formatters.py` (new)

This is a no-op refactor -- the format string moves from `_setup_logging`'s `logging.basicConfig(format=...)` call into a `Formatter` class. Subsequent tasks will then use this class explicitly so the format string lives in one place.

- [ ] **Step 1: Create the test file with a failing test**

Create `tests/test_log_formatters.py`:

```python
"""Tests for the three file-log formatters in rapid7_healthcheck._log."""
from __future__ import annotations

import json
import logging
import re

import pytest


def _make_record(
    level: int = logging.INFO,
    name: str = "rapid7_healthcheck",
    msg: str = "running check: Scan Engines",
    args: tuple = (),
    exc_info=None,
) -> logging.LogRecord:
    """Build a LogRecord without going through a Logger, so tests are deterministic."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="/abs/path/scan_engines.py",
        lineno=42,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )
    return record


# ---------- PlainFormatter ----------

def test_plain_formatter_matches_legacy_format_string():
    from rapid7_healthcheck._log import PlainFormatter
    record = _make_record(level=logging.INFO, name="rapid7_healthcheck", msg="hello")
    line = PlainFormatter().format(record)
    # Legacy format: "%(asctime)s %(levelname)s %(name)s: %(message)s"
    assert " INFO rapid7_healthcheck: hello" in line
    # asctime is at the start; default format is "YYYY-MM-DD HH:MM:SS,mmm".
    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} ", line)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_log_formatters.py::test_plain_formatter_matches_legacy_format_string -v`
Expected: FAIL -- `ImportError: cannot import name 'PlainFormatter'`.

- [ ] **Step 3: Add `PlainFormatter` to `_log.py`**

Edit `src/rapid7_healthcheck/_log.py`. After the existing `FlushingFileHandler` class, append:

```python
class PlainFormatter(logging.Formatter):
    """Drop-in for the legacy format string used by basicConfig.

    Format: "%(asctime)s %(levelname)s %(name)s: %(message)s"
    Centralized here so the three file formatters live side-by-side and the
    string isn't duplicated between `_setup_logging` and tests.
    """

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s %(name)s: %(message)s")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/test_log_formatters.py::test_plain_formatter_matches_legacy_format_string -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/_log.py tests/test_log_formatters.py
git commit -m "feat(_log): add PlainFormatter that mirrors the legacy format string"
```

---

## Task 2: Add `CMTraceFormatter`

**Files:**
- Modify: `src/rapid7_healthcheck/_log.py`
- Test: `tests/test_log_formatters.py`

CMTrace line shape:
```
<![LOG[<message>]LOG]!><time="HH:mm:ss.fff+ZZZ" date="MM-dd-yyyy" component="<name>" context="" type="<1|2|3>" thread="<tid>" file="<module>:<line>">
```

- [ ] **Step 1: Append failing tests**

Add to `tests/test_log_formatters.py`:

```python
# ---------- CMTraceFormatter ----------

_CMTRACE_RE = re.compile(
    r'^<!\[LOG\[(?P<msg>.*?)\]LOG\]!>'
    r'<time="(?P<time>\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{3})" '
    r'date="(?P<date>\d{2}-\d{2}-\d{4})" '
    r'component="(?P<component>[^"]*)" '
    r'context="(?P<context>[^"]*)" '
    r'type="(?P<type>[123])" '
    r'thread="(?P<thread>\d+)" '
    r'file="(?P<file>[^"]*)">$',
    re.DOTALL,
)


def test_cmtrace_formatter_basic_shape():
    from rapid7_healthcheck._log import CMTraceFormatter
    record = _make_record(level=logging.INFO, name="rapid7_healthcheck.checks.scan_engines", msg="running check")
    line = CMTraceFormatter().format(record)
    m = _CMTRACE_RE.match(line)
    assert m is not None, f"line did not match CMTrace shape: {line!r}"
    assert m["msg"] == "running check"
    assert m["component"] == "rapid7_healthcheck.checks.scan_engines"
    assert m["context"] == ""
    assert m["type"] == "1"  # INFO
    assert m["file"] == "scan_engines.py:42"


@pytest.mark.parametrize("level,expected_type", [
    (logging.DEBUG, "1"),
    (logging.INFO, "1"),
    (logging.WARNING, "2"),
    (logging.ERROR, "3"),
    (logging.CRITICAL, "3"),
])
def test_cmtrace_severity_mapping(level, expected_type):
    from rapid7_healthcheck._log import CMTraceFormatter
    record = _make_record(level=level, msg="x")
    line = CMTraceFormatter().format(record)
    m = _CMTRACE_RE.match(line)
    assert m is not None
    assert m["type"] == expected_type


def test_cmtrace_formatter_includes_exception_inline():
    from rapid7_healthcheck._log import CMTraceFormatter
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = _make_record(level=logging.ERROR, msg="failed", exc_info=sys.exc_info())
    line = CMTraceFormatter().format(record)
    m = _CMTRACE_RE.match(line)
    assert m is not None, f"exception record didn't match envelope: {line!r}"
    # Exception text is concatenated into the message portion of the envelope.
    assert "failed" in m["msg"]
    assert "ValueError: boom" in m["msg"]


def test_cmtrace_time_offset_format():
    """time= ends with [+-]NNN where NNN is local UTC offset in minutes."""
    from rapid7_healthcheck._log import CMTraceFormatter
    record = _make_record()
    line = CMTraceFormatter().format(record)
    m = _CMTRACE_RE.match(line)
    assert m is not None
    # Offset string must be exactly 4 chars: sign + 3 digits.
    offset = m["time"][-4:]
    assert re.match(r"[+-]\d{3}$", offset), f"unexpected offset: {offset!r}"
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_log_formatters.py -v -k cmtrace`
Expected: FAIL -- `ImportError: cannot import name 'CMTraceFormatter'`.

- [ ] **Step 3: Implement `CMTraceFormatter`**

Append to `src/rapid7_healthcheck/_log.py`:

```python
import time as _time
from datetime import datetime, timezone


_CMTRACE_TYPE_BY_LEVELNO: dict[int, int] = {
    logging.DEBUG: 1,
    logging.INFO: 1,
    logging.WARNING: 2,
    logging.ERROR: 3,
    logging.CRITICAL: 3,
}


def _local_offset_string(record_created: float) -> str:
    """Return CMTrace-style local UTC offset for the record's wall-clock time.

    Format: '+NNN' or '-NNN' where NNN is the offset in minutes (zero-padded
    to three digits). Matches what SCCM client logs emit.
    """
    local = datetime.fromtimestamp(record_created).astimezone()
    offset = local.utcoffset()
    if offset is None:
        return "+000"
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    return f"{sign}{abs(total_minutes):03d}"


class CMTraceFormatter(logging.Formatter):
    """Format log records for the SCCM/MECM CMTrace viewer.

    Line shape:
      <![LOG[<message>]LOG]!><time="HH:mm:ss.fff+ZZZ" date="MM-dd-yyyy"
      component="<logger>" context="" type="<1|2|3>" thread="<tid>"
      file="<module>:<lineno>">
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            # CMTrace handles multi-line messages inside <![LOG[...]LOG]!>; we
            # append the formatted traceback so the exception is visible in the
            # same record (no second envelope).
            exc_text = self.formatException(record.exc_info)
            message = f"{message}\n{exc_text}"

        # Local time HH:MM:SS.mmm
        local = datetime.fromtimestamp(record.created)
        time_str = local.strftime("%H:%M:%S") + f".{int(record.msecs):03d}"
        offset_str = _local_offset_string(record.created)
        date_str = local.strftime("%m-%d-%Y")

        cmtype = _CMTRACE_TYPE_BY_LEVELNO.get(record.levelno, 1)
        component = record.name
        thread_id = record.thread or 0
        # `record.module` is the basename without extension (logging strips it),
        # so we always append ".py" for the CMTrace `file=` field.
        file_field = f"{record.module}.py:{record.lineno}"

        return (
            f"<![LOG[{message}]LOG]!>"
            f'<time="{time_str}{offset_str}" '
            f'date="{date_str}" '
            f'component="{component}" '
            f'context="" '
            f'type="{cmtype}" '
            f'thread="{thread_id}" '
            f'file="{file_field}">'
        )
```

- [ ] **Step 4: Run the CMTrace tests**

Run: `pytest tests/test_log_formatters.py -v -k cmtrace`
Expected: PASS for all CMTrace tests including the parametrized severity mapping.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/_log.py tests/test_log_formatters.py
git commit -m "feat(_log): add CMTraceFormatter for SCCM/MECM viewer compatibility"
```

---

## Task 3: Add `JsonFormatter`

**Files:**
- Modify: `src/rapid7_healthcheck/_log.py`
- Test: `tests/test_log_formatters.py`

JSONL minimal shape: one object per line; keys `ts`, `level`, `logger`, `msg`; optional `exc` when `exc_info` is set.

- [ ] **Step 1: Append failing tests**

Add to `tests/test_log_formatters.py`:

```python
# ---------- JsonFormatter ----------

def test_json_formatter_minimal_shape():
    from rapid7_healthcheck._log import JsonFormatter
    record = _make_record(level=logging.WARNING, name="rapid7_healthcheck.audit", msg="suspicious config")
    line = JsonFormatter().format(record)
    obj = json.loads(line)
    assert set(obj.keys()) == {"ts", "level", "logger", "msg"}
    assert obj["level"] == "WARNING"
    assert obj["logger"] == "rapid7_healthcheck.audit"
    assert obj["msg"] == "suspicious config"
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", obj["ts"]), obj["ts"]


def test_json_formatter_args_are_interpolated():
    """logger.info('hello %s', 'world') must produce msg='hello world'."""
    from rapid7_healthcheck._log import JsonFormatter
    record = _make_record(msg="hello %s", args=("world",))
    obj = json.loads(JsonFormatter().format(record))
    assert obj["msg"] == "hello world"


def test_json_formatter_exception_field():
    from rapid7_healthcheck._log import JsonFormatter
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = _make_record(level=logging.ERROR, msg="failed", exc_info=sys.exc_info())
    obj = json.loads(JsonFormatter().format(record))
    assert set(obj.keys()) == {"ts", "level", "logger", "msg", "exc"}
    assert "ValueError: boom" in obj["exc"]


def test_json_formatter_non_ascii_round_trips():
    """ensure_ascii=False keeps unicode readable in the file."""
    from rapid7_healthcheck._log import JsonFormatter
    record = _make_record(msg="München")
    line = JsonFormatter().format(record)
    # Literal unicode, not \uXXXX escape.
    assert "München" in line
    obj = json.loads(line)
    assert obj["msg"] == "München"


def test_json_formatter_each_line_is_valid_json():
    """Two records produce two parseable JSON objects (one per line)."""
    from rapid7_healthcheck._log import JsonFormatter
    fmt = JsonFormatter()
    r1 = _make_record(msg="first")
    r2 = _make_record(msg="second")
    out = fmt.format(r1) + "\n" + fmt.format(r2)
    parsed = [json.loads(line) for line in out.splitlines()]
    assert [o["msg"] for o in parsed] == ["first", "second"]
```

- [ ] **Step 2: Run the JSON tests to verify they fail**

Run: `pytest tests/test_log_formatters.py -v -k json`
Expected: FAIL -- `ImportError: cannot import name 'JsonFormatter'`.

- [ ] **Step 3: Implement `JsonFormatter`**

Append to `src/rapid7_healthcheck/_log.py`:

```python
import json as _json


class JsonFormatter(logging.Formatter):
    """Format log records as one JSON object per line (JSONL).

    Shape: {"ts": "<UTC ISO-8601 with .ms and Z>", "level": "<NAME>",
            "logger": "<record.name>", "msg": "<rendered message>"}
    Adds an "exc" field with the formatted traceback when record.exc_info is set.
    """

    def format(self, record: logging.LogRecord) -> str:
        # UTC ISO-8601 with millisecond precision, trailing Z.
        utc = datetime.fromtimestamp(record.created, tz=timezone.utc)
        ts = utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z"

        obj: dict[str, object] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return _json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
```

- [ ] **Step 4: Run the JSON tests**

Run: `pytest tests/test_log_formatters.py -v -k json`
Expected: PASS for all five JSON tests.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/_log.py tests/test_log_formatters.py
git commit -m "feat(_log): add JsonFormatter for JSONL machine-readable logs"
```

---

## Task 4: Add `make_file_formatter` selector

**Files:**
- Modify: `src/rapid7_healthcheck/_log.py`
- Test: `tests/test_log_formatters.py`

Single switch that maps a string to one of the three formatters. Used by `_setup_logging` in Task 6.

- [ ] **Step 1: Append failing tests**

Add to `tests/test_log_formatters.py`:

```python
# ---------- make_file_formatter ----------

@pytest.mark.parametrize("name,cls_name", [
    ("plain", "PlainFormatter"),
    ("cmtrace", "CMTraceFormatter"),
    ("json", "JsonFormatter"),
])
def test_make_file_formatter_returns_expected_class(name, cls_name):
    from rapid7_healthcheck import _log as logmod
    f = logmod.make_file_formatter(name)
    assert type(f).__name__ == cls_name


def test_make_file_formatter_rejects_unknown():
    from rapid7_healthcheck._log import make_file_formatter
    with pytest.raises(ValueError, match="unknown log_format"):
        make_file_formatter("xml")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_log_formatters.py -v -k make_file_formatter`
Expected: FAIL -- `AttributeError: module 'rapid7_healthcheck._log' has no attribute 'make_file_formatter'`.

- [ ] **Step 3: Implement the selector**

Append to `src/rapid7_healthcheck/_log.py`:

```python
def make_file_formatter(log_format: str) -> logging.Formatter:
    """Return the file-log formatter matching the requested string.

    Defensive -- config validation should have caught unknown values upstream.
    """
    if log_format == "plain":
        return PlainFormatter()
    if log_format == "cmtrace":
        return CMTraceFormatter()
    if log_format == "json":
        return JsonFormatter()
    raise ValueError(f"unknown log_format: {log_format!r}")
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_log_formatters.py -v -k make_file_formatter`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/_log.py tests/test_log_formatters.py
git commit -m "feat(_log): add make_file_formatter switch for log_format string"
```

---

## Task 5: Extend `ReportConfig` with `log_format`

**Files:**
- Modify: `src/rapid7_healthcheck/config.py:33-38` (dataclass)
- Modify: `src/rapid7_healthcheck/config.py:486-520` (`_build_report_config`)
- Test: `tests/test_config.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/test_config.py` (no need to read full file -- these tests construct fresh fixtures):

```python
def test_report_log_format_defaults_to_plain(tmp_path, monkeypatch):
    """When report.log_format is absent in YAML, default is 'plain'."""
    from rapid7_healthcheck.config import load_config
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "rapid7:\n"
        "  base_url: https://example.com\n"
        "  verify_tls: true\n"
        "  request_timeout_seconds: 30\n"
        "  max_retries: 3\n"
        "report:\n"
        "  output_dir: ./reports\n"
        "  filename_pattern: r-{timestamp}.html\n"
        "  title: t\n"
        "thresholds: {}\n"
        "audit: {}\n"
        "user_audit: {}\n"
        "checks: {}\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_path))
    assert cfg.report.log_format == "plain"


def test_report_log_format_accepts_cmtrace(tmp_path):
    from rapid7_healthcheck.config import load_config
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "rapid7:\n"
        "  base_url: https://example.com\n"
        "  verify_tls: true\n"
        "  request_timeout_seconds: 30\n"
        "  max_retries: 3\n"
        "report:\n"
        "  output_dir: ./reports\n"
        "  filename_pattern: r-{timestamp}.html\n"
        "  title: t\n"
        "  log_format: cmtrace\n"
        "thresholds: {}\n"
        "audit: {}\n"
        "user_audit: {}\n"
        "checks: {}\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_path))
    assert cfg.report.log_format == "cmtrace"


def test_report_log_format_rejects_unknown_value(tmp_path):
    from rapid7_healthcheck.config import load_config, ConfigError
    import pytest as _pytest
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "rapid7:\n"
        "  base_url: https://example.com\n"
        "  verify_tls: true\n"
        "  request_timeout_seconds: 30\n"
        "  max_retries: 3\n"
        "report:\n"
        "  output_dir: ./reports\n"
        "  filename_pattern: r-{timestamp}.html\n"
        "  title: t\n"
        "  log_format: yaml\n"
        "thresholds: {}\n"
        "audit: {}\n"
        "user_audit: {}\n"
        "checks: {}\n",
        encoding="utf-8",
    )
    with _pytest.raises(ConfigError, match="report.log_format"):
        load_config(str(cfg_path))
```

> If `tests/test_config.py` already has helpers for building a minimal valid config dict, prefer those over inline YAML strings -- but don't refactor for it; either approach works.

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_config.py -v -k log_format`
Expected: FAIL -- `AttributeError: 'ReportConfig' object has no attribute 'log_format'`.

- [ ] **Step 3: Extend `ReportConfig` dataclass**

Edit `src/rapid7_healthcheck/config.py` lines 32-38. Replace:

```python
@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str
    delta_max_age_days: int | None = 30
```

with:

```python
@dataclass(frozen=True)
class ReportConfig:
    output_dir: str
    filename_pattern: str
    title: str
    delta_max_age_days: int | None = 30
    log_format: str = "plain"
```

- [ ] **Step 4: Extend `_build_report_config` validator**

Edit `src/rapid7_healthcheck/config.py` lines 486-520. Update three pieces:

a) The `expected` set (line 501) -- add `"log_format"`:

```python
    expected = {"output_dir", "filename_pattern", "title", "delta_max_age_days", "log_format"}
```

b) Insert a new validation block immediately after the `delta` block (between current lines 514 and 515):

```python
    log_format = data.get("log_format", "plain")
    if log_format not in ("plain", "cmtrace", "json"):
        raise ConfigError(
            f"report.log_format: invalid value {log_format!r}; "
            f"must be one of: plain, cmtrace, json"
        )
```

c) Pass `log_format` to the constructor (the existing `return ReportConfig(...)` call):

```python
    return ReportConfig(
        output_dir=data["output_dir"],
        filename_pattern=data["filename_pattern"],
        title=data["title"],
        delta_max_age_days=delta,
        log_format=log_format,
    )
```

- [ ] **Step 5: Run the new tests**

Run: `pytest tests/test_config.py -v -k log_format`
Expected: PASS for all three new tests.

- [ ] **Step 6: Run the full config-test file to catch regressions**

Run: `pytest tests/test_config.py -v`
Expected: All existing tests still PASS.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/config.py tests/test_config.py
git commit -m "feat(config): add report.log_format field with plain/cmtrace/json values"
```

---

## Task 6: Thread `log_format` through `_setup_logging`

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py:59-76` (`_setup_logging`)
- Test: `tests/test_logging_setup.py`

The stderr `StreamHandler` keeps using the legacy format string (via `logging.basicConfig(format=...)`); the `FlushingFileHandler` now sets a per-format formatter explicitly via `make_file_formatter`.

- [ ] **Step 1: Append failing tests**

Append to `tests/test_logging_setup.py`:

```python
def test_setup_logging_uses_json_formatter_for_file_handler(tmp_path):
    """When log_format='json', the file handler's formatter is JsonFormatter."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import JsonFormatter, FlushingFileHandler

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path), log_format="json")

    root = _logging.getLogger()
    file_handlers = [h for h in root.handlers if isinstance(h, FlushingFileHandler)]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0].formatter, JsonFormatter)


def test_setup_logging_stderr_stays_plain_when_format_is_json(tmp_path):
    """Stderr StreamHandler's formatter is unaffected by log_format."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import JsonFormatter

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path), log_format="json")

    root = _logging.getLogger()
    stream_handlers = [
        h for h in root.handlers
        if isinstance(h, _logging.StreamHandler) and not isinstance(h.formatter, JsonFormatter)
    ]
    # At least one StreamHandler exists and its formatter is NOT JsonFormatter.
    assert any(
        isinstance(h, _logging.StreamHandler) and not isinstance(h.formatter, JsonFormatter)
        for h in root.handlers
    )


def test_setup_logging_default_format_is_plain(tmp_path):
    """When log_format is omitted, default is 'plain' for the file handler."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging
    from rapid7_healthcheck._log import PlainFormatter, FlushingFileHandler

    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path))  # no log_format kwarg

    root = _logging.getLogger()
    file_handlers = [h for h in root.handlers if isinstance(h, FlushingFileHandler)]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0].formatter, PlainFormatter)
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_logging_setup.py -v -k formatter`
Expected: FAIL -- `_setup_logging() got an unexpected keyword argument 'log_format'`.

- [ ] **Step 3: Modify `_setup_logging`**

Edit `src/rapid7_healthcheck/__main__.py` lines 59-76. Replace:

```python
def _setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    file_open_error: str | None = None
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            handlers.append(FlushingFileHandler(log_file, encoding="utf-8"))
        except OSError as e:
            file_open_error = f"log file unavailable ({log_file}); continuing without file logging: {e}"
    if file_open_error:
        logging.getLogger(__name__).warning(file_open_error)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
```

with:

```python
def _setup_logging(verbose: bool, log_file: str | None, log_format: str = "plain") -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    file_open_error: str | None = None
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = FlushingFileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(make_file_formatter(log_format))
            handlers.append(file_handler)
        except OSError as e:
            file_open_error = f"log file unavailable ({log_file}); continuing without file logging: {e}"
    if file_open_error:
        logging.getLogger(__name__).warning(file_open_error)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
```

Update the import on line 24 from:

```python
from rapid7_healthcheck._log import FlushingFileHandler
```

to:

```python
from rapid7_healthcheck._log import FlushingFileHandler, make_file_formatter
```

- [ ] **Step 4: Run the new tests**

Run: `pytest tests/test_logging_setup.py -v -k formatter`
Expected: PASS for all three new tests.

- [ ] **Step 5: Run the full logging-setup test file**

Run: `pytest tests/test_logging_setup.py -v`
Expected: All existing tests still PASS (`_setup_logging`'s default `log_format="plain"` keeps callers that don't pass it working).

- [ ] **Step 6: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py tests/test_logging_setup.py
git commit -m "feat(__main__): thread log_format through _setup_logging; file handler picks formatter"
```

---

## Task 7: Make `_resolve_log_file` format-aware

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py:79-98` (`_resolve_log_file`)
- Test: `tests/test_logging_setup.py`

Auto-derived path (precedence step 4) gains `.jsonl` suffix when format is json. Steps 1-3 unchanged.

- [ ] **Step 1: Append failing tests**

Append to `tests/test_logging_setup.py`:

```python
def test_auto_derived_log_path_uses_jsonl_for_json_format():
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert resolved is not None
    assert str(resolved).endswith(".jsonl")


def test_auto_derived_log_path_uses_log_for_cmtrace_format():
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="cmtrace")
    assert resolved is not None
    assert str(resolved).endswith(".log")


def test_auto_derived_log_path_uses_log_for_plain_format():
    """Regression -- default format keeps the .log suffix."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="plain")
    assert resolved is not None
    assert str(resolved).endswith(".log")


def test_explicit_log_file_path_not_rewritten_for_json():
    """--log-file foo.log + json format keeps foo.log verbatim."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = "foo.log"
    args.output = None
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert str(resolved) == "foo.log"


def test_output_derived_log_path_not_rewritten_for_json():
    """--output report.html + json format -> report.log (not report.jsonl)."""
    from rapid7_healthcheck.__main__ import _resolve_log_file
    args = MagicMock()
    args.no_log_file = False
    args.log_file = None
    args.output = "/custom/myreport.html"
    cfg = MagicMock()
    cfg.report.output_dir = "reports"
    cfg.report.filename_pattern = "report-{timestamp}.html"
    resolved = _resolve_log_file(args, cfg, log_format="json")
    assert str(resolved).endswith("myreport.log")
```

Update the four pre-existing tests in `tests/test_logging_setup.py` (the ones at lines 11, 25, 37, 52 in the file as it exists today) to pass `log_format="plain"` explicitly. Replace each `_resolve_log_file(args, cfg)` call with `_resolve_log_file(args, cfg, log_format="plain")`.

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_logging_setup.py -v -k log_path`
Expected: FAIL -- `_resolve_log_file() got an unexpected keyword argument 'log_format'`.

- [ ] **Step 3: Modify `_resolve_log_file`**

Edit `src/rapid7_healthcheck/__main__.py` lines 79-98. Replace:

```python
def _resolve_log_file(args: argparse.Namespace, cfg: AppConfig) -> Path | None:
    """Resolve which path (if any) the run-log FileHandler should write to.

    Precedence:
      1. --no-log-file  -> None (suppress)
      2. --log-file <p> -> <p> (explicit override)
      3. --output <p>   -> <p> with .log suffix (alongside report)
      4. otherwise      -> cfg.report.output_dir + filename pattern with .log suffix
    """
    if getattr(args, "no_log_file", False):
        return None
    if getattr(args, "log_file", None):
        return Path(args.log_file)
    if getattr(args, "output", None):
        return Path(args.output).with_suffix(".log")
    # Derive from config -- mirror what write_report does for the default path.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    base = cfg.report.filename_pattern.replace("{timestamp}", timestamp)
    log_name = Path(base).with_suffix(".log").name
    return Path(cfg.report.output_dir) / log_name
```

with:

```python
def _resolve_log_file(args: argparse.Namespace, cfg: AppConfig, log_format: str) -> Path | None:
    """Resolve which path (if any) the run-log FileHandler should write to.

    Precedence:
      1. --no-log-file  -> None (suppress)
      2. --log-file <p> -> <p> (explicit override; honored verbatim)
      3. --output <p>   -> <p> with .log suffix (alongside report)
      4. otherwise      -> cfg.report.output_dir + filename pattern with
                           format-aware suffix (.jsonl for json, else .log)

    Format-aware suffix applies ONLY to step 4. Explicit user paths in
    steps 2 and 3 are never rewritten.
    """
    if getattr(args, "no_log_file", False):
        return None
    if getattr(args, "log_file", None):
        return Path(args.log_file)
    if getattr(args, "output", None):
        return Path(args.output).with_suffix(".log")
    # Derive from config -- mirror what write_report does for the default path.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    base = cfg.report.filename_pattern.replace("{timestamp}", timestamp)
    suffix = ".jsonl" if log_format == "json" else ".log"
    log_name = Path(base).with_suffix(suffix).name
    return Path(cfg.report.output_dir) / log_name
```

- [ ] **Step 4: Run the new + updated tests**

Run: `pytest tests/test_logging_setup.py -v`
Expected: PASS for all (5 new + 4 updated existing tests).

- [ ] **Step 5: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py tests/test_logging_setup.py
git commit -m "feat(__main__): make _resolve_log_file format-aware for auto-derived paths"
```

---

## Task 8: Wire `--log-format` CLI flag and resolve effective format

**Files:**
- Modify: `src/rapid7_healthcheck/__main__.py:49-56` (`_parse_args`)
- Modify: `src/rapid7_healthcheck/__main__.py:174-188` (top of `run()`)
- Test: `tests/test_main.py` (extend with two new tests)

CLI flag overrides config. The two-pass logging setup (first stderr-only, then with file) keeps its current shape.

- [ ] **Step 1: Append failing tests**

Append to `tests/test_main.py` (no need to read full file -- these tests stub the heavy parts):

```python
def test_cli_log_format_overrides_config(tmp_path, monkeypatch):
    """--log-format json overrides cfg.report.log_format='cmtrace'."""
    from unittest.mock import MagicMock, patch
    from rapid7_healthcheck import __main__ as main_mod

    captured = {}

    def fake_setup_logging(verbose, log_file=None, log_format="plain"):
        captured["log_format"] = log_format
        captured["log_file"] = log_file

    def fake_load_config(path):
        cfg = MagicMock()
        cfg.report.log_format = "cmtrace"
        cfg.report.output_dir = str(tmp_path)
        cfg.report.filename_pattern = "r-{timestamp}.html"
        cfg.rapid7.auth_mode = "api_key"
        return cfg

    with patch.object(main_mod, "_setup_logging", side_effect=fake_setup_logging), \
         patch.object(main_mod, "load_config", side_effect=fake_load_config), \
         patch.object(main_mod.os.environ, "get", return_value=None):
        # Sentinel: bail out of run() right after second _setup_logging call by raising.
        # Easier: just invoke _parse_args + the resolution snippet via a thin helper
        # if one exists; otherwise call run() with --no-log-file to short-circuit
        # the API-key check via missing R7_API_KEY (returns EXIT_STARTUP).
        argv = ["--config", "x.yaml", "--log-format", "json", "--no-log-file"]
        rc = main_mod.run(argv)

    # Either way, _setup_logging was called twice (first pass + second pass).
    # The second-pass log_format must be "json" (CLI override).
    assert captured["log_format"] == "json"


def test_cli_log_format_falls_back_to_config(tmp_path, monkeypatch):
    """When --log-format is absent, cfg.report.log_format is used."""
    from unittest.mock import MagicMock, patch
    from rapid7_healthcheck import __main__ as main_mod

    captured = {}

    def fake_setup_logging(verbose, log_file=None, log_format="plain"):
        captured["log_format"] = log_format

    def fake_load_config(path):
        cfg = MagicMock()
        cfg.report.log_format = "cmtrace"
        cfg.report.output_dir = str(tmp_path)
        cfg.report.filename_pattern = "r-{timestamp}.html"
        cfg.rapid7.auth_mode = "api_key"
        return cfg

    with patch.object(main_mod, "_setup_logging", side_effect=fake_setup_logging), \
         patch.object(main_mod, "load_config", side_effect=fake_load_config), \
         patch.object(main_mod.os.environ, "get", return_value=None):
        argv = ["--config", "x.yaml", "--no-log-file"]
        main_mod.run(argv)

    assert captured["log_format"] == "cmtrace"
```

> **Note for the implementer:** if `tests/test_main.py` already has fixtures that build a real `AppConfig`, prefer those. The MagicMock approach above works because `run()` doesn't call any methods on `cfg` between `load_config` and the second `_setup_logging` other than reading `cfg.report.log_format`, `cfg.report.output_dir`, `cfg.report.filename_pattern`, and `cfg.rapid7.auth_mode`. After the API-key check returns `EXIT_STARTUP`, the function exits.

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_main.py -v -k log_format`
Expected: FAIL -- argparse rejects unknown argument `--log-format`.

- [ ] **Step 3: Add `--log-format` to `_parse_args`**

Edit `src/rapid7_healthcheck/__main__.py` lines 49-56. Replace:

```python
def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rapid7-healthcheck")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    p.add_argument("--output", default=None, help="Override report output path")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    p.add_argument("--log-file", default=None, help="Also write logs to this file")
    p.add_argument("--no-log-file", action="store_true", help="Suppress the default-on run log file")
    return p.parse_args(argv)
```

with:

```python
def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rapid7-healthcheck")
    p.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    p.add_argument("--output", default=None, help="Override report output path")
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    p.add_argument("--log-file", default=None, help="Also write logs to this file")
    p.add_argument("--no-log-file", action="store_true", help="Suppress the default-on run log file")
    p.add_argument(
        "--log-format",
        choices=["plain", "cmtrace", "json"],
        default=None,
        help="File log format. Overrides report.log_format. Stderr stays plain.",
    )
    return p.parse_args(argv)
```

- [ ] **Step 4: Resolve effective format and pass it through `run()`**

Edit `src/rapid7_healthcheck/__main__.py` lines 174-188. Replace:

```python
def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    # First pass: stderr-only so config errors are visible.
    _setup_logging(args.verbose, log_file=None)
    load_dotenv(override=False)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("config error: %s", e)
        return EXIT_STARTUP

    # Second pass: now we know where the log should go.
    resolved_log = _resolve_log_file(args, cfg)
    _setup_logging(args.verbose, log_file=str(resolved_log) if resolved_log else None)
```

with:

```python
def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    # First pass: stderr-only so config errors are visible. log_format is plain
    # because we don't have the config yet; this pass never opens a file.
    _setup_logging(args.verbose, log_file=None, log_format="plain")
    load_dotenv(override=False)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("config error: %s", e)
        return EXIT_STARTUP

    # Effective format: CLI override > config default.
    effective_log_format = args.log_format or cfg.report.log_format

    # Second pass: now we know where the log should go and in which format.
    resolved_log = _resolve_log_file(args, cfg, effective_log_format)
    _setup_logging(
        args.verbose,
        log_file=str(resolved_log) if resolved_log else None,
        log_format=effective_log_format,
    )
```

- [ ] **Step 5: Run the new tests**

Run: `pytest tests/test_main.py -v -k log_format`
Expected: PASS for both new tests.

- [ ] **Step 6: Run the full test suite**

Run: `pytest -v`
Expected: All tests PASS. Watch for any pre-existing test that calls `_resolve_log_file` or `_setup_logging` without the new kwarg -- Task 7 already covered the ones in `test_logging_setup.py`, but if `test_main.py` has integration tests that go through `run()` with a real config, they should keep working because `_setup_logging`'s and `_resolve_log_file`'s new params have defaults (`log_format="plain"` / required-positional with one supplied).

> **Watch out:** `_resolve_log_file` made `log_format` a *required* positional. If `pytest -v` flags a `TypeError: missing argument log_format` from a place outside the files we've changed, find that call site, decide whether it should pass `"plain"` (most likely) or the effective format, and fix it before committing.

- [ ] **Step 7: Commit**

```bash
git add src/rapid7_healthcheck/__main__.py tests/test_main.py
git commit -m "feat(__main__): add --log-format CLI flag with config fallback"
```

---

## Task 9: Document the new key in the example config

**Files:**
- Modify: `docs/examples/config.yaml`

- [ ] **Step 1: Add the documented key**

Edit `docs/examples/config.yaml`. Find the `report:` block (starts around line 29 with `report:` followed by `output_dir`, `filename_pattern`, `title`, and a `delta_max_age_days` block with comments). After the existing entries inside `report:` and before the next top-level key, add:

```yaml
  # File-log format. Stderr stays human-readable plain regardless.
  #   plain   -- current default; "<ts> <LEVEL> <logger>: <msg>" lines.
  #   cmtrace -- SCCM/MECM CMTrace viewer format. Useful on Windows when ops
  #             open run logs in cmtrace.exe and want severity colorization
  #             and the component filter.
  #   json    -- JSON Lines (one object per line). Useful when shipping logs
  #             into Splunk/Loki/OpenSearch. Auto-derived path uses .jsonl.
  # Override at runtime with `--log-format {plain,cmtrace,json}`.
  log_format: plain
```

- [ ] **Step 2: Verify the example config still parses**

Run: `python -c "from rapid7_healthcheck.config import load_config; load_config('docs/examples/config.yaml'); print('OK')"`
Expected: `OK` (no exception). The default `log_format: plain` matches the in-code default -- no behavior change for users who don't touch the new key.

- [ ] **Step 3: Commit**

```bash
git add docs/examples/config.yaml
git commit -m "docs(config): document report.log_format option"
```

---

## Task 10: Final verification

- [ ] **Step 1: Run full test suite**

Run: `pytest -v`
Expected: All tests PASS, including the new ones from Tasks 1-8.

- [ ] **Step 2: Smoke-test each format end-to-end**

Run a fast no-network check that exercises the CLI flag without hitting Rapid7. The simplest path: invoke with a deliberately bad config so we exit at startup but still go through `_setup_logging` once with the format active.

```bash
# Plain (current behavior -- regression check)
python -m rapid7_healthcheck --config /does/not/exist --log-format plain --no-log-file 2>&1 | head -5

# CMTrace
python -m rapid7_healthcheck --config /does/not/exist --log-format cmtrace --no-log-file 2>&1 | head -5

# JSON
python -m rapid7_healthcheck --config /does/not/exist --log-format json --no-log-file 2>&1 | head -5
```

Expected for all three: process exits with code 3 (`EXIT_STARTUP`) and stderr contains a "config error:" line in the **plain** format (because stderr stays plain regardless of `--log-format`). No `<![LOG[` markers, no JSON braces on stderr. This confirms the file-only scope.

- [ ] **Step 3: Read-only invariant check (non-negotiable)**

Run: `pytest tests/test_readonly_invariant.py -v`
Expected: PASS. (No HTTP code was touched, but this is the project's belt-and-suspenders check.)

Then grep for any sneak-in of disallowed verbs:

```bash
grep -rnE 'PUT|PATCH|DELETE|client\.(put|patch|delete)' src/
```

Expected: zero matches (or only matches in `client.py`'s rejection logic -- `_ALLOWED_VERBS`, `ReadOnlyViolationError`, etc.).

- [ ] **Step 4: Check the `backlog.md` file**

If anything was deferred during implementation (e.g. you noticed but didn't tackle "expose run-id in JSON logs"), append it to `backlog.md` under an appropriate version heading per the project's rules in CLAUDE.md.

- [ ] **Step 5: Final commit (if backlog edited)**

```bash
git add backlog.md
git commit -m "chore(backlog): note deferred log-format follow-ups"
```

(If no follow-ups, skip.)

---

## Plan Self-Review

**Spec coverage:**

- §"User-facing surface / CLI" -- Task 8 (`--log-format` flag). ✓
- §"User-facing surface / Config" -- Task 5 (`ReportConfig.log_format` field + validation). ✓
- §"Precedence" -- Task 8 (`args.log_format or cfg.report.log_format`). ✓
- §"plain format" -- Task 1 (`PlainFormatter`). ✓
- §"cmtrace format" -- Task 2 (`CMTraceFormatter` including severity mapping, time/date, component, exception inline). ✓
- §"json format" -- Task 3 (`JsonFormatter` including UTC ISO-8601, fixed key set, exception field, non-ASCII). ✓
- §"Architecture / `make_file_formatter`" -- Task 4. ✓
- §"`__main__.py` changes / `_setup_logging`" -- Task 6. ✓
- §"`__main__.py` changes / `_resolve_log_file`" -- Task 7. ✓
- §"`__main__.py` changes / `run()`" -- Task 8 (effective-format resolution and second-pass call). ✓
- §"`config.py` changes" -- Task 5 (`expected` set, validator block, constructor). ✓
- §"`docs/examples/config.yaml`" -- Task 9. ✓
- §"Testing / formatter unit tests" -- Tasks 1-4. ✓
- §"Testing / `_setup_logging` integration" -- Task 6. ✓
- §"Testing / `_resolve_log_file`" -- Task 7. ✓
- §"Testing / config validation" -- Task 5. ✓
- §"Read-only safety" -- Task 10 (verification). ✓
- §"Out of scope" items -- explicitly NOT implemented (run-id, rotation, console-format, `extra={}`, top-level `logging:` block). ✓

**Placeholder scan:** No "TBD" / "implement later" / "similar to Task N" in any step. Every code step shows the actual code; every command step shows the actual command and expected output.

**Type/signature consistency:**

- `_setup_logging(verbose, log_file, log_format="plain")` -- Tasks 6, 8 use the same signature.
- `_resolve_log_file(args, cfg, log_format)` -- Tasks 7, 8 use the same signature (positional, required).
- `make_file_formatter(log_format: str) -> logging.Formatter` -- Tasks 4, 6 match.
- `ReportConfig.log_format: str = "plain"` -- Tasks 5, 8 (`cfg.report.log_format`) match.

**One issue caught and fixed inline:** The `CMTraceFormatter` implementation in Task 2 originally had a redundant `file_field` assignment (the second overwrote the first). Removed; the canonical form `f"{record.module}.py:{record.lineno}"` is the only assignment now. The CMTrace regex tests still pass because they match `file="[^"]*"` and the `_make_record` fixture uses `pathname="/abs/path/scan_engines.py"` which makes `record.module == "scan_engines"`.

Plan complete and saved to `docs/superpowers/plans/2026-05-06-log-format.md`. Two execution options:

**1. Subagent-Driven (recommended)** -- I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** -- Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
