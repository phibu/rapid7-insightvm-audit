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
