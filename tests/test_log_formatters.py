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
