"""Logging helpers internal to rapid7_healthcheck.

Public surface:
    FlushingFileHandler — drop-in for logging.FileHandler that flushes the
        underlying stream after every emit, so a tailed log file shows live
        progress during long-running audits.
"""
from __future__ import annotations

import json as _json
import logging
from datetime import datetime, timezone


class FlushingFileHandler(logging.FileHandler):
    """FileHandler that flush()es after every emit().

    Trades ~microseconds per record for live-tail visibility. Used in
    place of logging.FileHandler when --log-file is set so the user can
    `tail -f` the log mid-run and see API calls as they happen.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


class PlainFormatter(logging.Formatter):
    """Drop-in for the legacy format string used by basicConfig.

    Format: "%(asctime)s %(levelname)s %(name)s: %(message)s"
    Centralized here so the three file formatters live side-by-side and the
    string isn't duplicated between `_setup_logging` and tests.
    """

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s %(name)s: %(message)s")
