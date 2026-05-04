"""Logging helpers internal to rapid7_healthcheck.

Public surface:
    FlushingFileHandler — drop-in for logging.FileHandler that flushes the
        underlying stream after every emit, so a tailed log file shows live
        progress during long-running audits.
"""
from __future__ import annotations

import logging


class FlushingFileHandler(logging.FileHandler):
    """FileHandler that flush()es after every emit().

    Trades ~microseconds per record for live-tail visibility. Used in
    place of logging.FileHandler when --log-file is set so the user can
    `tail -f` the log mid-run and see API calls as they happen.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()
