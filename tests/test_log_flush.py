from __future__ import annotations

import logging
from pathlib import Path

from rapid7_healthcheck._log import FlushingFileHandler


def test_flushing_file_handler_writes_to_disk_on_each_emit(tmp_path: Path):
    """A record logged via FlushingFileHandler must be readable from disk
    immediately, before the handler is closed — proves we're flushing."""
    log_path = tmp_path / "live.log"
    handler = FlushingFileHandler(str(log_path), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Log a record. Do NOT close the handler.
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello-from-flush", args=(), exc_info=None,
    )
    handler.emit(record)

    # Read the file from a separate handle while the handler is still open.
    # If flush() is not called inside emit(), this will see an empty (or
    # incomplete) file because OS-level buffering hasn't released the data.
    contents = log_path.read_text(encoding="utf-8")
    assert "hello-from-flush" in contents

    handler.close()


def test_flushing_file_handler_is_a_filehandler_subclass():
    """Sanity check: behaves like a normal FileHandler for the rest of the
    Logging stack (level, formatter, baseFilename, etc.)."""
    assert issubclass(FlushingFileHandler, logging.FileHandler)
