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


import logging as _logging  # noqa: E402  (deliberately separate import for clarity below)

from rapid7_healthcheck.__main__ import _setup_logging  # noqa: E402


def test_setup_logging_uses_flushing_file_handler_when_log_file_set(tmp_path):
    """When _setup_logging is called with a log_file path, the resulting
    root logger handlers must include a FlushingFileHandler (NOT a plain
    logging.FileHandler)."""
    log_path = tmp_path / "out.log"
    _setup_logging(verbose=False, log_file=str(log_path))

    file_handlers = [
        h for h in _logging.root.handlers
        if isinstance(h, _logging.FileHandler)
    ]
    assert len(file_handlers) == 1
    assert isinstance(file_handlers[0], FlushingFileHandler), (
        f"expected FlushingFileHandler, got {type(file_handlers[0]).__name__}"
    )


def test_setup_logging_no_file_handler_when_log_file_none(tmp_path):
    """Without --log-file, only the stderr StreamHandler runs; no
    FileHandler-of-any-kind is added."""
    _setup_logging(verbose=True, log_file=None)

    file_handlers = [
        h for h in _logging.root.handlers
        if isinstance(h, _logging.FileHandler)
    ]
    assert file_handlers == []
