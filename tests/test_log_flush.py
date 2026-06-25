from __future__ import annotations

import logging
from pathlib import Path

import pytest

from rapid7_healthcheck._log import FlushingFileHandler


@pytest.fixture(autouse=True)
def _strip_flushing_file_handlers_after_test():
    """Strip any FlushingFileHandler instances from the root logger after each
    test in this file. See tests/test_logging_setup.py for the full rationale."""
    try:
        yield
    finally:
        root = logging.getLogger()
        for h in list(root.handlers):
            if isinstance(h, FlushingFileHandler):
                root.removeHandler(h)
                h.close()


def test_flushing_file_handler_writes_to_disk_on_each_emit(tmp_path: Path):
    """A record logged via FlushingFileHandler must be readable from disk
    immediately, before the handler is closed -- proves we're flushing."""
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


def test_zzz_a_installs_flushing_file_handler(tmp_path):
    """First half of the fixture-verification pair (mirror of test_logging_setup.py)."""
    from rapid7_healthcheck import __main__ as main_mod

    log_path = tmp_path / "out.log"
    main_mod._setup_logging(verbose=False, log_file=str(log_path), log_format="plain")

    flushing = [h for h in logging.getLogger().handlers if isinstance(h, FlushingFileHandler)]
    assert len(flushing) == 1, (
        f"expected exactly one FlushingFileHandler installed, got {len(flushing)}"
    )


def test_zzz_b_flushing_file_handler_was_cleaned_up():
    """Second half of the fixture-verification pair (mirror)."""
    flushing = [h for h in logging.getLogger().handlers if isinstance(h, FlushingFileHandler)]
    assert len(flushing) == 0, (
        f"expected zero FlushingFileHandler instances after autouse cleanup, "
        f"got {len(flushing)}: {flushing}"
    )
