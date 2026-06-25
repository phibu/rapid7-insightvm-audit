"""Tests for ProgressAwareStreamHandler.

The handler exists to prevent log records from gluing onto the in-place
TTY status line written by ProgressReporter. On a TTY, each emit must be
prefixed with ``\\r\\x1b[K`` (clear-current-line) so the progress line is
wiped before the log record is rendered. On a non-TTY (file/pipe), the
prefix must be omitted so log files stay clean.
"""
from __future__ import annotations

import io
import logging

from rapid7_healthcheck._log import ProgressAwareStreamHandler


_CLEAR_LINE = "\r\x1b[K"


class _FakeStream(io.StringIO):
    """StringIO with a controllable isatty() return."""

    def __init__(self, *, is_tty: bool) -> None:
        super().__init__()
        self._is_tty = is_tty

    def isatty(self) -> bool:  # type: ignore[override]
        return self._is_tty


def _make_record(msg: str = "hello") -> logging.LogRecord:
    return logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


def test_emits_clear_line_prefix_on_tty():
    stream = _FakeStream(is_tty=True)
    handler = ProgressAwareStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record("hello"))

    output = stream.getvalue()
    assert output.startswith(_CLEAR_LINE), (
        f"expected output to start with clear-line escape, got {output!r}"
    )
    assert "hello" in output


def test_does_not_emit_clear_line_prefix_on_non_tty():
    stream = _FakeStream(is_tty=False)
    handler = ProgressAwareStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_make_record("hello"))

    output = stream.getvalue()
    assert _CLEAR_LINE not in output, (
        f"expected no clear-line escape on non-TTY, got {output!r}"
    )
    assert "hello" in output


def test_handles_stream_without_isatty_method():
    """A stream that lacks isatty() (e.g. some test doubles) must not raise."""

    class _StreamNoIsatty(io.StringIO):
        pass

    stream = _StreamNoIsatty()
    handler = ProgressAwareStreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Treated as non-TTY -- no prefix, no exception.
    handler.emit(_make_record("hello"))

    output = stream.getvalue()
    assert _CLEAR_LINE not in output
    assert "hello" in output


def test_setup_logging_installs_progress_aware_handler_on_stderr():
    """_setup_logging should install a ProgressAwareStreamHandler, not a
    vanilla StreamHandler, so log records mid-progress redraw cleanly."""
    import logging as _logging
    from rapid7_healthcheck.__main__ import _setup_logging

    _setup_logging(verbose=False, log_file=None)

    root = _logging.getLogger()
    progress_aware = [
        h for h in root.handlers if isinstance(h, ProgressAwareStreamHandler)
    ]
    assert len(progress_aware) >= 1, (
        f"expected at least one ProgressAwareStreamHandler on root, "
        f"got handlers={root.handlers}"
    )
