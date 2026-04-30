"""Console progress status line for long CLI runs.

Writes directly to a stream (default stderr), bypassing the logging system.
Status updates are UX, not diagnostic data — they should not pollute the
default-on log file. On a TTY, status lines overwrite themselves via ``\\r``
and an ANSI clear-line; on a non-TTY (file, CI), each status emits its own
line so the output is greppable.
"""
from __future__ import annotations

import sys
from typing import IO


_CLEAR_LINE = "\r\x1b[K"


class ProgressReporter:
    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._tty = bool(getattr(self._stream, "isatty", lambda: False)())
        self._last_was_status = False

    def step(self, current: int, total: int, label: str) -> None:
        line = f"[{current}/{total}] {label}"
        if self._tty:
            self._stream.write(_CLEAR_LINE + line)
            self._last_was_status = True
        else:
            self._stream.write(line + "\n")
            self._last_was_status = False
        self._stream.flush()

    def done(self, current: int, total: int, label: str, *, duration_ms: int) -> None:
        line = f"[{current}/{total}] {label} ({duration_ms}ms)"
        if self._tty:
            self._stream.write(_CLEAR_LINE + line + "\n")
        else:
            self._stream.write(line + "\n")
        self._last_was_status = False
        self._stream.flush()

    def newline_if_needed(self) -> None:
        """Ensure subsequent output starts on a fresh line.

        Only emits a newline when the previous write was a TTY-mode status
        update (which doesn't end with ``\\n``). Idempotent.
        """
        if self._last_was_status:
            self._stream.write("\n")
            self._last_was_status = False
            self._stream.flush()
