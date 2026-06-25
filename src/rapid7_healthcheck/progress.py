"""Console progress status line for long CLI runs.

Hierarchical (#28): the run has an *outer* scope (the checks, e.g. ``[4/8]``)
and an *inner* scope (an audit category's rules). The two used to share one
flat counter, producing the confusing ``[1/8]…[1/11]…[5/8]`` interleave. Now a
check renders a global-percent line and its rules indent one level beneath it
with human-readable names and a real status (duration / skipped / cached / n/a)
-- never a misleading ``0ms``.

Writes directly to a stream (default stderr), bypassing the logging system.
Status updates are UX, not diagnostic data -- they should not pollute the
default-on log file. On a TTY, status lines overwrite themselves via ``\\r`` and
an ANSI clear-line; on a non-TTY (file, CI), each status emits its own line so
the output is greppable.
"""
from __future__ import annotations

import sys
from typing import IO


_CLEAR_LINE = "\r\x1b[K"

# Indent for an inner (rule) line beneath its check.
_RULE_INDENT = "    └ "


def format_duration(duration_ms: int) -> str:
    """Human-readable duration: ``88ms``, ``1.4s``, ``2m03s``.

    Used for the status text on finished checks/rules. Sub-second stays in ms;
    seconds get one decimal; minutes switch to ``MmSSs``.
    """
    if duration_ms < 1000:
        return f"{duration_ms}ms"
    seconds = duration_ms / 1000.0
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"


class ProgressReporter:
    def __init__(
        self,
        stream: IO[str] | None = None,
        *,
        enabled: bool | None = None,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        is_tty = bool(getattr(self._stream, "isatty", lambda: False)())
        if enabled is None:
            # Default: emit on both TTY (overwrite-in-place) and non-TTY
            # (one line per call, greppable). Preserves pre-0.3.6 behavior.
            self._enabled = True
            self._tty = is_tty
        else:
            self._enabled = enabled
            # Explicit enabled=True on a non-TTY stream uses the line-per-call
            # format -- never blast \r\x1b[K into a redirected file or pipe.
            self._tty = enabled and is_tty
        self._last_was_status = False

    def _write_safely(self, s: str) -> None:
        if not self._enabled:
            return
        try:
            self._stream.write(s)
            self._stream.flush()
        except OSError:
            self._enabled = False

    def _emit(self, line: str, *, transient: bool) -> None:
        """Write one status line.

        ``transient`` lines (an in-progress check/rule on a TTY) overwrite in
        place and leave the cursor parked for the next overwrite. A non-transient
        line (a finished check/rule, or any line on a non-TTY) terminates with a
        newline so it persists.
        """
        if self._tty:
            if transient:
                self._write_safely(_CLEAR_LINE + line)
                self._last_was_status = True
            else:
                self._write_safely(_CLEAR_LINE + line + "\n")
                self._last_was_status = False
        else:
            self._write_safely(line + "\n")
            self._last_was_status = False

    # --- Outer scope: checks -------------------------------------------------

    def start_check(self, idx: int, total: int, name: str) -> None:
        """Announce a check is starting. The global percent is the *completed*
        fraction so far (``(idx-1)/total``)."""
        pct = int((idx - 1) / total * 100) if total else 0
        self._emit(f"[{pct:3d}%] ({idx}/{total}) {name}", transient=True)

    def finish_check(self, idx: int, total: int, name: str, *, status_text: str) -> None:
        """Announce a check finished. The global percent is ``idx/total``;
        ``status_text`` is a duration (``1.4s``) or a word (``skipped``)."""
        pct = int(idx / total * 100) if total else 100
        self._emit(f"[{pct:3d}%] ({idx}/{total}) {name} ({status_text})", transient=False)

    # --- Inner scope: an audit category's rules ------------------------------

    def start_rule(self, name: str) -> None:
        """Announce a rule is starting, indented under the current check."""
        self._emit(f"{_RULE_INDENT}{name}", transient=True)

    def finish_rule(self, name: str, *, status_text: str) -> None:
        """Announce a rule finished, indented under the current check.
        ``status_text`` is a duration or one of ``skipped`` / ``cached`` /
        ``n/a`` -- never a misleading ``0ms``."""
        self._emit(f"{_RULE_INDENT}{name} ({status_text})", transient=False)

    def newline_if_needed(self) -> None:
        """Ensure subsequent output starts on a fresh line.

        Only emits a newline when the previous write was a TTY-mode transient
        status update (which doesn't end with ``\\n``). Idempotent.
        """
        if self._last_was_status:
            self._write_safely("\n")
            self._last_was_status = False
