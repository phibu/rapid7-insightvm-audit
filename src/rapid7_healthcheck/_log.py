"""Logging helpers internal to rapid7_healthcheck.

Public surface:
    FlushingFileHandler — drop-in for logging.FileHandler that flushes the
        underlying stream after every emit, so a tailed log file shows live
        progress during long-running audits.
    PlainFormatter — current default file format; mirrors the legacy
        basicConfig format string exactly.
    CMTraceFormatter — SCCM/MECM CMTrace viewer format. Lets Windows ops
        open run logs in cmtrace.exe with severity colorization and the
        component filter.
    JsonFormatter — JSON Lines (one object per line). For shipping logs
        into Splunk/Loki/OpenSearch.
    make_file_formatter — selector keyed by the literal config string
        ("plain" | "cmtrace" | "json"); used by __main__._setup_logging.
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


_CMTRACE_TYPE_BY_LEVELNO: dict[int, int] = {
    logging.DEBUG: 1,
    logging.INFO: 1,
    logging.WARNING: 2,
    logging.ERROR: 3,
    logging.CRITICAL: 3,
}


def _local_offset_string(record_created: float) -> str:
    """Return CMTrace-style local UTC offset for the record's wall-clock time.

    Format: '+NNN' or '-NNN' where NNN is the offset in minutes (zero-padded
    to three digits). Matches what SCCM client logs emit.
    """
    local = datetime.fromtimestamp(record_created).astimezone()
    offset = local.utcoffset()
    if offset is None:
        return "+000"
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    return f"{sign}{abs(total_minutes):03d}"


class CMTraceFormatter(logging.Formatter):
    """Format log records for the SCCM/MECM CMTrace viewer.

    Line shape:
      <![LOG[<message>]LOG]!><time="HH:mm:ss.fff+ZZZ" date="MM-dd-yyyy"
      component="<logger>" context="" type="<1|2|3>" thread="<tid>"
      file="<module>:<lineno>">
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            # CMTrace handles multi-line messages inside <![LOG[...]LOG]!>; we
            # append the formatted traceback so the exception is visible in the
            # same record (no second envelope).
            exc_text = self.formatException(record.exc_info)
            message = f"{message}\n{exc_text}"

        local = datetime.fromtimestamp(record.created)
        time_str = local.strftime("%H:%M:%S") + f".{int(record.msecs):03d}"
        offset_str = _local_offset_string(record.created)
        date_str = local.strftime("%m-%d-%Y")

        cmtype = _CMTRACE_TYPE_BY_LEVELNO.get(record.levelno, 1)
        component = record.name
        thread_id = record.thread or 0
        # `record.module` is the basename without extension (logging strips it),
        # so we always append ".py" for the CMTrace `file=` field.
        file_field = f"{record.module}.py:{record.lineno}"

        return (
            f"<![LOG[{message}]LOG]!>"
            f'<time="{time_str}{offset_str}" '
            f'date="{date_str}" '
            f'component="{component}" '
            f'context="" '
            f'type="{cmtype}" '
            f'thread="{thread_id}" '
            f'file="{file_field}">'
        )


class JsonFormatter(logging.Formatter):
    """Format log records as one JSON object per line (JSONL).

    Shape: {"ts": "<UTC ISO-8601 with .ms and Z>", "level": "<NAME>",
            "logger": "<record.name>", "msg": "<rendered message>"}
    Adds an "exc" field with the formatted traceback when record.exc_info is set.
    """

    def format(self, record: logging.LogRecord) -> str:
        # UTC ISO-8601 with millisecond precision, trailing Z.
        utc = datetime.fromtimestamp(record.created, tz=timezone.utc)
        ts = utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z"

        obj: dict[str, object] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return _json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def make_file_formatter(log_format: str) -> logging.Formatter:
    """Return the file-log formatter matching the requested string.

    Defensive — config validation should have caught unknown values upstream.
    """
    if log_format == "plain":
        return PlainFormatter()
    if log_format == "cmtrace":
        return CMTraceFormatter()
    if log_format == "json":
        return JsonFormatter()
    raise ValueError(f"unknown log_format: {log_format!r}")
