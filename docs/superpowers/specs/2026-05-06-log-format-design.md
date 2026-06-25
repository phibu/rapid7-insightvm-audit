# Configurable log format

**Date:** 2026-05-06
**Status:** Approved (design); implementation plan pending
**Scope:** Add a configurable file-log format with three options -- `plain` (current behavior), `cmtrace` (SCCM/MECM viewer), and `json` (JSONL).

## Motivation

The tool produces a single text log file alongside each report. Today the format is hardcoded to a Python `logging` format string. Two real operator workflows are not served:

- **Windows / SCCM shops** want CMTrace-formatted logs so operators can open the run log in `cmtrace.exe` and use its severity colorization, component filter, and structured navigation.
- **Centralized logging shops** want JSON Lines so logs can be shipped into Splunk / Loki / OpenSearch without an ingest-side parser.

Both are read-only, additive concerns -- no API surface change, no behavioral change to the audit itself.

## Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Where does the format choice live? | Both: config default + CLI override |
| 2 | Does format apply to stderr too? | No -- file only. Stderr stays human-readable plain. |
| 3 | What does the JSON format emit? | JSONL minimal (fixed key set, no `extra={...}` plumbing) |
| 4 | CMTrace `component` field source? | Python logger name (`record.name`) |
| 5 | Auto-derived file extension when format is JSON? | `.jsonl` when path is auto-derived; explicit `--log-file <path>` is honored verbatim |

## User-facing surface

### CLI

```
--log-format {plain,cmtrace,json}    # overrides config.report.log_format
```

Existing flags unchanged: `--log-file`, `--no-log-file`, `--output`, `--verbose`.

### Config

```yaml
report:
  log_format: plain   # plain (default) | cmtrace | json
```

Lives under the existing `report:` block. Validation: unknown values raise `ConfigError` (consistent with other `report.*` fields).

### Precedence

```
CLI --log-format  >  config report.log_format  >  built-in default ("plain")
```

## The three formats

### plain (default -- unchanged behavior)

```
2026-05-06 14:23:01,123 INFO rapid7_healthcheck: running check: Scan Engines
```

Format string: `%(asctime)s %(levelname)s %(name)s: %(message)s` (the current code path). Exception tracebacks via Python `logging`'s default behavior.

### cmtrace

```
<![LOG[running check: Scan Engines]LOG]!><time="14:23:01.123+000" date="05-06-2026" component="rapid7_healthcheck.checks.scan_engines" context="" type="1" thread="12345" file="scan_engines.py:42">
```

Field rules:

- `<message>` -- `record.getMessage()`. Embedded newlines (e.g. tracebacks) are kept as-is; CMTrace handles multi-line messages inside the `<![LOG[...]LOG]!>` envelope.
- `time` -- local time, format `HH:mm:ss.fff+ZZZ` where `ZZZ` is the local UTC offset in minutes (SCCM convention; e.g. `+060` for UTC+1).
- `date` -- local date, format `MM-dd-yyyy` (SCCM convention).
- `component` -- `record.name` (Python logger name).
- `context` -- always empty string `""` (we have no SCCM context concept).
- `type` -- severity mapping: `DEBUG=1`, `INFO=1`, `WARNING=2`, `ERROR=3`, `CRITICAL=3`.
- `thread` -- `record.thread` (integer thread id).
- `file` -- `record.module + ":" + record.lineno` (e.g. `scan_engines.py:42`). We use the module basename, not the full path, to keep lines short -- CMTrace's "file" filter works on the displayed string.

Exceptions: when `record.exc_info` is set, the formatted traceback is appended to the message inside the `<![LOG[...]LOG]!>` envelope (one CMTrace record, multi-line message).

### json (JSONL)

```
{"ts":"2026-05-06T14:23:01.123Z","level":"INFO","logger":"rapid7_healthcheck.checks.scan_engines","msg":"running check: Scan Engines"}
```

Field rules (one JSON object per line, no surrounding array):

- `ts` -- UTC ISO-8601 with millisecond precision and trailing `Z` (e.g. `2026-05-06T14:23:01.123Z`).
- `level` -- uppercase level name (`DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL`).
- `logger` -- `record.name`.
- `msg` -- `record.getMessage()` (after `%`-formatting of args).
- `exc` -- present only when `record.exc_info` is truthy; value is the formatted traceback string (same content `logging.Formatter.formatException` produces).

No other top-level keys. We do not currently use `logger.info(..., extra={...})` anywhere in the codebase, so adding `extra` plumbing now would be unused capacity; it can be added later without breaking compatibility (new top-level fields are additive for JSONL consumers).

JSON encoding: `json.dumps(obj, ensure_ascii=False, separators=(",", ":"))` -- compact, UTF-8.

## Architecture

### Module: `src/rapid7_healthcheck/_log.py`

Already exists today and exports `FlushingFileHandler`. Extended to also export three formatters and a selector:

- `PlainFormatter` -- `logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")`. Defined here so the format string lives in one place; today it lives inside `_setup_logging`'s `logging.basicConfig(format=...)` call.
- `CMTraceFormatter(logging.Formatter)` -- overrides `format()` to emit the SCCM line shape per the field rules above. Helper for the local-offset string format.
- `JsonFormatter(logging.Formatter)` -- overrides `format()` to emit one JSON object per call.
- `make_file_formatter(log_format: str) -> logging.Formatter` -- switch on the literal value; returns the appropriate formatter instance. Unknown values raise `ValueError` (defensive -- config validation should have caught it earlier).

### `__main__.py` changes

`_parse_args` gains:

```python
p.add_argument(
    "--log-format",
    choices=["plain", "cmtrace", "json"],
    default=None,  # None => fall back to config
    help="File log format. Overrides report.log_format. Stderr is unaffected.",
)
```

`_setup_logging` signature gains a `log_format: str` parameter:

```python
def _setup_logging(verbose: bool, log_file: str | None, log_format: str = "plain") -> None:
    ...
    if log_file:
        try:
            ...
            handler = FlushingFileHandler(log_file, encoding="utf-8")
            handler.setFormatter(make_file_formatter(log_format))
            handlers.append(handler)
        ...
```

The stderr `StreamHandler` keeps the current plain format string. `logging.basicConfig` is still called with `format=...` for the stderr formatter; the file handler now overrides via `setFormatter`.

`_resolve_log_file` signature gains `log_format: str`:

```python
def _resolve_log_file(args: argparse.Namespace, cfg: AppConfig, log_format: str) -> Path | None:
    ...
    # Step 4 (auto-derived) becomes format-aware:
    suffix = ".jsonl" if log_format == "json" else ".log"
    log_name = Path(base).with_suffix(suffix).name
    return Path(cfg.report.output_dir) / log_name
```

Steps 1-3 unchanged: `--no-log-file` returns `None`; explicit `--log-file <p>` returns `Path(p)` verbatim; `--output <p>` returns `Path(p).with_suffix(".log")`. Explicit user paths are never rewritten by the format choice.

In `run()`:

```python
# First-pass logging (stderr only, plain) for config errors -- unchanged.
_setup_logging(args.verbose, log_file=None, log_format="plain")
load_dotenv(override=False)

cfg = load_config(args.config)

# Resolve effective format: CLI > config > default
effective_format = args.log_format or cfg.report.log_format

resolved_log = _resolve_log_file(args, cfg, effective_format)
_setup_logging(
    args.verbose,
    log_file=str(resolved_log) if resolved_log else None,
    log_format=effective_format,
)
```

### `config.py` changes

`ReportConfig` dataclass gains `log_format: str = "plain"`. The existing `report:` block validator gets one new check:

```python
if cfg.report.log_format not in ("plain", "cmtrace", "json"):
    raise ConfigError(
        f"report.log_format: invalid value {cfg.report.log_format!r}; "
        f"must be one of: plain, cmtrace, json"
    )
```

Unknown keys under `report:` already raise per the project rule; the new key is added to the schema, so it parses cleanly.

### `docs/examples/config.yaml`

Add (under existing `report:` block, with a commented sibling for discoverability):

```yaml
  log_format: plain   # plain | cmtrace | json -- file format only; stderr stays plain
```

## Testing

### `tests/test_log_formatters.py` (new)

Build `logging.LogRecord` instances by hand (or via `logger.makeRecord`) and assert on `formatter.format(record)`:

- **PlainFormatter** -- one record with `level=INFO`, name `rapid7_healthcheck`, message `running check: X`. Assert the line matches the existing format (regression guard against accidental drift).
- **CMTraceFormatter**:
  - Envelope present: starts with `<![LOG[`, contains `]LOG]!>`.
  - Severity mapping: `DEBUG → type="1"`, `INFO → type="1"`, `WARNING → type="2"`, `ERROR → type="3"`, `CRITICAL → type="3"`.
  - `component=` equals `record.name`.
  - `time=` matches regex `\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{3}`.
  - `date=` matches regex `\d{2}-\d{2}-\d{4}`.
  - Exception path: a record built with `exc_info` produces a single line whose message contains both the original message and the traceback's last line.
- **JsonFormatter**:
  - Each emit is valid JSON (`json.loads` succeeds).
  - Key set is exactly `{ts, level, logger, msg}` for a record without exception.
  - Key set is exactly `{ts, level, logger, msg, exc}` for a record with exception.
  - `ts` matches `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z`.
  - `level` is uppercase.
  - Non-ASCII message round-trips (e.g. `"München"` survives without `\u` escapes -- `ensure_ascii=False`).

### `tests/test_log_resolution.py` (new -- or extend existing if one materializes)

Use `argparse.Namespace` and a stub `AppConfig`/`ReportConfig` to drive `_resolve_log_file`:

- Auto-derived + `log_format="json"` → suffix is `.jsonl`.
- Auto-derived + `log_format="cmtrace"` → suffix is `.log`.
- Auto-derived + `log_format="plain"` → suffix is `.log` (regression).
- Explicit `--log-file foo.log` + `log_format="json"` → path is `foo.log` (no rewrite).
- `--output report.html` + `log_format="json"` → log path is `report.log` (existing `--output`-derived precedence wins; not rewritten).
- `--no-log-file` + any format → returns `None`.

### Integration: `_setup_logging`

One smoke test asserting that with `log_format="json"`, the file handler's formatter is `JsonFormatter` and stderr's formatter is the plain format string. (Inspect `logger.handlers` after `_setup_logging`.)

### Config validation

Extend the existing config-loading test file (or add `tests/test_config_log_format.py`):

- Loading a config with `report.log_format: cmtrace` succeeds; field round-trips.
- Loading with `report.log_format: yaml` raises `ConfigError`.
- Default value (`log_format` absent in YAML) is `"plain"`.

## Out of scope (deferred to backlog)

- **Run-id / tool-version / host enrichment** for log correlation across runs. Better tackled when we wire up a real run-id concept (related to the report's run hash).
- **Log rotation / retention.** External tools (logrotate, file-rotation libraries, scheduled cleanup) handle this; we don't want to own it.
- **`--console-format` flag.** Stderr stays plain. If demand emerges, add later -- does not break compatibility.
- **`extra={...}` enrichment at call sites.** No current call site uses `extra`. JSONL keeps a fixed minimal shape until there's a real consumer need.
- **Top-level `logging:` config block.** One key (`log_format`) does not justify a new block. If more logging knobs land later (per-logger level, rotation policy), introduce `logging:` then and migrate `report.log_format` with a deprecation alias.

## Read-only safety

This change touches no HTTP code paths. `client.py`, `audit/rules/*`, `audit/snapshot.py`, and the `_REGISTRY` are unaffected. The verb allowlist and `_ALLOWED_POST_PATHS` are not modified. The change adds one new module-internal switch, one new config field, one new CLI flag, and three new formatter classes -- none of which can issue HTTP.
