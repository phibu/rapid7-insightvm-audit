from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _coerce_positive_int(value, *, name: str, default: int) -> int:
    """Return value as a positive int; fall back to ``default`` on bad input.

    Rejects ``True``/``False`` (bool is an int subclass -- accepting it is
    almost always a user typo). Rejects floats with a fractional part
    (``0.5`` silently truncating to ``0`` would set the threshold equal
    to ``now()`` and flag every engine as stale). Rejects zero and
    negatives. Anything rejected logs a warning and falls back to
    ``default`` rather than raising -- rule loaders that aren't validated
    upstream shouldn't take down the whole audit on one typo.
    """
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); using default %d", name, value, default)
        return default
    if isinstance(value, float):
        if not value.is_integer():
            logger.warning(
                "ignoring %s=%r (fractional values truncate to a threshold of "
                "now() and flag everything); using default %d",
                name, value, default,
            )
            return default
        value = int(value)
    if isinstance(value, int) and value > 0:
        return value
    logger.warning("ignoring %s=%r (must be a positive int); using default %d", name, value, default)
    return default


def _coerce_positive_float(value, *, name: str, default: float) -> float:
    """Return value as a positive float; fall back to ``default`` on bad input.

    Rejects ``True``/``False`` (bool is an int subclass -- almost always a
    typo), non-numeric strings, ``NaN``/``inf``, and values <= 0 (a
    percentage threshold of 0 or below fires on any stale asset at all).
    Anything rejected logs a warning and falls back rather than raising --
    one config typo must not take down the whole audit.
    """
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); using default %s", name, value, default)
        return default
    try:
        coerced = float(value)
    except (TypeError, ValueError):
        logger.warning("ignoring %s=%r (not a number); using default %s", name, value, default)
        return default
    if coerced != coerced or coerced in (float("inf"), float("-inf")):
        logger.warning("ignoring %s=%r (NaN/inf not accepted); using default %s", name, value, default)
        return default
    if coerced <= 0:
        logger.warning("ignoring %s=%r (must be positive); using default %s", name, value, default)
        return default
    return coerced


def _coerce_optional_positive_int(value, *, name: str) -> int | None:
    """Return value as a positive int, or ``None`` if unset/invalid.

    Unlike ``_coerce_positive_int`` there is no default -- an absent or
    invalid ``max_stale_count`` simply disables the count-based trigger.
    Rejects bool, non-numeric input, fractional floats, and values <= 0.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        logger.warning("ignoring %s=%r (bool not accepted); count trigger disabled", name, value)
        return None
    if isinstance(value, float):
        if not value.is_integer():
            logger.warning("ignoring %s=%r (must be a whole number); count trigger disabled", name, value)
            return None
        value = int(value)
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        logger.warning("ignoring %s=%r (not an integer); count trigger disabled", name, value)
        return None
    if coerced <= 0:
        logger.warning("ignoring %s=%r (must be positive); count trigger disabled", name, value)
        return None
    return coerced
