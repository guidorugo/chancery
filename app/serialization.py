"""Small helpers for turning model fields into JSON-friendly values."""

import json
from datetime import datetime, timezone


def iso(dt):
    """A datetime as an ISO-8601 string, or None."""
    return dt.isoformat() if dt else None


def days_until(dt):
    """Whole days from now (UTC) until `dt`; None if `dt` is None.

    Stored notAfter values are naive UTC, so a naive `dt` is treated as UTC.
    Negative means already past.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - datetime.now(timezone.utc)).days


def expiry_status(dt, warning_days=30):
    """`valid` | `expiring_soon` | `expired` | `unknown` from a notAfter."""
    d = days_until(dt)
    if d is None:
        return "unknown"
    if d < 0:
        return "expired"
    return "expiring_soon" if d <= warning_days else "valid"


def json_or_none(text):
    """Parse a stored JSON text column into an object; None when empty, or the
    raw string if it is not valid JSON (never raises)."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text
