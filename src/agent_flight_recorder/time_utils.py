from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> str:
    """Return an ISO-8601 timestamp with a stable UTC suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

