"""
datetime_utils.py — Simple timestamp helper.
Mirrors the main project so security_scanner.py works unchanged.
"""
from datetime import datetime, timezone


def now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
