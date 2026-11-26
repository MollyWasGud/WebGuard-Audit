
"""Scope validation safeguards for WebGuard Audit."""

from unicodedata import category
from urllib.parse import urlsplit

APPROVED_SCOPE = {
    ("http", "127.0.0.1:8000"),
    ("https", "127.0.0.1:8443"),
}


def approved_origin(target: str) -> str | None:
    """Return the display origin only for a valid, approved target."""
    if not target or any(c.isspace() or category(c) in {"Cc", "Cf"} for c in target):
        return None
    if any(delimiter in target for delimiter in "\\?#"):
        return None
    try:
        parsed = urlsplit(target)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
        ):
            return None
        origin = (parsed.scheme, parsed.netloc.lower())
        return f"{origin[0]}://{origin[1]}" if origin in APPROVED_SCOPE else None
    except ValueError:
        return None


def validate_target(target: str) -> bool:
    return approved_origin(target) is not None
