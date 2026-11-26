
"""Scope validation safeguards for WebGuard Audit."""

from ipaddress import ip_address
from unicodedata import category
from urllib.parse import urlsplit

APPROVED_SCOPE = {
    ("http", "127.0.0.1:8000"): ("127.0.0.1", 8000),
    ("https", "127.0.0.1:8443"): ("127.0.0.1", 8443),
}


def _origin_key(target: str) -> tuple[str, str] | None:
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
        return parsed.scheme, parsed.netloc.lower()
    except ValueError:
        return None


def approved_origin(target: str) -> str | None:
    """Return the display origin only for a valid, approved target."""
    origin = _origin_key(target)
    if origin is None or origin not in APPROVED_SCOPE:
        return None
    return f"{origin[0]}://{origin[1]}"


def approved_http_endpoint(target: str) -> tuple[str, int] | None:
    """Return the configured numeric loopback endpoint for a plain HTTP target."""
    origin = _origin_key(target)
    if origin is None or origin[0] != "http":
        return None
    endpoint = APPROVED_SCOPE.get(origin)
    if endpoint is None:
        return None
    host, port = endpoint
    try:
        if ip_address(host).is_loopback and 1 <= port <= 65535:
            return endpoint
    except ValueError:
        return None
    return None


def validate_target(target: str) -> bool:
    return approved_origin(target) is not None
