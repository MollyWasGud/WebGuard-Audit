
"""Scope validation safeguards for WebGuard Audit."""

from urllib.parse import urlsplit

# Approved targets for local development and testing.
APPROVED_SCOPE = {
    ("http", "127.0.0.1:8000"),
}


def validate_target(target: str) -> bool:
    """Check whether a target is within the approved scope."""

    if not target or any(c.isspace() for c in target):
        return False

    if "\\" in target:
        return False

    try:
        parsed = urlsplit(target)

        # Only allow HTTP and HTTPS.
        if parsed.scheme not in ("http", "https"):
            return False

        # Reject missing hostnames.
        if not parsed.hostname:
            return False

        # Reject URLs containing login credentials.
        if parsed.username is not None or parsed.password is not None:
            return False

        # Initially allow only the approved root URL.
        if parsed.path not in ("", "/"):
            return False

        if parsed.query or parsed.fragment:
            return False

        # Check the exact scheme, hostname and port.
        origin = (parsed.scheme, parsed.netloc.lower())

        return origin in APPROVED_SCOPE

    except ValueError:
        return False
