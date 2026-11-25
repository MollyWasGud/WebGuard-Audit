"""Demo fetcher. DIRECT + LOOPBACK ONLY - the real, scope-validated fetcher belongs to Member 4.

Safety rules (review item M1-01):
- only plain http to a loopback IP literal (127.0.0.0/8 or ::1); hostnames such as "localhost" are refused,
  so no DNS lookup can ever happen
- uses http.client directly: it never reads HTTP_PROXY / ALL_PROXY, so traffic cannot be routed via a proxy
- redirects (3xx) are refused, never followed
- short timeout and bounded response size
"""

from __future__ import annotations

import http.client
import ipaddress
from urllib.parse import urlsplit

from webguard.core.models import ResponseData

TIMEOUT_SECONDS = 5
MAX_BODY_BYTES = 200_000


class FetchRefused(PermissionError):
    """The demo fetcher refused to contact the target."""


def _check_target(url: str) -> tuple[str, int, str]:
    try:
        parts = urlsplit(url)
        port = parts.port or 80
    except ValueError:
        raise FetchRefused("Demo fetcher refused: malformed URL.") from None
    if parts.scheme != "http":
        raise FetchRefused("Demo fetcher refused: only plain http to loopback is allowed.")
    if parts.username is not None or parts.password is not None:
        raise FetchRefused("Demo fetcher refused: credentials in the URL are not allowed.")
    host = parts.hostname or ""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False  # a hostname, not an IP literal
    if not is_loopback:
        raise FetchRefused("Demo fetcher refused: target must be a loopback IP address (127.x.x.x or ::1).")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path


def fetch(url: str) -> ResponseData:
    host, port, path = _check_target(url)
    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT_SECONDS)  # direct: no proxy support
    try:
        conn.request("GET", path, headers={"User-Agent": "WebGuard-demo", "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise FetchRefused("Demo fetcher refused: redirects are not followed.")
        body = resp.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
        return ResponseData(url, resp.status, resp.getheaders(), body)
    finally:
        conn.close()
