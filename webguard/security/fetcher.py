"""Direct HTTP fetch for the exact origin approved by the CLI."""

import http.client
from time import monotonic

from demo.loopback_fetch import (
    MAX_BODY_BYTES,
    TIMEOUT_SECONDS,
    FetchRefused,
    _check_target,
)
from webguard.core.models import ResponseData
from webguard.security.dialer import AuthorizedTransport
from webguard.security.scope_validator import approved_origin


def fetch(url: str, *, transport: AuthorizedTransport | None = None) -> ResponseData:
    """Fetch one approved loopback resource and refuse redirect responses."""
    if approved_origin(url) is None:
        raise FetchRefused("Target is outside the approved scope")
    host, port, path = _check_target(url)
    if transport is None:
        transport = AuthorizedTransport(
            "http", host, port, host, deadline=monotonic() + TIMEOUT_SECONDS
        )
    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT_SECONDS)
    try:
        peer = transport.connect("http", host, port, TIMEOUT_SECONDS)
        conn.sock = peer
        conn.auto_open = 0
        peer.settimeout(transport.checkpoint(TIMEOUT_SECONDS))
        conn.request(
            "GET",
            path,
            headers={"User-Agent": "WebGuard-demo", "Accept-Encoding": "identity"},
        )
        peer.settimeout(transport.checkpoint(TIMEOUT_SECONDS))
        response = conn.getresponse()
        try:
            if not 200 <= response.status <= 599:
                raise FetchRefused("Invalid final HTTP status")
            if 300 <= response.status < 400:
                raise FetchRefused("Redirects are not followed")
            remaining = transport.checkpoint(TIMEOUT_SECONDS)
            if peer.fileno() != -1:
                peer.settimeout(remaining)
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
            return ResponseData(url, response.status, response.getheaders(), body)
        finally:
            response.close()
    except http.client.HTTPException:
        raise FetchRefused("Invalid HTTP response") from None
    finally:
        conn.close()
