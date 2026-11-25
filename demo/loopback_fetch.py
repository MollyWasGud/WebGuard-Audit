"""Tiny fetcher for the demo. LOOPBACK ONLY - the real, scope-validated fetcher belongs to Member 4."""

from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

from webguard.core.models import ResponseData

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def fetch(url: str) -> ResponseData:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise PermissionError(f"Demo fetcher only talks to loopback hosts, refused '{host}'.")
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (host checked above)
        body = resp.read(200_000).decode("utf-8", errors="replace")
        return ResponseData(url, resp.status, list(resp.headers.items()), body)
