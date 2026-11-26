"""The single place where WebGuard fetches a page.

It re-uses the hardened loopback fetcher: direct connection (no proxy), plain http to a loopback IP only,
no redirects, bounded time and size. The CLI calls it only AFTER validate_target() and the authorization prompt.
"""

from demo.loopback_fetch import FetchRefused, fetch

__all__ = ["FetchRefused", "fetch"]
