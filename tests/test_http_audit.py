"""Short tests for the HTTP Security Auditor. Run: python -m pytest -q"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from demo.loopback_fetch import fetch  # noqa: E402
from demo.servers import HardenedHandler, WeakHandler, start  # noqa: E402
from webguard.auditors.http_audit import audit, check_cookies, summarize  # noqa: E402
from webguard.core.models import ResponseData  # noqa: E402


def ids(findings):
    return {f.check_id for f in findings}


def make(headers, url="https://example.test/"):
    return ResponseData(url=url, status=200, headers=headers)


def test_missing_headers_reported():
    found = ids(audit(make([])))
    assert {"HDR:hsts", "HDR:nosniff", "HDR:clickjacking", "CSP:missing"} <= found


def test_hsts_only_checked_on_https():
    assert "HDR:hsts" not in ids(audit(make([], url="http://127.0.0.1/")))


def test_good_headers_clean():
    headers = [
        ("Strict-Transport-Security", "max-age=31536000"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'self'"),
    ]
    assert audit(make(headers)) == []


def test_csp_unsafe_inline_flagged():
    found = ids(audit(make([("Content-Security-Policy", "script-src 'unsafe-inline'")])))
    assert "CSP:unsafe-inline" in found


def test_frame_ancestors_replaces_xfo():
    found = ids(audit(make([("Content-Security-Policy", "frame-ancestors 'none'")])))
    assert "HDR:clickjacking" not in found


def test_server_version_leak():
    assert "DISC:server" in ids(audit(make([("Server", "Apache/2.4.1")])))


def test_cookie_flags_missing():
    found = ids(check_cookies(make([("Set-Cookie", "sid=abc123")])))
    assert {"COOKIE:secure", "COOKIE:httponly", "COOKIE:samesite"} <= found


def test_cookie_value_never_stored():
    for f in check_cookies(make([("Set-Cookie", "sid=SECRETVALUE")])):
        assert "SECRETVALUE" not in f.to_dict().values().__str__()


def test_sorted_most_severe_first():
    findings = audit(make([("Server", "nginx/1.0")]))
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    ranks = [order.index(f.severity) for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_demo_weak_vs_hardened():
    counts = {}
    for name, handler in (("weak", WeakHandler), ("hard", HardenedHandler)):
        server, url = start(handler)
        try:
            counts[name] = len(audit(fetch(url)))
        finally:
            server.shutdown()
    assert counts["weak"] > counts["hard"]


def test_summarize_counts():
    assert sum(summarize(audit(make([]))).values()) == len(audit(make([])))
