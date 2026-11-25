"""Regression tests for review item M1-01: the demo fetcher must stay direct and loopback-only. All offline."""

import http.client
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from demo.loopback_fetch import MAX_BODY_BYTES, FetchRefused, fetch  # noqa: E402
from demo.servers import WeakHandler, start  # noqa: E402


@pytest.mark.parametrize("url", [
    "http://localhost:1/",                 # hostname: would need DNS
    "http://example.com/",                 # not loopback
    "http://127.0.0.1.evil.test/",         # look-alike hostname
    "http://127.0.0.1@evil.test/",         # credentials trick: real host is evil.test
    "http://user:pw@127.0.0.1/",           # credentials in URL
    "https://127.0.0.1/",                  # only plain http
    "ftp://127.0.0.1/",
    "http://10.0.0.5/",                    # private, not loopback
    "http://0.0.0.0/",
    "http://127.0.0.1:notaport/",
])
def test_refused_before_any_connection(url, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("a connection was attempted for a refused target")
    monkeypatch.setattr(http.client.HTTPConnection, "connect", boom)
    with pytest.raises(FetchRefused):
        fetch(url)


def test_proxy_environment_is_ignored(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")   # a closed port: any proxy use would fail
    server, url = start(WeakHandler)
    try:
        assert fetch(url).status == 200
    finally:
        server.shutdown()


def test_redirect_is_refused_and_not_followed():
    hits = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    target = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/secret")
            self.end_headers()

        def log_message(self, *args):
            pass

    server, url = start(Redirector)
    try:
        with pytest.raises(FetchRefused):
            fetch(url)
    finally:
        server.shutdown()
        target.shutdown()
    assert hits == []   # the redirect target was never contacted


def test_response_body_is_bounded():
    class Big(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"A" * (MAX_BODY_BYTES * 3)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, url = start(Big)
    try:
        assert len(fetch(url).body) <= MAX_BODY_BYTES
    finally:
        server.shutdown()
