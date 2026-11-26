"""Two LOCAL demo web servers (127.0.0.1 only): one deliberately weak, one hardened - for before/after demos."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

LOOPBACK = "127.0.0.1"


class WeakHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><!-- TODO: remove admin password before release --><body>Welcome</body></html>"
        self.send_response(200)
        for key, value in [
            ("Content-Type", "text/html"),
            ("X-Powered-By", "PHP/7.2.1"),
            ("X-Backend-Server", "10.0.3.17"),
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Security-Policy", "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'"),
            ("Set-Cookie", "PHPSESSID=demo-not-a-real-session; Path=/"),
            ("Set-Cookie", "theme=dark; Path=/"),
        ]:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the demo output clean
        pass


class HardenedHandler(WeakHandler):
    def version_string(self):
        return "webserver"

    def do_GET(self):
        body = b"<html><body>Welcome</body></html>"
        self.send_response(200)
        for key, value in [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Security-Policy", "default-src 'none'; script-src 'self' 'nonce-Zm9vYmFy'; style-src 'self'; "
                                        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("X-Content-Type-Options", "nosniff"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Cache-Control", "no-store"),
            ("Set-Cookie", "__Host-session=demo-not-a-real-session; Path=/; Secure; HttpOnly; SameSite=Strict"),
        ]:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(handler) -> tuple[HTTPServer, str]:
    """Start a demo server on a free loopback port in a background thread."""
    server = HTTPServer((LOOPBACK, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{LOOPBACK}:{server.server_address[1]}/"
