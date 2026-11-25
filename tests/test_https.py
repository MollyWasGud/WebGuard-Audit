import errno
import gc
import http.client
import io
import json
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import Future
from contextlib import contextmanager
from threading import Thread
from unittest.mock import MagicMock

import pytest

# Member 2 verification uses pytest's default prepend mode for sibling imports.
# Importlib mode requires tests/ on sys.path.
import test_tls

from webguard.auditors import https

_RESPONSE = b"HTTP/1.1 %d Test\r\nConnection: close\r\nContent-Length: 7\r\n%s\r\n"
_TRUNCATED_HEADERS = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"


class ResponseStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size=-1):
        data = super().read(size)
        self.bytes_read = self.tell()
        return data

    def readline(self, size=-1):
        line = super().readline(size)
        self.bytes_read = self.tell()
        return line


@pytest.fixture
def offline_https(monkeypatch):
    tcp = MagicMock(spec=socket.socket)
    tls_socket = MagicMock(spec=ssl.SSLSocket)
    connect = MagicMock(return_value=tcp)
    wrap = MagicMock(return_value=tls_socket)
    resolve = MagicMock(side_effect=AssertionError("Unexpected real DNS lookup"))
    proxies = MagicMock(side_effect=AssertionError("Unexpected proxy discovery"))

    def wrap_socket(context, sock, *, server_hostname, **options):
        return wrap(context, sock, server_hostname=server_hostname, **options)

    def respond(data):
        stream = ResponseStream(data)
        tls_socket.makefile.return_value = stream
        return stream

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)
    monkeypatch.setattr(urllib.request, "getproxies", proxies)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    return tcp, tls_socket, connect, wrap, resolve, proxies, respond


@pytest.mark.parametrize(
    ("status", "redirect"),
    [
        (200, False),
        (300, True),
        (301, True),
        (302, True),
        (303, True),
        (304, False),
        (307, True),
        (308, True),
        (403, False),
        (404, False),
        (405, False),
        (501, False),
        (503, False),
    ],
)
def test_final_https_response_establishes_availability(offline_https, status, redirect):
    _, stream_socket, connect, _, resolve, proxies, respond = offline_https
    headers = _RESPONSE % (status, b"Location: https://redirect.invalid/private\r\n")
    response = respond(headers + b"PAYLOAD")

    result = https.audit_https_availability("example.test")

    assert result["outcome"] == "available"
    assert result["http_status"] == status and result["is_redirect"] is redirect
    assert result["failed_stage"] is result["verify_code"] is None
    connect.assert_called_once()
    resolve.assert_not_called()
    proxies.assert_not_called()
    stream_socket.makefile.assert_called_once()
    wire = b"".join(call.args[0] for call in stream_socket.sendall.call_args_list)
    request, body = wire.split(b"\r\n\r\n", 1)
    request_line, *sent_headers = request.split(b"\r\n")
    assert request_line == b"HEAD / HTTP/1.1" and body == b""
    sent = dict(header.lower().split(b": ", 1) for header in sent_headers)
    assert sent[b"connection"] == b"close"
    assert sent.keys().isdisjoint({b"authorization", b"proxy-authorization", b"cookie"})
    assert response.bytes_read == len(headers)
    assert response.closed
    stream_socket.close.assert_called()
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize(
    ("hostname", "port", "lookup", "identity", "authority"),
    [
        (
            "b\u00fccher.example",
            443,
            "xn--bcher-kva.example",
            "xn--bcher-kva.example",
            b"xn--bcher-kva.example",
        ),
        ("example.test.", 8443, "example.test.", "example.test", b"example.test:8443"),
        ("2001:db8::1", 443, "2001:db8::1", "2001:db8::1", b"[2001:db8::1]"),
        ("2001:db8::1", 8443, "2001:db8::1", "2001:db8::1", b"[2001:db8::1]:8443"),
    ],
)
def test_verified_https_uses_correct_lookup_identity_and_host_authority(
    offline_https, hostname, port, lookup, identity, authority
):
    tcp, stream_socket, connect, wrap, _, _, respond = offline_https
    respond(_RESPONSE % (200, b""))

    result = https.audit_https_availability(hostname, port, timeout=2.0)

    assert result["outcome"] == "available"
    assert result["target"] == {"hostname": identity, "port": port}
    connect.assert_called_once()
    assert connect.call_args.args[0] == (lookup, port)
    args, kwargs = connect.call_args
    assert (args[1] if len(args) > 1 else kwargs["timeout"]) == 2.0
    wrap.assert_called_once()
    context, sock = wrap.call_args.args
    assert sock is tcp and wrap.call_args.kwargs["server_hostname"] == identity
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    wire = b"".join(call.args[0] for call in stream_socket.sendall.call_args_list)
    assert [
        line for line in wire.split(b"\r\n") if line.lower().startswith(b"host:")
    ] == [b"Host: " + authority]


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        pytest.param(b"", "transport_error", id="remote-disconnected"),
        pytest.param(b"garbage\r\n\r\n", "invalid_http_response", id="bad-status-line"),
        pytest.param(
            _TRUNCATED_HEADERS, "invalid_http_response", id="missing-header-terminator"
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nContent-Len",
            "invalid_http_response",
            id="partial-header",
        ),
        pytest.param(
            b"HTTP/1.1 099 Invalid\r\n\r\n", "invalid_http_response", id="below-range"
        ),
        pytest.param(
            b"HTTP/1.1 600 Invalid\r\n\r\n", "invalid_http_response", id="above-range"
        ),
        pytest.param(
            b"HTTP/1.1 103 Early Hints\r\n\r\n",
            "unsupported_http_response",
            id="interim",
        ),
        pytest.param(
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            "unsupported_http_response",
            id="upgrade",
        ),
    ],
)
def test_https_classifies_raw_response_failures(offline_https, wire, expected):
    _, stream_socket, connect, _, _, _, respond = offline_https
    response = respond(wire)

    result = https.audit_https_availability("example.test")

    assert result["outcome"] == expected
    assert result["failed_stage"] == "response"
    assert (
        result["http_status"] is result["is_redirect"] is result["verify_code"] is None
    )
    connect.assert_called_once()
    assert response.closed
    stream_socket.close.assert_called()


def test_stdlib_parser_accepts_eof_instead_of_header_terminator():
    sock = MagicMock(spec=ssl.SSLSocket)
    sock.makefile.return_value = io.BytesIO(_TRUNCATED_HEADERS)
    with http.client.HTTPResponse(sock, method="HEAD") as response:
        response.begin()
        assert response.status == 200


def _certificate_error(verify_code):
    error = ssl.SSLCertVerificationError("peer certificate could not be verified")
    if verify_code is not None:
        error.verify_code = verify_code
    return error


@pytest.mark.parametrize(
    ("stage", "error", "outcome", "verify_code"),
    [
        ("connect", ConnectionRefusedError("refused"), "connection_refused", None),
        ("connect", TimeoutError("connect timeout"), "timeout", None),
        ("connect", socket.gaierror("resolver error"), "transport_error", None),
        ("handshake", _certificate_error(20), "certificate_verification_failed", 20),
        (
            "handshake",
            _certificate_error(None),
            "certificate_verification_failed",
            None,
        ),
        ("handshake", ssl.SSLError("TLS handshake failure"), "tls_error", None),
        ("request", ConnectionResetError("reset"), "transport_error", None),
        ("response", TimeoutError("header timeout"), "timeout", None),
        ("response", OSError(errno.EIO, "read error"), "transport_error", None),
    ],
    ids=[
        "refusal",
        "connect-timeout",
        "resolver-error",
        "cert-with-code",
        "cert-without-code",
        "tls-error",
        "request-reset",
        "response-timeout",
        "response-io-error",
    ],
)
def test_https_errors_preserve_phase_and_close_acquired_resources(
    offline_https, stage, error, outcome, verify_code
):
    tcp, stream_socket, connect, wrap, _, _, respond = offline_https
    response = respond(b"") if stage == "response" else None
    if response is not None:
        response.readline = MagicMock(side_effect=error)
    failing_call = {
        "connect": connect,
        "handshake": wrap,
        "request": stream_socket.sendall,
    }.get(stage)
    if failing_call is not None:
        failing_call.side_effect = error

    result = https.audit_https_availability("example.test")

    assert (result["outcome"], result["failed_stage"], result["verify_code"]) == (
        outcome,
        stage,
        verify_code,
    )
    assert result["http_status"] is result["is_redirect"] is None
    connect.assert_called_once()
    if stage == "connect":
        wrap.assert_not_called()
    elif stage == "handshake":
        tcp.close.assert_called()
        stream_socket.sendall.assert_not_called()
    else:
        stream_socket.close.assert_called()
    if response is not None:
        assert response.closed
    json.dumps(result, allow_nan=False)


def test_cleanup_error_does_not_replace_request_failure(offline_https):
    _, stream_socket, connect, _, _, _, _ = offline_https
    stream_socket.sendall.side_effect = ConnectionResetError("send reset")
    stream_socket.close.side_effect = OSError("close failed")

    result = https.audit_https_availability("example.test")

    assert (result["outcome"], result["failed_stage"]) == ("transport_error", "request")
    stream_socket.close.assert_called()
    connect.assert_called_once()


@pytest.mark.parametrize(
    ("field", "value", "target"),
    [
        pytest.param(
            "hostname",
            "https://user:secret@example.test/",
            (None, 443),
            id="sensitive-url",
        ),
        pytest.param(
            "hostname",
            "example.test\r\nx-injected: value",
            (None, 443),
            id="header-injection",
        ),
        pytest.param("hostname", "xn--0.test", (None, 443), id="invalid-idna"),
        pytest.param("hostname", "fe80::1%3", (None, 443), id="scoped-ipv6"),
        pytest.param("port", 1 << 15000, ("example.test", None), id="oversized-port"),
        pytest.param("port", True, ("example.test", None), id="boolean-port"),
        pytest.param("timeout", float("nan"), ("example.test", 443), id="nan-timeout"),
        pytest.param(
            "timeout", float("inf"), ("example.test", 443), id="infinite-timeout"
        ),
        pytest.param(
            "timeout", 1 << 15000, ("example.test", 443), id="oversized-timeout"
        ),
    ],
)
def test_invalid_https_input_never_attempts_network(
    offline_https, field, value, target
):
    _, stream_socket, connect, wrap, resolve, proxies, _ = offline_https
    options = {"hostname": "example.test", "port": 443, "timeout": 5.0}
    options[field] = value

    result = https.audit_https_availability(**options)

    assert (result["outcome"], result["failed_stage"]) == (
        "invalid_input",
        "validation",
    )
    assert result["target"] == dict(zip(("hostname", "port"), target, strict=True))
    assert (
        result["http_status"] is result["is_redirect"] is result["elapsed_ms"] is None
    )
    for operation in (connect, wrap, resolve, proxies, stream_socket.sendall):
        operation.assert_not_called()
    encoded = json.dumps(result, allow_nan=False)
    assert "user:secret" not in encoded and "x-injected" not in encoded


def test_elapsed_milliseconds_follow_monotonic_time(offline_https, monkeypatch):
    _, _, connect, _, _, _, respond = offline_https
    respond(_RESPONSE % (200, b""))
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def connect_with_clock(*args, **kwargs):
        clock[0] += 0.125
        return connect.return_value

    connect.side_effect = connect_with_clock

    result = https.audit_https_availability("example.test")

    assert result["elapsed_ms"] == pytest.approx(125.0)


_VALID_HTTP_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
_CONTINUE_HEAD = b"HTTP/1.1 100 Continue\r\n\r\n"


@pytest.mark.parametrize(
    ("wire", "outcome"),
    [
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test: a\x00b\r\n\r\n",
            "invalid_http_response",
            id="nul-in-field-value",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test: a\rX-Other: b\r\n\r\n",
            "invalid_http_response",
            id="bare-cr-in-field",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nBad@Name: value\r\n\r\n",
            "invalid_http_response",
            id="invalid-field-name",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test : value\r\n\r\n",
            "invalid_http_response",
            id="whitespace-before-colon",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test: value\r\n folded\r\n\r\n",
            "invalid_http_response",
            id="obsolete-line-folding",
        ),
        pytest.param(
            b"HTTP/1.1 200 O\x00K\r\n\r\n",
            "invalid_http_response",
            id="nul-in-reason-phrase",
        ),
        pytest.param(
            b"HTTP/1.1 200\r\n\r\n",
            "invalid_http_response",
            id="missing-reason-phrase-separator",
        ),
        pytest.param(
            b"HTTP/1.1 100 Continue\r\nbroken header\r\n\r\n" + _VALID_HTTP_HEAD,
            "invalid_http_response",
            id="malformed-continue",
        ),
        pytest.param(
            b"HTTP/0.9 200 OK\r\n\r\n",
            "unsupported_http_response",
            id="synthetic-http09",
        ),
        pytest.param(
            b"HTTP/9.9 100 Continue\r\n\r\n" + _VALID_HTTP_HEAD,
            "unsupported_http_response",
            id="unsupported-version-on-continue",
        ),
        pytest.param(
            b"HTTP/1.1 103 Early Hints\r\n\r\n" + _VALID_HTTP_HEAD,
            "unsupported_http_response",
            id="early-hints-before-final",
        ),
        pytest.param(
            _TRUNCATED_HEADERS, "invalid_http_response", id="incomplete-final-head"
        ),
        pytest.param(
            b"HTTP/1.1 200 " + b"a" * http.client._MAXLINE + b"\r\n\r\n",
            "invalid_http_response",
            id="overlong-status-line",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test: " + b"a" * http.client._MAXLINE + b"\r\n\r\n",
            "invalid_http_response",
            id="overlong-field-line",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\n"
            + b"X-Test: value\r\n" * http.client._MAXHEADERS
            + b"\r\n",
            "invalid_http_response",
            id="too-many-fields",
        ),
        pytest.param(
            _CONTINUE_HEAD * 8 + _VALID_HTTP_HEAD,
            "invalid_http_response",
            id="too-many-response-heads",
        ),
        pytest.param(b"HTTP/1.0 200 OK\r\n\r\n", "available", id="http10"),
        pytest.param(b"HTTP/1.1 200 \r\n\r\n", "available", id="http11-empty-reason"),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-!#$%&'*+.^_\x60|~: \tA z~\x80\xff\t \r\nEmpty:\r\n\r\n",
            "available",
            id="permitted-field-bytes",
        ),
        pytest.param(
            b"HTTP/1.1 100 Continue\r\nX-Test: \tvalue\x80\r\n\r\n" + _VALID_HTTP_HEAD,
            "available",
            id="valid-continue-before-final",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX: " + b"a" * (http.client._MAXLINE - 5) + b"\r\n\r\n",
            "available",
            id="field-line-at-limit",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\n"
            + b"X-Test: value\r\n" * (http.client._MAXHEADERS - 1)
            + b"\r\n",
            "available",
            id="field-count-at-limit",
        ),
        pytest.param(
            _CONTINUE_HEAD * 7 + _VALID_HTTP_HEAD,
            "available",
            id="response-heads-at-limit",
        ),
    ],
)
def test_https_response_head_wire_syntax_and_limits(offline_https, wire, outcome):
    _, stream_socket, connect, _, _, _, respond = offline_https
    response = respond(wire)

    result = https.audit_https_availability("example.test")

    assert result["outcome"] == outcome
    if outcome == "available":
        assert (
            result["failed_stage"],
            result["http_status"],
            result["is_redirect"],
        ) == (
            None,
            200,
            False,
        )
    else:
        assert result["failed_stage"] == "response"
        assert result["http_status"] is result["is_redirect"] is None
    connect.assert_called_once()
    assert response.closed
    stream_socket.close.assert_called()


local_tls_certificate = test_tls.local_tls_certificate

_HTTPS_LOOPBACK = "127.0.0.1"
_HTTPS_SERVER_TIMEOUT = 5.0
_HTTPS_CLIENT_TIMEOUT = 2.0
_HTTPS_REQUEST_LIMIT = 8192
_HTTPS_RESPONSE_200 = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)


def _read_local_request_head(peer):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        chunk = peer.recv(_HTTPS_REQUEST_LIMIT - len(request))
        assert chunk, "Client closed or exceeded the request-head limit"
        request.extend(chunk)
    return bytes(request)


def _observe_plain_http_request(listener, wire):
    peer, address = listener.accept()
    with peer:
        assert address[0] == _HTTPS_LOOPBACK
        peer.settimeout(_HTTPS_SERVER_TIMEOUT)
        request = _read_local_request_head(peer)
        peer.sendall(wire)
        assert peer.recv(1) == b"", "Expected EOF after one request"
    assert peer.fileno() == -1
    return request, None


def _observe_https_request(listener, context, wire):
    peer, address = listener.accept()
    with peer:
        assert address[0] == _HTTPS_LOOPBACK
        peer.settimeout(_HTTPS_SERVER_TIMEOUT)
        with context.wrap_socket(
            peer, server_side=True, do_handshake_on_connect=False
        ) as tls_socket:
            try:
                tls_socket.do_handshake()
            except (
                ssl.SSLError,
                ConnectionAbortedError,
                ConnectionResetError,
            ) as error:
                observation = (None, error)
            else:
                request = _read_local_request_head(tls_socket)

                if wire is not None:
                    tls_socket.sendall(wire)
                if wire is not None and not wire.endswith(b"\r\n\r\n"):
                    # Send close_notify so the client sees EOF inside TLS.
                    try:
                        peer_after_tls = tls_socket.unwrap()
                    except (ssl.SSLEOFError, ConnectionResetError):
                        pass
                    else:
                        assert peer_after_tls.recv(1) == b"", (
                            "Expected EOF after one request"
                        )
                else:
                    assert tls_socket.recv(1) == b"", "Expected EOF after one request"
                observation = (request, None)
        assert tls_socket.fileno() == -1
    assert peer.fileno() == -1
    return observation


@pytest.fixture
def local_https_server(local_tls_certificate):
    context, ca_pem = local_tls_certificate

    @contextmanager
    def serve(wire, *, use_tls=True):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(_HTTPS_SERVER_TIMEOUT)
            listener.bind((_HTTPS_LOOPBACK, 0))
            listener.listen(1)
            host, port = listener.getsockname()
            assert host == _HTTPS_LOOPBACK
            observed = Future()

            def run():
                try:
                    result = (
                        _observe_https_request(listener, context, wire)
                        if use_tls
                        else _observe_plain_http_request(listener, wire)
                    )
                    observed.set_result(result)
                except Exception as error:  # noqa: BLE001 - Relay worker failures to pytest.
                    observed.set_exception(error)

            worker = Thread(target=run, name="webguard-loopback-https", daemon=True)
            worker.start()
            try:
                yield port, ca_pem, observed
            finally:
                worker.join(timeout=4 * _HTTPS_SERVER_TIMEOUT + 1)
                assert not worker.is_alive(), "Local HTTPS server did not stop"
        assert listener.fileno() == -1

    return serve


def _audit_local_https(
    server, hostname, trust_ca, monkeypatch, record_property, *, redirect_scheme=None
):
    port, ca_pem, observed = server
    connect = socket.create_connection
    getaddrinfo = socket.getaddrinfo
    attempts = []
    lookups = []
    tcp_sockets = []
    tls_sockets = []
    writes = []
    responses = []

    class ObservedSSLSocket(ssl.SSLSocket):
        def do_handshake(self, block=False):
            tls_sockets.append(self)
            assert self.getpeername() == (_HTTPS_LOOPBACK, port)
            assert self.gettimeout() == _HTTPS_CLIENT_TIMEOUT
            return super().do_handshake(block)

        def sendall(self, data, flags=0):
            writes.append(bytes(data))
            return super().sendall(data, flags)

    class ObservedResponse(https._CompleteHTTPResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            responses.append(self)

    def loopback_connect(address, timeout, **kwargs):
        attempts.append(address)
        assert address == (hostname, port)
        assert timeout == _HTTPS_CLIENT_TIMEOUT
        peer = connect((_HTTPS_LOOPBACK, port), timeout, **kwargs)
        tcp_sockets.append(peer)
        return peer

    def loopback_lookup(host, *args, **kwargs):
        lookups.append(host)
        assert host == _HTTPS_LOOPBACK
        return getaddrinfo(host, *args, **kwargs)

    def unexpected_proxy_discovery():
        pytest.fail("Direct audit attempted proxy discovery")

    context = None
    if redirect_scheme != "http":
        context = https._create_verified_client_context()
        if trust_ca:
            context.load_verify_locations(cadata=ca_pem)
        context.sslsocket_class = ObservedSSLSocket
        monkeypatch.setattr(https, "_create_verified_client_context", lambda: context)
    monkeypatch.setattr(socket, "create_connection", loopback_connect)
    if redirect_scheme is not None:
        connection_type = (
            https._DirectHTTPSConnection
            if context is not None
            else https._DirectHTTPConnection
        )
        monkeypatch.setattr(connection_type, "response_class", ObservedResponse)
        monkeypatch.setattr(socket, "getaddrinfo", loopback_lookup)
        monkeypatch.setattr(urllib.request, "getproxies", unexpected_proxy_discovery)
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("NO_PROXY", "")

    if redirect_scheme is None:
        result = https.audit_https_availability(
            hostname, port, timeout=_HTTPS_CLIENT_TIMEOUT
        )
        assert result["target"] == {"hostname": hostname, "port": port}
        probe = result
    else:
        result = https.audit_http_redirect(
            hostname, port, source_scheme=redirect_scheme, timeout=_HTTPS_CLIENT_TIMEOUT
        )
        assert result["source"] == {
            "scheme": redirect_scheme,
            "hostname": hostname,
            "port": port,
        }
        assert lookups == [_HTTPS_LOOPBACK]
        probe = result["probe"]
    request, handshake_error = observed.result(timeout=4 * _HTTPS_SERVER_TIMEOUT + 1)
    if redirect_scheme is not None:
        assert len(responses) == int(request is not None)
        assert all(response.closed for response in responses)
    assert attempts == [(hostname, port)]
    if context is not None:
        assert (
            context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        )
        assert len(tls_sockets) == 1
    else:
        assert not tls_sockets
    assert len(tcp_sockets) == 1
    assert all(peer.fileno() == -1 for peer in tcp_sockets + tls_sockets)
    if request is None:
        assert handshake_error is not None and writes == []
        request_line = None
        authority = None
    else:
        assert handshake_error is None
        if context is not None:
            assert b"".join(writes) == request
        request_line, *header_lines = request[:-4].decode("ascii").split("\r\n")
        assert request_line == "HEAD / HTTP/1.1"
        headers = [
            (name.lower(), value.strip())
            for name, value in (line.split(":", 1) for line in header_lines)
        ]
        authority = f"{hostname}:{port}"
        assert [value for name, value in headers if name == "host"] == [authority]
        assert [value.lower() for name, value in headers if name == "connection"] == [
            "close"
        ]
        assert all(
            name not in {"authorization", "cookie", "proxy-authorization"}
            for name, _ in headers
        )

    record_property(
        "https_observation",
        json.dumps(
            {
                "request": request_line,
                "authority": authority,
                "outcome": probe["outcome"],
                "http_status": probe["http_status"],
                "failed_stage": probe["failed_stage"],
                "verify_code": probe["verify_code"],
                "server_handshake_error": type(handshake_error).__name__
                if handshake_error
                else None,
            },
            allow_nan=False,
        ),
    )
    return result, request


@pytest.mark.parametrize(
    ("wire", "outcome", "status", "stage"),
    [
        pytest.param(_HTTPS_RESPONSE_200, "available", 200, None, id="ok"),
        pytest.param(
            b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\n\r\n",
            "available",
            405,
            None,
            id="method-not-allowed",
        ),
        pytest.param(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            "available",
            503,
            None,
            id="service-unavailable",
        ),
        pytest.param(
            b"this is not an HTTP status line\r\n\r\n",
            "invalid_http_response",
            None,
            "response",
            id="malformed-status",
        ),
        pytest.param(
            _TRUNCATED_HEADERS,
            "invalid_http_response",
            None,
            "response",
            id="truncated-head",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nX-Test: a\x00b\r\n\r\n",
            "invalid_http_response",
            None,
            "response",
            id="control-character",
        ),
        pytest.param(
            b"HTTP/1.1 100 Continue\r\n\r\n" + _HTTPS_RESPONSE_200,
            "available",
            200,
            None,
            id="continue-then-ok",
        ),
        pytest.param(
            b"HTTP/2.0 200 OK\r\n\r\n",
            "unsupported_http_response",
            None,
            "response",
            id="unsupported-version",
        ),
        pytest.param(None, "timeout", None, "response", id="stalled"),
    ],
)
def test_local_https_integration_response(
    local_https_server, wire, outcome, status, stage, monkeypatch, record_property
):
    with local_https_server(wire) as server:
        result, request = _audit_local_https(
            server, "localhost", True, monkeypatch, record_property
        )
    assert request is not None
    assert (result["outcome"], result["http_status"], result["failed_stage"]) == (
        outcome,
        status,
        stage,
    )
    assert result["is_redirect"] is (False if status is not None else None)
    assert result["verify_code"] is None


@pytest.mark.parametrize(
    ("hostname", "trust_ca"),
    [
        pytest.param("localhost", False, id="untrusted-ca"),
        pytest.param(_HTTPS_LOOPBACK, True, id="trusted-identity-mismatch"),
    ],
)
def test_local_https_integration_rejects_certificate_before_http(
    local_https_server, hostname, trust_ca, monkeypatch, record_property
):
    with local_https_server(_HTTPS_RESPONSE_200) as server:
        result, request = _audit_local_https(
            server, hostname, trust_ca, monkeypatch, record_property
        )
    assert request is None
    assert result["outcome"] == "certificate_verification_failed"
    assert result["failed_stage"] == "handshake"
    assert result["verify_code"] is not None
    assert result["http_status"] is result["is_redirect"] is None


def test_local_https_integration_leaves_redirect_destination_uncontacted(
    local_https_server, monkeypatch, record_property
):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as destination:
        destination.bind((_HTTPS_LOOPBACK, 0))
        destination.listen(1)
        destination.setblocking(False)
        target = f"https://{_HTTPS_LOOPBACK}:{destination.getsockname()[1]}/target"
        wire = (
            f"HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n"
        ).encode("ascii")
        with local_https_server(wire) as server:
            result, request = _audit_local_https(
                server, "localhost", True, monkeypatch, record_property
            )
        assert request is not None
        assert result["outcome"] == "available" and result["http_status"] == 302
        assert result["is_redirect"] is True and result["failed_stage"] is None
        with pytest.raises(BlockingIOError):
            destination.accept()
    assert destination.fileno() == -1


def _redirect_response(status, *locations):
    fields = b"".join(b"Location: " + value + b"\r\n" for value in locations)
    head = _RESPONSE % (status, fields)
    return head, head + b"PAYLOAD"


@pytest.fixture
def offline_redirect(offline_https, monkeypatch):
    tcp, tls_socket, connect, wrap, resolve, proxies, respond = offline_https
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")

    def set_response(wire):
        stream = respond(wire)
        tcp.makefile.return_value = stream
        return stream

    return tcp, tls_socket, connect, wrap, resolve, proxies, set_response


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308])
def test_redirect_supported_statuses_record_upgrade_intent(offline_redirect, status):
    tcp, _, connect, wrap, resolve, proxies, respond = offline_redirect
    head, wire = _redirect_response(
        status, b"https://EXAMPLE.test.:443/private-path?token=redacted-query#hidden"
    )
    response = respond(wire)

    result = https.audit_http_redirect("example.test", None, timeout=2.0)

    assert result["source"] == {
        "scheme": "http",
        "hostname": "example.test",
        "port": 80,
    }
    assert result["probe"]["outcome"] == "available"
    assert result["probe"]["http_status"] == status
    assert result["probe"]["failed_stage"] is None
    assert result["redirect"]["outcome"] == "upgrade"
    assert result["redirect"]["destination"] == {
        "scheme": "https",
        "hostname": "example.test",
        "port": 443,
        "verification": "not_attempted",
    }
    assert result["redirect"]["same_host"] is True
    assert result["redirect"]["port_changed"] is True
    assert result["recommendations"] == []
    encoded = json.dumps(result, allow_nan=False)
    assert all(
        secret not in encoded for secret in ("private-path", "redacted-query", "hidden")
    )

    connect.assert_called_once()
    args, kwargs = connect.call_args
    assert args[0] == ("example.test", 80)
    assert (args[1] if len(args) > 1 else kwargs["timeout"]) == 2.0
    tcp.makefile.assert_called_once()
    wire_request = b"".join(call.args[0] for call in tcp.sendall.call_args_list)
    request, body = wire_request.split(b"\r\n\r\n", 1)
    request_line, *headers = request.split(b"\r\n")
    assert request_line == b"HEAD / HTTP/1.1" and body == b""
    fields = dict(line.lower().split(b": ", 1) for line in headers)
    assert fields[b"host"] == b"example.test" and fields[b"connection"] == b"close"
    assert fields.keys().isdisjoint(
        {b"authorization", b"cookie", b"proxy-authorization"}
    )
    assert response.bytes_read == len(head)
    assert response.closed
    tcp.close.assert_called()
    for operation in (wrap, resolve, proxies):
        operation.assert_not_called()


@pytest.mark.parametrize(
    (
        "scheme",
        "hostname",
        "port",
        "location",
        "destination",
        "outcome",
        "same_host",
        "advice",
    ),
    [
        pytest.param(
            "https",
            "example.test",
            None,
            b"http://example.test/",
            ("http", "example.test", 80),
            "downgrade",
            True,
            ["https_to_http_downgrade"],
            id="verified-downgrade",
        ),
        pytest.param(
            "https",
            "example.test",
            8443,
            b"../next%20page?x=1#section",
            ("https", "example.test", 8443),
            "same_scheme_redirect",
            True,
            [],
            id="relative-https-custom-port",
        ),
        pytest.param(
            "https",
            "example.test",
            None,
            b"//other.test/path",
            ("https", "other.test", 443),
            "same_scheme_redirect",
            False,
            ["review_cross_host_redirect"],
            id="scheme-relative-https",
        ),
        pytest.param(
            "http",
            "example.test",
            None,
            b"/continue",
            ("http", "example.test", 80),
            "same_scheme_redirect",
            True,
            ["review_https_upgrade"],
            id="root-relative-http",
        ),
        pytest.param(
            "http",
            "example.test",
            8080,
            b"//example.test:8081/",
            ("http", "example.test", 8081),
            "same_scheme_redirect",
            True,
            ["review_https_upgrade", "review_unusual_redirect_port"],
            id="unusual-port-change",
        ),
        pytest.param(
            "http",
            "2001:0db8:0:0::1",
            None,
            b"https://[2001:db8::1]/",
            ("https", "2001:db8::1", 443),
            "upgrade",
            True,
            [],
            id="canonical-ipv6",
        ),
        pytest.param(
            "http",
            "b\u00fccher.example",
            None,
            b"https://XN--BCHER-KVA.example./",
            ("https", "xn--bcher-kva.example", 443),
            "upgrade",
            True,
            [],
            id="ascii-idna",
        ),
        pytest.param(
            "http",
            "example.test",
            None,
            b"https://other.test/",
            ("https", "other.test", 443),
            "upgrade",
            False,
            ["review_cross_host_redirect"],
            id="cross-host-upgrade",
        ),
    ],
)
def test_redirect_resolves_origin_without_following(
    offline_redirect,
    scheme,
    hostname,
    port,
    location,
    destination,
    outcome,
    same_host,
    advice,
):
    tcp, tls_socket, connect, wrap, resolve, proxies, respond = offline_redirect
    response = respond(_redirect_response(302, location)[1])

    result = https.audit_http_redirect(hostname, port, source_scheme=scheme)

    redirect = result["redirect"]
    assert redirect["outcome"] == outcome and redirect["same_host"] is same_host
    assert redirect["destination"] == {
        **dict(zip(("scheme", "hostname", "port"), destination, strict=True)),
        "verification": "not_attempted",
    }
    assert redirect["port_changed"] is (result["source"]["port"] != destination[2])
    assert sorted(result["recommendations"]) == sorted(advice)
    connect.assert_called_once()
    resolve.assert_not_called()
    proxies.assert_not_called()
    assert response.closed
    if scheme == "https":
        wrap.assert_called_once()
        context, raw_socket = wrap.call_args.args
        assert raw_socket is tcp
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert wrap.call_args.kwargs["server_hostname"] == hostname
        assert b"".join(
            call.args[0] for call in tls_socket.sendall.call_args_list
        ).startswith(b"HEAD / HTTP/1.1\r\n")
        tls_socket.close.assert_called()
    else:
        wrap.assert_not_called()


@pytest.mark.parametrize(
    ("status", "locations", "outcome", "advice"),
    [
        pytest.param(
            200,
            (b"https://other.test/",),
            "no_redirect",
            ["review_https_upgrade"],
            id="non-redirect",
        ),
        pytest.param(
            304,
            (b"https://other.test/",),
            "no_redirect",
            ["review_https_upgrade"],
            id="not-modified",
        ),
        pytest.param(
            305,
            (b"https://other.test/",),
            "unsupported_redirect_status",
            [],
            id="use-proxy",
        ),
        pytest.param(306, (), "unsupported_redirect_status", [], id="unused-status"),
        pytest.param(
            300, (), "missing_location", [], id="multiple-choices-without-location"
        ),
        pytest.param(301, (), "missing_location", [], id="missing-location"),
        pytest.param(302, (b"\t ",), "empty_location", [], id="empty-location"),
        pytest.param(
            302, (b"/same", b"/same"), "ambiguous_location", [], id="duplicate-fields"
        ),
        pytest.param(
            302,
            (b"https://one.test/,https://two.test/",),
            "ambiguous_location",
            [],
            id="comma-bearing",
        ),
        pytest.param(
            302,
            (b"ftp://other.test/file",),
            "unsupported_scheme",
            [],
            id="unsupported-scheme",
        ),
    ],
)
def test_redirect_report_handles_status_and_location_cardinality(
    offline_redirect, status, locations, outcome, advice
):
    _, _, connect, _, resolve, proxies, respond = offline_redirect
    respond(_redirect_response(status, *locations)[1])

    result = https.audit_http_redirect("example.test")

    assert result["probe"]["http_status"] == status
    assert result["redirect"]["outcome"] == outcome
    assert result["redirect"]["destination"] is None
    assert result["redirect"]["same_host"] is result["redirect"]["port_changed"] is None
    assert result["recommendations"] == advice
    connect.assert_called_once()
    resolve.assert_not_called()
    proxies.assert_not_called()


@pytest.mark.parametrize(
    "location",
    [
        b"https://example.test/a b",
        b"https://example.test/a\tb",
        b"https://example.test\\path",
        b"https://example.test/%ZZ",
        b"https://example.test/%",
        b"https://example.test%40other.test/",
        b"https://example.test%2fother.test/",
        b"https://2130706433/",
        b"https://0x7f000001/",
        b"https://user:secret@example.test/private",
        b"https://example.test:65536/",
        b"https://example.test:/",
        b"https://example.test:0/",
        b"https://[2001:db8::1/",
        b"https://2001:db8::1/",
        b"https://[fe80::1%25eth0]/",
        b"///other.test/path",
        b"https:///other.test/",
        b"https:other.test",
    ],
)
def test_redirect_rejects_invalid_location_without_echoing_it(
    offline_redirect, location
):
    _, _, connect, _, resolve, _, respond = offline_redirect
    respond(_redirect_response(302, location)[1])

    result = https.audit_http_redirect("example.test")

    assert result["probe"]["http_status"] == 302
    assert result["redirect"]["outcome"] == "invalid_location"
    assert result["redirect"]["destination"] is None
    assert result["recommendations"] == []
    encoded_location = json.dumps(location.decode("ascii"))
    assert encoded_location not in json.dumps(result, allow_nan=False)
    connect.assert_called_once()
    resolve.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("source_scheme", "ftp", id="source-scheme"),
        pytest.param(
            "hostname", "https://user:secret@source.invalid/", id="source-url"
        ),
        pytest.param("port", True, id="boolean-port"),
        pytest.param("port", 1 << 15000, id="oversized-port"),
        pytest.param("timeout", float("nan"), id="nan-timeout"),
        pytest.param("timeout", float("inf"), id="infinite-timeout"),
        pytest.param("timeout", -1, id="negative-timeout"),
    ],
)
def test_redirect_rejects_invalid_source_before_network(offline_redirect, field, value):
    tcp, tls_socket, connect, wrap, resolve, proxies, _ = offline_redirect
    options = {
        "hostname": "example.test",
        "port": None,
        "source_scheme": "http",
        "timeout": 2.0,
    }
    options[field] = value

    result = https.audit_http_redirect(**options)

    assert (result["probe"]["outcome"], result["probe"]["failed_stage"]) == (
        "invalid_input",
        "validation",
    )
    assert result["redirect"]["outcome"] == "not_evaluated"
    assert result["redirect"]["destination"] is None and result["recommendations"] == []
    assert "user:secret" not in json.dumps(result, allow_nan=False)
    for operation in (connect, wrap, resolve, proxies, tcp.sendall, tls_socket.sendall):
        operation.assert_not_called()


def test_redirect_does_not_assess_after_failed_source_certificate(offline_redirect):
    tcp, tls_socket, connect, wrap, resolve, _, _ = offline_redirect
    wrap.side_effect = _certificate_error(62)

    result = https.audit_http_redirect("example.test", source_scheme="https")

    assert (result["probe"]["outcome"], result["probe"]["failed_stage"]) == (
        "certificate_verification_failed",
        "handshake",
    )
    assert result["source"]["port"] == 443
    assert result["probe"]["verify_code"] == 62
    assert result["probe"]["http_status"] is None
    assert result["redirect"]["outcome"] == "not_evaluated"
    assert result["redirect"]["destination"] is None and result["recommendations"] == []
    connect.assert_called_once()
    tcp.sendall.assert_not_called()
    tls_socket.sendall.assert_not_called()
    resolve.assert_not_called()
    tcp.close.assert_called()


@pytest.mark.parametrize(
    ("wire", "outcome"),
    [
        pytest.param(
            b"HTTP/1.1 301 Test\r\nLocation: https://other.test/\r\n",
            "invalid_http_response",
            id="truncated-head",
        ),
        pytest.param(
            _redirect_response(301, b"https://other.test/a\x00b")[1],
            "invalid_http_response",
            id="control-byte-in-head",
        ),
        pytest.param(
            b"HTTP/9.9 100 Continue\r\n\r\n" + _redirect_response(301, b"/")[1],
            "unsupported_http_response",
            id="unsupported-interim-version",
        ),
    ],
)
def test_redirect_reuses_strict_response_head_validation(
    offline_redirect, wire, outcome
):
    tcp, _, connect, _, resolve, _, respond = offline_redirect
    response = respond(wire)

    result = https.audit_http_redirect("example.test")

    assert (result["probe"]["outcome"], result["probe"]["failed_stage"]) == (
        outcome,
        "response",
    )
    assert result["probe"]["http_status"] is None
    assert result["redirect"]["outcome"] == "not_evaluated"
    assert result["redirect"]["destination"] is None and result["recommendations"] == []
    connect.assert_called_once()
    resolve.assert_not_called()
    assert response.closed
    tcp.close.assert_called()


@pytest.mark.parametrize(
    ("failed_stage", "error", "outcome"),
    [
        pytest.param(
            "connect", ConnectionRefusedError(), "connection_refused", id="refused"
        ),
        pytest.param("request", ConnectionResetError(), "transport_error", id="reset"),
        pytest.param("response", TimeoutError(), "timeout", id="response-timeout"),
    ],
)
def test_redirect_preserves_source_transport_failure_stage(
    offline_redirect, failed_stage, error, outcome
):
    tcp, _, connect, wrap, resolve, _, respond = offline_redirect
    response = respond(b"")
    operations = {"connect": connect, "request": tcp.sendall}
    if failed_stage == "response":
        response.readline = MagicMock(side_effect=error)
    else:
        operations[failed_stage].side_effect = error

    result = https.audit_http_redirect("example.test")

    assert (result["probe"]["outcome"], result["probe"]["failed_stage"]) == (
        outcome,
        failed_stage,
    )
    assert result["probe"]["http_status"] is None
    assert result["redirect"]["outcome"] == "not_evaluated"
    assert result["redirect"]["destination"] is None and result["recommendations"] == []
    connect.assert_called_once()
    wrap.assert_not_called()
    resolve.assert_not_called()
    if failed_stage != "connect":
        tcp.close.assert_called()
    if failed_stage == "response":
        assert response.closed


@pytest.mark.parametrize(
    ("authority", "port_suffix"),
    [
        pytest.param("192.0x.2.1", "", id="bare-hex-middle"),
        pytest.param("192.0X.2.1.", ":8443", id="bare-hex-uppercase-root-dot"),
        pytest.param("0x.0.2.1", ":8443", id="bare-hex-first"),
        pytest.param("192.0.2.0x", ":8443", id="bare-hex-last"),
        pytest.param("0X", ":8443", id="bare-hex-single"),
        pytest.param("xn--a.test", ":8443", id="decoded-control"),
        pytest.param("XN--A.TeSt.", ":8443", id="decoded-control-uppercase-root-dot"),
    ],
)
def test_redirect_destination_rejects_ambiguous_ipv4_and_control_alabels(
    offline_redirect, authority, port_suffix
):
    tcp, _, connect, wrap, resolve, proxies, respond = offline_redirect
    location = f"https://{authority}{port_suffix}/private-path?token=secret-query#secret-fragment"
    response = respond(_redirect_response(302, location.encode("ascii"))[1])

    result = https.audit_http_redirect("192.0.2.1")

    assert result["probe"]["http_status"] == 302
    assert result["redirect"] == {
        "outcome": "invalid_location",
        "destination": None,
        "same_host": None,
        "port_changed": None,
    }
    assert result["recommendations"] == []
    encoded = json.dumps(result, allow_nan=False)
    assert all(
        text not in encoded
        for text in (authority, "private-path", "secret-query", "secret-fragment")
    )
    connect.assert_called_once()
    assert connect.call_args.args[0] == ("192.0.2.1", 80)
    for operation in (wrap, resolve, proxies):
        operation.assert_not_called()
    assert response.closed
    tcp.close.assert_called()


@pytest.mark.parametrize(
    ("authority", "expected_host"),
    [
        pytest.param("192.0.2.1", "192.0.2.1", id="canonical-ipv4"),
        pytest.param("ExAmPle.TeSt.", "example.test", id="ordinary-dns"),
        pytest.param("lab.0X.TeSt.", "lab.0x.test", id="literal-hex-label-in-dns"),
        pytest.param("123.lab.test", "123.lab.test", id="decimal-label-in-dns"),
        pytest.param("xn--bcher-kva.test", "xn--bcher-kva.test", id="valid-alabel"),
        pytest.param(
            "XN--BCHER-KVA.TeSt.", "xn--bcher-kva.test", id="uppercase-alabel"
        ),
        pytest.param("XN--FA-HIA.test.", "xn--fa-hia.test", id="preencoded-sharp-s"),
    ],
)
def test_redirect_destination_preserves_valid_ip_dns_and_alabels(
    offline_redirect, authority, expected_host
):
    _, _, connect, wrap, resolve, proxies, respond = offline_redirect
    respond(_redirect_response(302, f"https://{authority}/".encode("ascii"))[1])

    result = https.audit_http_redirect("192.0.2.1")

    assert result["redirect"]["outcome"] == "upgrade"
    assert result["redirect"]["destination"] == {
        "scheme": "https",
        "hostname": expected_host,
        "port": 443,
        "verification": "not_attempted",
    }
    same_host = expected_host == "192.0.2.1"
    assert result["redirect"]["same_host"] is same_host
    assert result["redirect"]["port_changed"] is True
    assert result["recommendations"] == (
        [] if same_host else ["review_cross_host_redirect"]
    )
    connect.assert_called_once()
    for operation in (wrap, resolve, proxies):
        operation.assert_not_called()
    json.dumps(result, allow_nan=False)


@pytest.fixture
def local_redirect_destination():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as destination:
        destination.bind((_HTTPS_LOOPBACK, 0))
        destination.listen(1)
        destination.setblocking(False)
        yield destination
        with pytest.raises(BlockingIOError):
            destination.accept()
    assert destination.fileno() == -1


@pytest.mark.parametrize(
    ("source_scheme", "destination_scheme", "destination_host", "outcome", "advice"),
    [
        pytest.param(
            "http",
            "https",
            "redirect.invalid",
            "upgrade",
            ["review_cross_host_redirect", "review_unusual_redirect_port"],
            id="upgrade",
        ),
        pytest.param(
            "https",
            "http",
            "localhost",
            "downgrade",
            ["https_to_http_downgrade", "review_unusual_redirect_port"],
            id="downgrade",
        ),
    ],
)
def test_local_redirect_integration_keeps_destination_uncontacted(
    local_https_server,
    local_redirect_destination,
    monkeypatch,
    record_property,
    source_scheme,
    destination_scheme,
    destination_host,
    outcome,
    advice,
):
    destination_port = local_redirect_destination.getsockname()[1]
    location = (
        f"{destination_scheme}://{destination_host}:{destination_port}"
        "/private-path?token=private-query#private-fragment"
    )
    wire = _redirect_response(302, location.encode("ascii"))[0]
    with local_https_server(wire, use_tls=source_scheme == "https") as server:
        result, request = _audit_local_https(
            server,
            "localhost",
            True,
            monkeypatch,
            record_property,
            redirect_scheme=source_scheme,
        )

    assert request is not None
    assert result["probe"]["outcome"] == "available"
    assert result["probe"]["http_status"] == 302
    assert result["probe"]["failed_stage"] is None
    assert result["redirect"] == {
        "outcome": outcome,
        "destination": {
            "scheme": destination_scheme,
            "hostname": destination_host,
            "port": destination_port,
            "verification": "not_attempted",
        },
        "same_host": destination_host == "localhost",
        "port_changed": True,
    }
    assert sorted(result["recommendations"]) == sorted(advice)
    serialized = json.dumps(result, allow_nan=False)
    assert all(
        secret not in serialized
        for secret in (location, "private-path", "private-query", "private-fragment")
    )
    record_property("redirect_observation", serialized)


@pytest.mark.parametrize(
    ("status", "locations", "outcome", "advice"),
    [
        pytest.param(
            200, (), "no_redirect", ["review_https_upgrade"], id="plaintext-no-upgrade"
        ),
        pytest.param(
            301,
            (b"../private-path?token=private-query#private-fragment",),
            "same_scheme_redirect",
            ["review_https_upgrade"],
            id="relative-location",
        ),
        pytest.param(
            302, (b"/one", b"/two"), "ambiguous_location", [], id="duplicate-location"
        ),
        pytest.param(
            302,
            (b"https://sample-user:sample-secret@redirect.invalid/private-path",),
            "invalid_location",
            [],
            id="credential-bearing-location",
        ),
        pytest.param(
            302,
            (b"https://192.0x.2.1:8443/private-path",),
            "invalid_location",
            [],
            id="ambiguous-ipv4-location",
        ),
    ],
)
def test_local_redirect_integration_classifies_plaintext_response(
    local_https_server, monkeypatch, record_property, status, locations, outcome, advice
):
    with local_https_server(
        _redirect_response(status, *locations)[0], use_tls=False
    ) as server:
        port = server[0]
        result, request = _audit_local_https(
            server,
            "localhost",
            False,
            monkeypatch,
            record_property,
            redirect_scheme="http",
        )

    assert request is not None
    assert result["probe"]["outcome"] == "available"
    assert result["probe"]["http_status"] == status
    assert result["probe"]["failed_stage"] is None
    assert result["redirect"]["outcome"] == outcome
    if outcome == "same_scheme_redirect":
        assert result["redirect"]["destination"] == {
            "scheme": "http",
            "hostname": "localhost",
            "port": port,
            "verification": "not_attempted",
        }
        assert result["redirect"]["same_host"] is True
        assert result["redirect"]["port_changed"] is False
    else:
        assert result["redirect"]["destination"] is None
        assert (
            result["redirect"]["same_host"]
            is result["redirect"]["port_changed"]
            is None
        )
    assert result["recommendations"] == advice
    serialized = json.dumps(result, allow_nan=False)
    assert all(location.decode("ascii") not in serialized for location in locations)
    assert all(
        secret not in serialized
        for secret in (
            "private-path",
            "private-query",
            "private-fragment",
            "sample-user",
            "sample-secret",
        )
    )
    record_property("redirect_observation", serialized)


@pytest.mark.parametrize(
    ("hostname", "trust_ca"),
    [
        pytest.param("localhost", False, id="untrusted-ca"),
        pytest.param(_HTTPS_LOOPBACK, True, id="trusted-identity-mismatch"),
    ],
)
def test_local_redirect_integration_skips_assessment_on_tls_verification_failure(
    local_https_server,
    local_redirect_destination,
    monkeypatch,
    record_property,
    hostname,
    trust_ca,
):
    location = (
        f"http://{_HTTPS_LOOPBACK}:{local_redirect_destination.getsockname()[1]}/"
    )
    wire = _redirect_response(302, location.encode("ascii"))[0]
    with local_https_server(wire) as server:
        result, request = _audit_local_https(
            server,
            hostname,
            trust_ca,
            monkeypatch,
            record_property,
            redirect_scheme="https",
        )

    assert request is None
    assert result["probe"]["outcome"] == "certificate_verification_failed"
    assert result["probe"]["failed_stage"] == "handshake"
    assert (
        result["probe"]["http_status"] is None
        and result["probe"]["verify_code"] is not None
    )
    assert result["redirect"]["outcome"] == "not_evaluated"
    assert result["redirect"]["destination"] is None and result["recommendations"] == []
    record_property("redirect_observation", json.dumps(result, allow_nan=False))


@pytest.mark.parametrize("hostname", test_tls._SHARED_INVALID_SOURCE_HOSTNAMES)
@pytest.mark.parametrize("redirect", [False, True], ids=["availability", "redirect"])
def test_shared_source_validation_rejects_invalid_https_hostnames(
    offline_https, monkeypatch, hostname, redirect
):
    tcp, tls_socket, connect, wrap, resolve, proxies, _ = offline_https
    create_context = MagicMock(wraps=https._create_verified_client_context)
    monkeypatch.setattr(https, "_create_verified_client_context", create_context)
    connect.side_effect = ConnectionRefusedError(
        "Unexpected connection after validation"
    )

    if redirect:
        result = https.audit_http_redirect(hostname, source_scheme="https")
        assert result["redirect"] == {
            "outcome": "not_evaluated",
            "destination": None,
            "same_host": None,
            "port_changed": None,
        }
        assert result["recommendations"] == []
        probe = result["probe"]
        target = result["source"]
    else:
        result = https.audit_https_availability(hostname)
        assert result["is_redirect"] is None
        probe = result
        target = result["target"]
    assert (probe["outcome"], probe["failed_stage"]) == (
        "invalid_input",
        "validation",
    ), (
        probe,
        connect.call_args_list,
    )
    assert target["hostname"] is None and target["port"] == 443
    assert probe["http_status"] is probe["verify_code"] is probe["elapsed_ms"] is None
    assert hostname not in json.dumps(result, allow_nan=False)
    for operation in (
        create_context,
        resolve,
        connect,
        wrap,
        proxies,
        tcp.sendall,
        tls_socket.sendall,
        tls_socket.do_handshake,
    ):
        operation.assert_not_called()


keylog_sandbox = test_tls.keylog_sandbox


@pytest.mark.parametrize(
    ("identity", "trust", "expected"),
    [
        pytest.param("localhost", True, "available", id="trusted"),
        pytest.param(
            "localhost", False, "certificate_verification_failed", id="untrusted"
        ),
        pytest.param(
            _HTTPS_LOOPBACK, True, "certificate_verification_failed", id="mismatch"
        ),
    ],
)
def test_keylog_red_loopback_https_preserves_verification(
    local_https_server, keylog_sandbox, identity, trust, expected
):
    destination = keylog_sandbox / "https-keylog"
    sentinel = b"WebGuard HTTPS sentinel\n"
    destination.write_bytes(sentinel)
    before = destination.stat().st_mtime_ns
    with local_https_server(_HTTPS_RESPONSE_200) as server:
        port, ca_pem, observation = server
        ca_file = keylog_sandbox / "ca.pem"
        ca_file.write_text(ca_pem, encoding="ascii")
        observed = test_tls.run_keylog_child(
            "https",
            destination,
            hostname=identity,
            port=port,
            ca_file=ca_file if trust else None,
        )
        request, handshake_error = observation.result(timeout=_HTTPS_SERVER_TIMEOUT)

    assert observed["error"] is None
    result = observed["result"]
    assert result["outcome"] == expected
    if expected == "available":
        assert handshake_error is None
        assert request.startswith(b"HEAD / HTTP/1.1\r\n")
        assert result["http_status"] == 200
    else:
        assert handshake_error is not None
        assert request is None
        assert result["failed_stage"] == "handshake"
        assert result["verify_code"] is not None
    unchanged = destination.read_bytes() == sentinel
    assert unchanged, "HTTPS context creation changed the sentinel"
    assert destination.stat().st_mtime_ns == before
    assert observed["armed_before_wrap"] == [False]


setup_failure_io = test_tls.setup_failure_io


@pytest.mark.parametrize("is_redirect", [False, True], ids=["https", "redirect"])
@pytest.mark.parametrize("error_type", test_tls._SETUP_ERRORS)
def test_context_setup_red_https_returns_local_failure(
    setup_failure_io, monkeypatch, is_redirect, error_type
):
    factory = MagicMock(side_effect=test_tls.setup_failure(error_type))
    monkeypatch.setattr(https, "_create_verified_client_context", factory)
    request = MagicMock(side_effect=AssertionError("Unexpected HTTP request"))
    monkeypatch.setattr(http.client.HTTPConnection, "request", request)

    if is_redirect:
        result = https.audit_http_redirect("example.test", source_scheme="https")
        assert result["redirect"]["outcome"] == "not_evaluated"
        assert result["redirect"]["destination"] is None
        assert result["recommendations"] == []
        probe = result["probe"]
    else:
        result = https.audit_https_availability("example.test")
        assert result["is_redirect"] is None
        probe = result

    factory.assert_called_once_with()
    request.assert_not_called()
    assert probe["outcome"] == "tls_error"
    assert probe["failed_stage"] == "tls_setup"
    assert probe["http_status"] is probe["verify_code"] is None
    assert "setup-test-marker" not in json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("is_redirect", [False, True], ids=["https", "redirect"])
@pytest.mark.parametrize("error_type", test_tls._SETUP_UNEXPECTED)
def test_context_setup_red_https_propagates_unexpected_failures(
    setup_failure_io, monkeypatch, is_redirect, error_type
):
    error = test_tls.setup_failure(error_type)
    factory = MagicMock(side_effect=error)
    monkeypatch.setattr(https, "_create_verified_client_context", factory)

    with pytest.raises(error_type) as raised:
        if is_redirect:
            https.audit_http_redirect("example.test", source_scheme="https")
        else:
            https.audit_https_availability("example.test")
    assert raised.value is error
    factory.assert_called_once_with()


@pytest.mark.parametrize(
    (
        "kind",
        "wire",
        "fail_stream",
        "fail_socket",
        "fail_request",
        "outcome",
        "stage",
        "status",
        "expected_order",
    ),
    [
        pytest.param(
            "https",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            True,
            True,
            False,
            "available",
            None,
            200,
            ["response", "connection"],
            id="paired-finalizer",
        ),
        pytest.param(
            "https",
            _TRUNCATED_HEADERS,
            True,
            True,
            False,
            "invalid_http_response",
            "response",
            None,
            ["response", "connection"],
            id="parser-internal-response-close",
        ),
        pytest.param(
            "https",
            _HTTPS_RESPONSE_200,
            False,
            True,
            False,
            "available",
            None,
            200,
            ["connection", "response"],
            id="internal-connection-close",
        ),
        pytest.param(
            "https",
            None,
            False,
            True,
            True,
            "transport_error",
            "request",
            None,
            ["connection"],
            id="request-failure",
        ),
        pytest.param(
            "http",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
            True,
            True,
            False,
            "available",
            None,
            204,
            ["response", "connection"],
            id="plaintext-redirect",
        ),
    ],
)
def test_secondary_failure_red_http_cleanup_keeps_primary_outcome(
    offline_https,
    kind,
    wire,
    fail_stream,
    fail_socket,
    fail_request,
    outcome,
    stage,
    status,
    expected_order,
):
    tcp, tls_socket, _, wrap, _, _, respond = offline_https
    sock = tls_socket if kind == "https" else tcp
    events = []
    if wire is not None:
        stream = respond(wire)
        sock.makefile.return_value = stream
        close_stream = stream.close

        def observe_response_close():
            events.append("response")
            close_stream()
            if fail_stream:
                raise OSError("synthetic private response close path")

        stream.close = MagicMock(side_effect=observe_response_close)
    if fail_request:
        sock.sendall.side_effect = ConnectionResetError("synthetic request failure")

    def observe_connection_close():
        events.append("connection")
        if fail_socket:
            raise OSError("synthetic private connection close path")

    sock.close.side_effect = observe_connection_close
    if kind == "https":
        result = https.audit_https_availability("example.test")
        probe = result
    else:
        result = https.audit_http_redirect("example.test", source_scheme="http")
        probe = result["probe"]
        assert result["redirect"]["outcome"] == "no_redirect"
        wrap.assert_not_called()

    assert (probe["outcome"], probe["failed_stage"], probe["http_status"]) == (
        outcome,
        stage,
        status,
    )
    assert events == expected_order
    expected = {
        code
        for enabled, code in (
            (fail_stream, "http_response_close_failed"),
            (fail_socket, "http_connection_close_failed"),
        )
        if enabled
    }
    assert len(probe["diagnostics"]) == len(expected)
    assert set(probe["diagnostics"]) == expected
    assert "synthetic private" not in json.dumps(result, allow_nan=False)


def test_secondary_failure_red_unexpected_response_close_still_attempts_connection(
    offline_https,
):
    _, tls_socket, _, _, _, _, respond = offline_https
    stream = respond(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    error = RuntimeError("unexpected response close defect")
    close_stream = stream.close

    def fail_close():
        close_stream()
        raise error

    stream.close = MagicMock(side_effect=fail_close)
    tls_socket.close.side_effect = OSError("synthetic secondary socket failure")

    with pytest.raises(RuntimeError) as raised:
        https.audit_https_availability("example.test")

    assert raised.value is error
    stream.close.assert_called_once_with()
    tls_socket.close.assert_called_once_with()


@pytest.fixture
def response_unraisable_exceptions(monkeypatch):
    gc.collect()
    failures = []

    def capture(args):
        failures.append((args.exc_type.__name__, str(args.exc_value)))

    with monkeypatch.context() as hooks:
        hooks.setattr(sys, "unraisablehook", capture)
        yield failures


def test_cycle5_response_finalization_handles_makefile_failure(
    offline_https, response_unraisable_exceptions
):
    _, tls_socket, connect, _, resolve, _, _ = offline_https

    def fail_makefile(*args):
        raise OSError("could not create response stream")

    tls_socket.makefile.side_effect = fail_makefile

    result = https.audit_https_availability("example.test")
    gc.collect()

    tls_socket.makefile.assert_called_once_with("rb")
    tls_socket.close.assert_called_once_with()
    connect.assert_called_once()
    resolve.assert_not_called()
    assert result["outcome"] == "transport_error"
    assert result["failed_stage"] == "response"
    assert result["http_status"] is result["is_redirect"] is None
    assert "diagnostics" not in result
    assert response_unraisable_exceptions == []


@pytest.mark.parametrize(
    "close_error",
    [
        pytest.param(None, id="ordinary-response"),
        pytest.param(OSError, id="operational-connection-close"),
        pytest.param(RuntimeError, id="unexpected-response-close"),
    ],
)
def test_cycle5_response_finalization_keeps_normal_close_behavior(
    offline_https, response_unraisable_exceptions, close_error
):
    _, tls_socket, connect, _, resolve, _, respond = offline_https
    stream = respond(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    if close_error is RuntimeError:
        error = close_error("unexpected response close defect")
        close_stream = stream.close

        def fail_close():
            close_stream()
            raise error

        stream.close = MagicMock(side_effect=fail_close)
        with pytest.raises(RuntimeError) as raised:
            https.audit_https_availability("example.test")
        assert raised.value is error
    else:
        if close_error is OSError:
            tls_socket.close.side_effect = close_error("could not close connection")
        result = https.audit_https_availability("example.test")
        assert result["outcome"] == "available"
        assert result["failed_stage"] is None
        assert result["http_status"] == 200
        assert result["is_redirect"] is False
        if close_error is OSError:
            assert result["diagnostics"] == ["http_connection_close_failed"]
        else:
            assert "diagnostics" not in result

    gc.collect()
    assert stream.closed
    tls_socket.makefile.assert_called_once_with("rb")
    tls_socket.close.assert_called_once_with()
    connect.assert_called_once()
    resolve.assert_not_called()
    assert response_unraisable_exceptions == []
