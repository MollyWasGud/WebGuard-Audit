import http.client
import ipaddress
import re
import socket
import ssl
import time
from contextlib import suppress
from functools import partial
from typing import Literal, TypedDict
from urllib.parse import urlsplit

from webguard.security.dialer import AuthorizedTransport

from .tls import (
    _create_verified_client_context,
    _is_valid_port,
    _normalize_hostname,
    _validate_endpoint,
)

_REDIRECT_STATUSES = {300, 301, 302, 303, 307, 308}
_STATUS_LINE = re.compile(
    rb"(HTTP/[0-9]\.[0-9]) [1-5][0-9]{2} [\t\x20-\x7e\x80-\xff]*\r\n"
)
_HEADER_FIELD = re.compile(
    rb"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*\r\n"
)
_SUPPORTED_HTTP_VERSIONS = {b"HTTP/1.0", b"HTTP/1.1"}
_MAX_RESPONSE_HEADS = 8
_DEFAULT_PORTS = {"http": 80, "https": 443}
_INVALID_URI_CHARACTER = re.compile(r"[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_AUTHORITY = re.compile(
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(?P<port>[0-9]+))?"
)

_FailureStage = Literal[
    "validation", "tls_setup", "connect", "handshake", "request", "response"
]
_Outcome = Literal[
    "available",
    "invalid_input",
    "certificate_verification_failed",
    "connection_refused",
    "timeout",
    "invalid_http_response",
    "unsupported_http_response",
    "tls_error",
    "transport_error",
]


class HTTPSTarget(TypedDict):
    hostname: str | None
    port: int | None


_HTTPAuditDiagnostic = Literal[
    "http_response_close_failed", "http_connection_close_failed"
]
_HTTPCleanup = dict[_HTTPAuditDiagnostic, None]


class _HTTPResultDiagnostics(TypedDict, total=False):
    diagnostics: list[_HTTPAuditDiagnostic]


class _ResponseProbe(_HTTPResultDiagnostics):
    outcome: _Outcome
    http_status: int | None
    failed_stage: _FailureStage | None
    verify_code: int | None
    elapsed_ms: float | None


class HTTPSAvailabilityResult(_ResponseProbe):
    target: HTTPSTarget
    is_redirect: bool | None


_Scheme = Literal["http", "https"]


class _RedirectSource(HTTPSTarget):
    scheme: _Scheme | None


class _RedirectDestination(TypedDict):
    scheme: str
    hostname: str
    port: int
    verification: Literal["not_attempted"]


class _RedirectAssessment(TypedDict):
    outcome: Literal[
        "not_evaluated",
        "no_redirect",
        "unsupported_redirect_status",
        "missing_location",
        "empty_location",
        "ambiguous_location",
        "invalid_location",
        "unsupported_scheme",
        "same_scheme_redirect",
        "upgrade",
        "downgrade",
    ]
    destination: _RedirectDestination | None
    same_host: bool | None
    port_changed: bool | None


class HTTPRedirectAuditResult(TypedDict):
    source: _RedirectSource
    probe: _ResponseProbe
    redirect: _RedirectAssessment
    recommendations: list[str]


class _ResponseHeadReader:
    """Validate each response head, including those discarded by http.client."""

    def __init__(self, stream):
        self._stream = stream
        self._in_headers = False
        self._heads = 0

    def readline(self, limit: int) -> bytes:
        line = self._stream.readline(limit)
        if self._in_headers:
            if not line.endswith(b"\r\n"):
                raise http.client.HTTPException("Incomplete HTTP header block")
            self._in_headers = line != b"\r\n"
            if self._in_headers and not _HEADER_FIELD.fullmatch(line):
                raise http.client.HTTPException("Malformed HTTP header field")
        elif line:
            status_line = _STATUS_LINE.fullmatch(line)
            if status_line is None:
                raise http.client.BadStatusLine(line)
            version = status_line[1]
            if version not in _SUPPORTED_HTTP_VERSIONS:
                raise http.client.UnknownProtocol(version.decode("ascii"))
            self._heads += 1
            if self._heads > _MAX_RESPONSE_HEADS:
                raise http.client.HTTPException("Too many HTTP response heads")
            self._in_headers = True
        elif self._heads:
            raise http.client.HTTPException("No final HTTP response")
        return line

    def close(self) -> None:
        self._stream.close()


class _CompleteHTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args, cleanup: _HTTPCleanup, **kwargs):
        self._cleanup = cleanup
        # HTTPResponse.close() can run if makefile() raises during construction.
        self.fp = None
        super().__init__(*args, **kwargs)

    def begin(self) -> None:
        if self.headers is not None:
            return
        stream = self.fp
        self.fp = _ResponseHeadReader(stream)
        try:
            super().begin()
        finally:
            if self.fp is not None:
                self.fp = stream
        if self.headers.defects:
            raise http.client.HTTPException("Malformed HTTP header block")

    def close(self) -> None:
        try:
            super().close()
        except OSError:
            self._cleanup["http_response_close_failed"] = None

    def _close_conn(self) -> None:
        # http.client also closes the stream directly when reading the status line hits EOF.
        try:
            super()._close_conn()
        except OSError:
            self._cleanup["http_response_close_failed"] = None


class _DirectHTTPSConnection(http.client.HTTPSConnection):
    response_class = _CompleteHTTPResponse

    def __init__(
        self,
        lookup_host: str,
        identity: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
        cleanup: _HTTPCleanup,
        transport: AuthorizedTransport | None = None,
    ):
        super().__init__(identity, port, timeout=timeout, context=context)
        self._transport = transport
        self._lookup_host = lookup_host
        self._cleanup = cleanup
        self.response_class = partial(self.response_class, cleanup=cleanup)
        self.stage: _FailureStage = "connect"

    def connect(self) -> None:
        self.stage = "connect"
        self.sock = (
            socket.create_connection((self._lookup_host, self.port), self.timeout)
            if self._transport is None
            else self._transport.connect("https", self.host, self.port, self.timeout)
        )
        self.stage = "handshake"
        if self._transport is not None:
            self.auto_open = 0
            self.sock.settimeout(self._transport.checkpoint(self.timeout))
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    def close(self) -> None:
        try:
            super().close()
        except OSError:
            self._cleanup["http_connection_close_failed"] = None


class _DirectHTTPConnection(http.client.HTTPConnection):
    response_class = _CompleteHTTPResponse

    def __init__(
        self,
        lookup_host: str,
        identity: str,
        port: int,
        timeout: float,
        cleanup: _HTTPCleanup,
        transport: AuthorizedTransport | None = None,
    ):
        super().__init__(identity, port, timeout=timeout)
        self._transport = transport
        self._lookup_host = lookup_host
        self._cleanup = cleanup
        self.response_class = partial(self.response_class, cleanup=cleanup)

    def connect(self) -> None:
        self.sock = (
            socket.create_connection((self._lookup_host, self.port), self.timeout)
            if self._transport is None
            else self._transport.connect("http", self.host, self.port, self.timeout)
        )
        if self._transport is not None:
            self.auto_open = 0

    def close(self) -> None:
        try:
            super().close()
        except OSError:
            self._cleanup["http_connection_close_failed"] = None


def _new_response_probe() -> _ResponseProbe:
    return {
        "outcome": "invalid_input",
        "http_status": None,
        "failed_stage": "validation",
        "verify_code": None,
        "elapsed_ms": None,
    }


def _probe_response_head(
    lookup_host: str,
    identity: str,
    port: int,
    timeout: float,
    scheme: _Scheme,
    transport: AuthorizedTransport | None = None,
) -> tuple[_ResponseProbe, list[str]]:
    result = _new_response_probe()
    start = time.monotonic()
    stage: _FailureStage = "tls_setup" if scheme == "https" else "connect"
    connection = None
    response = None
    locations: list[str] = []
    cleanup: _HTTPCleanup = {}
    try:
        if scheme == "https":
            try:
                context = _create_verified_client_context()
            except OSError:
                result.update(outcome="tls_error", failed_stage="tls_setup")
                return result, locations
            if ssl.HAS_ALPN:
                context.set_alpn_protocols(["http/1.1"])
            connection = _DirectHTTPSConnection(
                lookup_host, identity, port, timeout, context, cleanup, transport
            )
        else:
            connection = _DirectHTTPConnection(
                lookup_host, identity, port, timeout, cleanup, transport
            )
        connection.connect()
        stage = "request"
        if transport is not None:
            connection.sock.settimeout(transport.checkpoint(timeout))
        connection.request("HEAD", "/", headers={"Connection": "close"})
        stage = "response"
        if transport is not None:
            connection.sock.settimeout(transport.checkpoint(timeout))
        response = connection.getresponse()
        status = response.status
        if 200 <= status <= 599:
            if status in _REDIRECT_STATUSES:
                locations = response.headers.get_all("Location", [])
            result.update(outcome="available", http_status=status)
        elif 100 <= status <= 199:
            result["outcome"] = "unsupported_http_response"
        else:
            result["outcome"] = "invalid_http_response"
    except ssl.SSLCertVerificationError as error:
        result["outcome"] = "certificate_verification_failed"
        result["verify_code"] = getattr(error, "verify_code", None)
    except ConnectionRefusedError:
        result["outcome"] = "connection_refused"
    except TimeoutError:
        result["outcome"] = "timeout"
    except ssl.SSLError:
        result["outcome"] = "tls_error"
    except OSError:
        # RemoteDisconnected also inherits BadStatusLine.
        result["outcome"] = "transport_error"
    except http.client.UnknownProtocol:
        result["outcome"] = "unsupported_http_response"
    except http.client.HTTPException:
        result["outcome"] = "invalid_http_response"
    finally:
        result["elapsed_ms"] = (time.monotonic() - start) * 1000
        try:
            if response is not None:
                response.close()
        finally:
            if connection is not None:
                connection.close()

    if stage == "tls_setup" and isinstance(connection, _DirectHTTPSConnection):
        stage = connection.stage
    result["failed_stage"] = None if result["outcome"] == "available" else stage
    if cleanup:
        result["diagnostics"] = list(cleanup)
    return result, locations


def audit_https_availability(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = 5.0,
    transport: AuthorizedTransport | None = None,
) -> HTTPSAvailabilityResult:
    """Check whether a single HEAD request receives a final response over verified TLS."""
    result: HTTPSAvailabilityResult = {
        "target": {"hostname": None, "port": port if _is_valid_port(port) else None},
        "outcome": "invalid_input",
        "http_status": None,
        "is_redirect": None,
        "failed_stage": "validation",
        "verify_code": None,
        "elapsed_ms": None,
    }
    try:
        lookup_host, identity = _validate_endpoint(hostname, port, timeout)
    except ValueError:
        with suppress(ValueError):
            result["target"]["hostname"] = _normalize_hostname(hostname)[1]
        return result
    result["target"]["hostname"] = identity

    probe, _ = _probe_response_head(
        lookup_host, identity, port, timeout, "https", transport
    )
    result.update(probe)
    if probe["http_status"] is not None:
        result["is_redirect"] = probe["http_status"] in _REDIRECT_STATUSES
    return result


def _canonical_host(hostname: str) -> str:
    with suppress(ValueError):
        return ipaddress.ip_address(hostname).compressed
    return hostname.lower()


def _location_origin(
    location: str, scheme: _Scheme, hostname: str, port: int
) -> tuple[str, str, int] | None:
    reference = urlsplit(location)
    if reference.scheme and reference.scheme not in _DEFAULT_PORTS:
        return None
    if not reference.netloc:
        if (
            reference.scheme
            or location.startswith("//")
            or ":" in reference.path.split("/", 1)[0]
        ):
            raise ValueError("Invalid redirect reference")
        # A relative reference to / keeps the origin regardless of its path.
        return scheme, hostname, port

    authority = _AUTHORITY.fullmatch(reference.netloc)
    if authority is None:
        raise ValueError("Invalid redirect authority")
    _, identity = _normalize_hostname(authority["host"].strip("[]"))
    destination_host = _canonical_host(identity)
    destination_scheme = reference.scheme or scheme
    explicit_port = authority["port"]
    destination_port = (
        int(explicit_port)
        if explicit_port is not None
        else _DEFAULT_PORTS[destination_scheme]
    )
    if not _is_valid_port(destination_port):
        raise ValueError("Invalid redirect port")
    return destination_scheme, destination_host, destination_port


def _classify_redirect(
    status: int, locations: list[str], scheme: _Scheme, hostname: str, port: int
) -> _RedirectAssessment:
    assessment: _RedirectAssessment = {
        "outcome": "no_redirect",
        "destination": None,
        "same_host": None,
        "port_changed": None,
    }
    if status in {305, 306}:
        assessment["outcome"] = "unsupported_redirect_status"
    if status not in _REDIRECT_STATUSES:
        return assessment
    if not locations:
        assessment["outcome"] = "missing_location"
        return assessment
    if len(locations) != 1:
        assessment["outcome"] = "ambiguous_location"
        return assessment

    location = locations[0].strip(" \t")
    if not location:
        assessment["outcome"] = "empty_location"
        return assessment
    if _INVALID_URI_CHARACTER.search(location) or _INVALID_PERCENT_ESCAPE.search(
        location
    ):
        assessment["outcome"] = "invalid_location"
        return assessment
    if "," in location:
        assessment["outcome"] = "ambiguous_location"
        return assessment

    try:
        origin = _location_origin(location, scheme, hostname, port)
    except ValueError:
        assessment["outcome"] = "invalid_location"
        return assessment
    if origin is None:
        assessment["outcome"] = "unsupported_scheme"
        return assessment

    destination_scheme, destination_host, destination_port = origin
    assessment["destination"] = {
        "scheme": destination_scheme,
        "hostname": destination_host,
        "port": destination_port,
        "verification": "not_attempted",
    }
    assessment["same_host"] = hostname == destination_host
    assessment["port_changed"] = port != destination_port
    if destination_scheme == scheme:
        assessment["outcome"] = "same_scheme_redirect"
    else:
        assessment["outcome"] = (
            "upgrade" if destination_scheme == "https" else "downgrade"
        )
    return assessment


def audit_http_redirect(
    hostname: str,
    port: int | None = None,
    *,
    source_scheme: Literal["http", "https"] = "http",
    timeout: float = 5.0,
    transport: AuthorizedTransport | None = None,
) -> HTTPRedirectAuditResult:
    """Classify redirect intent from one authorized origin's response head."""
    scheme = source_scheme if source_scheme in ("http", "https") else None
    source: _RedirectSource = {"scheme": scheme, "hostname": None, "port": None}
    result: HTTPRedirectAuditResult = {
        "source": source,
        "probe": _new_response_probe(),
        "redirect": {
            "outcome": "not_evaluated",
            "destination": None,
            "same_host": None,
            "port_changed": None,
        },
        "recommendations": [],
    }
    if scheme is None:
        return result
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    source["port"] = port if _is_valid_port(port) else None
    try:
        lookup_host, identity = _validate_endpoint(hostname, port, timeout)
    except ValueError:
        with suppress(ValueError):
            source["hostname"] = _canonical_host(_normalize_hostname(hostname)[1])
        return result

    source_host = _canonical_host(identity)
    source["hostname"] = source_host
    probe, locations = _probe_response_head(
        lookup_host, identity, port, timeout, scheme, transport
    )
    result["probe"] = probe
    if probe["http_status"] is None:
        return result

    redirect = _classify_redirect(
        probe["http_status"], locations, scheme, source_host, port
    )
    result["redirect"] = redirect
    advice = result["recommendations"]
    if redirect["outcome"] == "downgrade":
        advice.append("https_to_http_downgrade")
    elif scheme == "http" and redirect["outcome"] in {
        "no_redirect",
        "same_scheme_redirect",
    }:
        advice.append("review_https_upgrade")
    if redirect["same_host"] is False:
        advice.append("review_cross_host_redirect")
    destination = redirect["destination"]
    if (
        destination is not None
        and redirect["port_changed"]
        and destination["port"] != _DEFAULT_PORTS[destination["scheme"]]
    ):
        advice.append("review_unusual_redirect_port")
    return result
