import ipaddress
import re
import socket
import ssl
import sys
from collections.abc import Callable
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from inspect import getattr_static
from stringprep import in_table_b1
from types import TracebackType
from typing import Literal, TypedDict, TypeVar
from unicodedata import category

_DNS_LABEL = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE | re.ASCII
)
_IDNA_SEPARATOR = re.compile("[.\u3002\uff0e\uff61]")
# Some URL parsers interpret a bare 0x component as zero.
_IPV4_NUMBER = re.compile(r"[0-9]+|0x[0-9a-f]*", re.IGNORECASE | re.ASCII)
# Bound the work the IDNA codec can do on untrusted text.
_MAX_HOSTNAME_INPUT_LENGTH = 1024
# Windows CPython converts socket timeouts to signed 32-bit milliseconds.
_MAX_SOCKET_TIMEOUT = (2**31 - 1) / 1000
_TLS_SETUP_DIAGNOSTIC = "Could not initialize the local TLS client context."
_TLS_VERSION_DIAGNOSTIC = "Could not read the negotiated TLS version."
_TLSFailureStage = Literal["validation", "tls_setup", "connect", "handshake"]
_SocketCloseDiagnostic = Literal["tcp_close_failed", "tls_close_failed"]
_TLSAuditDiagnostic = Literal[
    "tls_version_unavailable",
    "cipher_metadata_unavailable",
    "tcp_close_failed",
    "tls_close_failed",
]
_Socket = TypeVar("_Socket", bound=socket.socket)


class _TLSResultDiagnostics(TypedDict, total=False):
    diagnostics: list[_TLSAuditDiagnostic]


class TLSConnectivityResult(_TLSResultDiagnostics):
    hostname: str
    port: int
    status: Literal[
        "ok",
        "invalid_input",
        "tls_setup_error",
        "connection_error",
        "timeout",
        "certificate_verification_failed",
        "tls_handshake_error",
    ]
    failed_stage: _TLSFailureStage | None
    tls_version: str | None
    cipher_suite: str | None
    error_message: str | None
    verify_code: int | None


class _TLSHandshakeEvidence(TypedDict, total=False):
    ssl_reason: str | None
    secret_bits: int | None


class CertificateSAN(TypedDict):
    type: Literal["dns", "ip"]
    value: str


class TLSCertificateMetadata(TypedDict):
    subject: str
    issuer: str
    serial_number: str
    sans: list[CertificateSAN]
    not_valid_before: str
    not_valid_after: str
    remaining_seconds: float
    expiration_status: Literal["current", "expiring_soon", "expired"]
    sha256_fingerprint: str


class TLSCertificateAuditResult(TypedDict):
    connectivity: TLSConnectivityResult | None
    certificate_status: Literal[
        "ok", "not_collected", "metadata_error", "invalid_options"
    ]
    certificate: TLSCertificateMetadata | None
    certificate_error: str | None


def _normalize_hostname(hostname: str) -> tuple[str, str]:
    if not isinstance(hostname, str) or not hostname:
        raise ValueError("hostname must be a nonempty string")
    if len(hostname) > _MAX_HOSTNAME_INPUT_LENGTH:
        raise ValueError("hostname is too long to normalize safely")
    if "%" in hostname:
        raise ValueError(
            "hostname cannot contain percent escapes or IPv6 scope identifiers"
        )
    # IDNA's Nameprep can delete characters, so check for them before encoding.
    if any(
        char.isspace()
        or category(char) in {"Cc", "Cf"}
        or in_table_b1(char)
        or char in "/\\?#@[]"
        for char in hostname
    ):
        raise ValueError(
            "hostname contains whitespace, control characters, or URL syntax"
        )

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if ":" in hostname:
            raise ValueError(
                "hostname contains an invalid IPv6 address or an embedded port"
            ) from None
    else:
        return hostname, hostname

    # Split before encoding so normalization cannot create new label boundaries.
    labels = _IDNA_SEPARATOR.split(hostname)
    absolute = labels[-1] == ""
    if absolute:
        labels.pop()
    try:
        labels = [label.encode("idna").decode("ascii") for label in labels]
    except UnicodeError:
        raise ValueError(
            "hostname has an invalid IDNA label or a label longer than 63 bytes"
        ) from None

    tls_identity = ".".join(labels)
    if len(tls_identity) > 253 or not all(
        _DNS_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError(
            "hostname must fit within 253 ASCII characters and use valid DNS labels"
        )
    if all(_IPV4_NUMBER.fullmatch(label) for label in labels):
        raise ValueError("hostname uses a malformed or ambiguous IPv4 representation")

    # Check Punycode directly to preserve pre-encoded IDNA 2008 names.
    for label in labels:
        if not label.lower().startswith("xn--"):
            continue
        payload = label[4:].lower().encode("ascii")
        try:
            decoded = payload.decode("punycode")
        except UnicodeError:
            raise ValueError("hostname has a malformed Punycode label") from None
        if (
            decoded.isascii()
            or any(category(char) in {"Cc", "Cs"} for char in decoded)
            or decoded.encode("punycode") != payload
        ):
            raise ValueError("hostname has a malformed Punycode label")

    lookup_host = f"{tls_identity}." if absolute else tls_identity
    return lookup_host, tls_identity


def _is_valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _validate_endpoint(hostname: str, port: int, timeout: float) -> tuple[str, str]:
    lookup_host, tls_identity = _normalize_hostname(hostname)
    if not _is_valid_port(port):
        raise ValueError("port must be an integer from 1 to 65535")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < timeout <= _MAX_SOCKET_TIMEOUT
    ):
        raise ValueError(
            f"timeout must be a positive finite number up to {_MAX_SOCKET_TIMEOUT} seconds"
        )
    return lookup_host, tls_identity


def audit_tls_connectivity(
    hostname: str, port: int = 443, *, timeout: float = 5.0
) -> TLSConnectivityResult:
    """Report a verified TLS connection's settings or failure.

    IPv6 scope identifiers are unsupported.
    """
    return _audit_tls(hostname, port, timeout)


def _create_verified_client_context() -> ssl.SSLContext:
    """Create a fresh verified client context without honoring SSLKEYLOGFILE."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # CPython's default factory adds these verification flags from Python 3.13.
    if sys.version_info >= (3, 13):
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context


def _enter_socket(
    stack: ExitStack,
    manager: _Socket,
    diagnostics: list[_TLSAuditDiagnostic],
    close_failure: _SocketCloseDiagnostic,
) -> _Socket:
    def guarded_exit(
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            return manager.__exit__(exc_type, exc, traceback)
        except OSError:
            diagnostics.append(close_failure)
            return False

    resource = manager.__enter__()
    stack.push(guarded_exit)
    return resource


def _audit_tls(
    hostname: str,
    port: int,
    timeout: float,
    collect: Callable[[ssl.SSLSocket], None] | None = None,
    *,
    context: ssl.SSLContext | None = None,
    evidence: _TLSHandshakeEvidence | None = None,
) -> TLSConnectivityResult:
    result: TLSConnectivityResult = {
        "hostname": hostname,
        "port": port,
        "status": "ok",
        "failed_stage": None,
        "tls_version": None,
        "cipher_suite": None,
        "error_message": None,
        "verify_code": None,
    }
    try:
        lookup_host, tls_identity = _validate_endpoint(hostname, port, timeout)
    except ValueError as error:
        result["status"] = "invalid_input"
        result["failed_stage"] = "validation"
        result["error_message"] = str(error)
        return result

    if context is None:
        try:
            context = _create_verified_client_context()
        except OSError:
            result.update(
                status="tls_setup_error",
                failed_stage="tls_setup",
                error_message=_TLS_SETUP_DIAGNOSTIC,
            )
            return result
    stage: Literal["connect", "handshake"] = "connect"
    diagnostics: list[_TLSAuditDiagnostic] = []

    with ExitStack() as sockets:
        try:
            tcp_socket = _enter_socket(
                sockets,
                socket.create_connection((lookup_host, port), timeout=timeout),
                diagnostics,
                "tcp_close_failed",
            )
            stage = "handshake"
            tls_socket = _enter_socket(
                sockets,
                context.wrap_socket(
                    tcp_socket,
                    server_hostname=tls_identity,
                    do_handshake_on_connect=False,
                ),
                diagnostics,
                "tls_close_failed",
            )
            tls_socket.settimeout(timeout)
            tls_socket.do_handshake()
        except ssl.SSLCertVerificationError as error:
            result["status"] = "certificate_verification_failed"
            result["error_message"] = getattr(error, "verify_message", None) or str(
                error
            )
            result["verify_code"] = getattr(error, "verify_code", None)
        except TimeoutError as error:
            result["status"] = "timeout"
            result["error_message"] = str(error)
        except ssl.SSLError as error:
            result["status"] = "tls_handshake_error"
            if evidence is not None:
                evidence["ssl_reason"] = getattr(error, "reason", None)
            result["error_message"] = str(error)
        except OSError as error:
            result["status"] = "connection_error"
            result["error_message"] = str(error)
        else:
            try:
                result["tls_version"] = tls_socket.version()
            except OSError:
                diagnostics.append("tls_version_unavailable")
            try:
                cipher_info = tls_socket.cipher()
            except OSError:
                diagnostics.append("cipher_metadata_unavailable")
            else:
                if cipher_info is not None:
                    result["cipher_suite"] = cipher_info[0]
                    if evidence is not None:
                        evidence["secret_bits"] = cipher_info[2]
            if collect is not None:
                collect(tls_socket)

    if result["status"] != "ok":
        result["failed_stage"] = stage
    if diagnostics:
        result["diagnostics"] = diagnostics
    return result


class _CertificateDependencyError(Exception):
    pass


def _certificate_metadata(der: bytes, warning_days: int) -> TLSCertificateMetadata:
    try:
        from cryptography import x509
    except ImportError:
        raise _CertificateDependencyError from None

    try:
        leaf = x509.load_der_x509_certificate(der)
        sans: list[CertificateSAN] = []
        try:
            names = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            pass
        else:
            for name in names:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "dns", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "ip", "value": str(name.value)})
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        raise ValueError("Unable to parse verified certificate metadata") from None

    missing = object()
    if (
        getattr_static(leaf, "not_valid_before_utc", missing) is missing
        or getattr_static(leaf, "not_valid_after_utc", missing) is missing
    ):
        raise _CertificateDependencyError

    expires = leaf.not_valid_after_utc
    now = datetime.now(timezone.utc)  # noqa: UP017 - Keep Python 3.10 compatibility.
    remaining = expires - now
    expiration_status: Literal["current", "expiring_soon", "expired"] = "current"
    if remaining <= timedelta(0):
        expiration_status = "expired"
    elif (remaining.days, remaining.seconds, remaining.microseconds) <= (
        warning_days,
        0,
        0,
    ):
        expiration_status = "expiring_soon"

    return {
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial_number": format(leaf.serial_number, "x"),
        "sans": sans,
        "not_valid_before": leaf.not_valid_before_utc.isoformat(),
        "not_valid_after": expires.isoformat(),
        "remaining_seconds": remaining.total_seconds(),
        "expiration_status": expiration_status,
        "sha256_fingerprint": sha256(der).hexdigest(),
    }


def audit_tls_certificate(
    hostname: str, port: int = 443, *, timeout: float = 5.0, warning_days: int = 30
) -> TLSCertificateAuditResult:
    """Collect leaf metadata only after the peer passes certificate and identity checks."""
    result: TLSCertificateAuditResult = {
        "connectivity": None,
        "certificate_status": "not_collected",
        "certificate": None,
        "certificate_error": None,
    }
    if (
        not isinstance(warning_days, int)
        or isinstance(warning_days, bool)
        or warning_days < 0
    ):
        result["certificate_status"] = "invalid_options"
        result["certificate_error"] = "warning_days must be a nonnegative integer"
        return result

    der = None

    def capture(socket: ssl.SSLSocket) -> None:
        nonlocal der
        try:
            der = socket.getpeercert(binary_form=True)
        except (OSError, ValueError):
            result["certificate_error"] = "Unable to read verified certificate DER"

    connectivity = _audit_tls(hostname, port, timeout, capture)
    result["connectivity"] = connectivity
    if connectivity["status"] != "ok":
        return result

    result["certificate_status"] = "metadata_error"
    if not der:
        result["certificate_error"] = (
            result["certificate_error"] or "Verified peer supplied no certificate DER"
        )
        return result
    try:
        result["certificate"] = _certificate_metadata(der, warning_days)
    except _CertificateDependencyError:
        result["certificate_error"] = (
            "cryptography is required for certificate metadata"
        )
    except ValueError:
        result["certificate_error"] = "Unable to parse verified certificate metadata"
    else:
        result["certificate_status"] = "ok"
    return result


class TLSProtocolProbe(_TLSResultDiagnostics):
    requested_version: str
    outcome: Literal[
        "confirmed_supported", "client_restricted", "server_rejected", "inconclusive"
    ]
    evidence_code: str
    negotiated_version: str | None
    cipher_suite: str | None
    secret_bits: int | None
    failed_stage: _TLSFailureStage | None
    error_message: str | None
    verify_code: int | None


class TLSProtocolAuditResult(TypedDict):
    target: dict[str, str | int | None]
    status: Literal["ok", "invalid_input"]
    error_message: str | None
    probes: list[TLSProtocolProbe]
    not_probed: list[str]
    recommendations: list[dict[str, str]]


_MODERN_PROTOCOLS = (
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "HAS_TLSv1_2", ssl.OP_NO_TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "HAS_TLSv1_3", ssl.OP_NO_TLSv1_3),
)
_LEGACY_PROTOCOLS = (
    ("TLSv1", ssl.TLSVersion.TLSv1, "HAS_TLSv1", ssl.OP_NO_TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "HAS_TLSv1_1", ssl.OP_NO_TLSv1_1),
)


def _probe_tls_version(
    hostname: str,
    port: int,
    timeout: float,
    name: str,
    version: ssl.TLSVersion,
    build_flag: str,
    disable_flag: int,
) -> TLSProtocolProbe:
    probe: TLSProtocolProbe = {
        "requested_version": name,
        "outcome": "client_restricted",
        "evidence_code": "runtime_version_unavailable",
        "negotiated_version": None,
        "cipher_suite": None,
        "secret_bits": None,
        "failed_stage": None,
        "error_message": None,
        "verify_code": None,
    }
    if not getattr(ssl, build_flag):
        return probe

    try:
        context = _create_verified_client_context()
    except OSError:
        probe.update(
            outcome="inconclusive",
            evidence_code="tls_setup_error",
            failed_stage="tls_setup",
            error_message=_TLS_SETUP_DIAGNOSTIC,
        )
        return probe
    if (
        version < context.minimum_version
        or (
            context.maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
            and version > context.maximum_version
        )
        or context.options & disable_flag
    ):
        probe["evidence_code"] = "client_version_policy"
        return probe
    try:
        context.minimum_version = context.maximum_version = version
    except (ValueError, ssl.SSLError) as error:
        probe["evidence_code"] = "client_version_configuration"
        probe["error_message"] = str(error)
        return probe

    evidence: _TLSHandshakeEvidence = {}
    connection = _audit_tls(hostname, port, timeout, context=context, evidence=evidence)
    reason = evidence.get("ssl_reason")
    probe.update(
        outcome="inconclusive",
        evidence_code=reason or connection["status"],
        negotiated_version=connection["tls_version"],
        cipher_suite=connection["cipher_suite"],
        secret_bits=evidence.get("secret_bits"),
        failed_stage=connection["failed_stage"],
        error_message=connection["error_message"],
        verify_code=connection["verify_code"],
    )
    diagnostics = connection.get("diagnostics")
    if diagnostics:
        probe["diagnostics"] = diagnostics
    if connection["status"] == "ok":
        if diagnostics and "tls_version_unavailable" in diagnostics:
            probe.update(
                evidence_code="tls_version_unavailable",
                error_message=_TLS_VERSION_DIAGNOSTIC,
            )
        elif connection["tls_version"] == name:
            probe.update(
                outcome="confirmed_supported", evidence_code="verified_handshake"
            )
        else:
            probe["evidence_code"] = "unexpected_negotiated_version"
    elif connection["failed_stage"] == "handshake":
        if reason == "TLSV1_ALERT_PROTOCOL_VERSION":
            probe["outcome"] = "server_rejected"
        elif reason in {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"}:
            probe["outcome"] = "client_restricted"
    return probe


def audit_tls_protocols(
    hostname: str, port: int = 443, *, timeout: float = 5.0, probe_legacy: bool = False
) -> TLSProtocolAuditResult:
    """Probe exact versions under the client policy and report one cipher per handshake."""
    result: TLSProtocolAuditResult = {
        "target": {
            "hostname": hostname if isinstance(hostname, str) else None,
            "port": port if _is_valid_port(port) else None,
        },
        "status": "ok",
        "error_message": None,
        "probes": [],
        "not_probed": [],
        "recommendations": [],
    }
    try:
        if not isinstance(probe_legacy, bool):
            raise TypeError("probe_legacy must be a boolean")
        _validate_endpoint(hostname, port, timeout)
    except (TypeError, ValueError) as error:
        result["status"] = "invalid_input"
        result["error_message"] = str(error)
        return result

    versions = _MODERN_PROTOCOLS
    if probe_legacy:
        versions += _LEGACY_PROTOCOLS
    else:
        result["not_probed"] = [name for name, *_ in _LEGACY_PROTOCOLS]

    for version in versions:
        result["probes"].append(_probe_tls_version(hostname, port, timeout, *version))

    tls12, tls13, *legacy = result["probes"]
    if any(probe["outcome"] == "confirmed_supported" for probe in legacy):
        result["recommendations"].append(
            {
                "code": "disable_legacy_tls",
                "message": "Disable the legacy TLS versions confirmed by verified handshakes.",
            }
        )
    if (
        tls12["outcome"] == "confirmed_supported"
        and tls13["outcome"] == "server_rejected"
    ):
        result["recommendations"].append(
            {
                "code": "review_tls_1_3",
                "message": "Review TLS 1.3 availability for the audited endpoint.",
            }
        )
    return result
