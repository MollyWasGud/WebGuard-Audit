import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
from concurrent.futures import Future
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from webguard.auditors import tls


def test_successful_handshake_reports_verified_tls_details():
    hostname = "example.test"
    port = 443
    timeout = 2.5

    tcp_socket = MagicMock(spec=socket.socket)
    tcp_socket.__enter__.return_value = tcp_socket
    tls_socket = MagicMock(spec=ssl.SSLSocket)
    tls_socket.__enter__.return_value = tls_socket
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def wrap_verified_socket(
        context, sock, *, server_hostname, do_handshake_on_connect
    ):
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert sock is tcp_socket
        assert server_hostname == hostname
        assert do_handshake_on_connect is False
        return tls_socket

    with (
        patch("socket.create_connection", return_value=tcp_socket) as connect,
        patch.object(
            tls,
            "_create_verified_client_context",
            wraps=tls._create_verified_client_context,
        ) as create_context,
        patch.object(
            ssl.SSLContext,
            "wrap_socket",
            autospec=True,
            side_effect=wrap_verified_socket,
        ) as wrap_socket,
    ):
        result = tls.audit_tls_connectivity(hostname, timeout=timeout)

    assert result == {
        "hostname": hostname,
        "port": port,
        "status": "ok",
        "failed_stage": None,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "error_message": None,
        "verify_code": None,
    }
    create_context.assert_called_once()
    connect.assert_called_once_with((hostname, port), timeout=timeout)
    wrap_socket.assert_called_once()
    tls_socket.do_handshake.assert_called_once_with()


@pytest.mark.parametrize(
    ("verify_code", "diagnostic"),
    [
        pytest.param(10, "certificate has expired", id="expired"),
        pytest.param(20, "unable to get local issuer certificate", id="untrusted"),
        pytest.param(62, "hostname mismatch", id="hostname-mismatch"),
        pytest.param(
            None, "unable to get local issuer certificate", id="untrusted-without-code"
        ),
    ],
)
def test_certificate_verification_failure_reports_diagnostic(verify_code, diagnostic):
    hostname = "example.test"
    tcp_socket = MagicMock(spec=socket.socket)
    tcp_socket.__enter__.return_value = tcp_socket
    tls_socket = MagicMock(spec=ssl.SSLSocket)
    tls_socket.__enter__.return_value = tls_socket

    certificate_error = ssl.SSLCertVerificationError(
        ssl.SSL_ERROR_SSL, f"certificate verify failed: {diagnostic}"
    )
    certificate_error.verify_message = diagnostic
    if verify_code is not None:
        certificate_error.verify_code = verify_code
    tls_socket.do_handshake.side_effect = certificate_error

    def wrap_verified_socket(
        context, sock, *, server_hostname, do_handshake_on_connect
    ):
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert sock is tcp_socket
        assert server_hostname == hostname
        assert do_handshake_on_connect is False
        return tls_socket

    with (
        patch("socket.create_connection", return_value=tcp_socket) as connect,
        patch.object(
            ssl.SSLContext,
            "wrap_socket",
            autospec=True,
            side_effect=wrap_verified_socket,
        ),
    ):
        result = tls.audit_tls_connectivity(hostname)

    assert result["hostname"] == hostname
    assert result["port"] == 443
    assert result["status"] == "certificate_verification_failed"
    assert result["failed_stage"] == "handshake"
    assert result["tls_version"] is None
    assert result["cipher_suite"] is None
    assert result["verify_code"] == verify_code
    assert isinstance(result["error_message"], str)
    assert diagnostic in result["error_message"]
    connect.assert_called_once()
    tls_socket.do_handshake.assert_called_once_with()


@pytest.mark.parametrize(
    ("failed_stage", "exception_type", "expected_status", "diagnostic"),
    [
        pytest.param(
            "connect",
            TimeoutError,
            "timeout",
            "TCP connection timed out",
            id="tcp-timeout",
        ),
        pytest.param(
            "connect",
            socket.gaierror,
            "connection_error",
            "hostname resolution failed",
            id="dns-failure",
        ),
        pytest.param(
            "connect",
            ConnectionRefusedError,
            "connection_error",
            "TCP connection refused",
            id="tcp-refused",
        ),
        pytest.param(
            "handshake",
            TimeoutError,
            "timeout",
            "TLS handshake timed out",
            id="handshake-timeout",
        ),
        pytest.param(
            "handshake",
            ssl.SSLError,
            "tls_handshake_error",
            "TLS protocol negotiation failed",
            id="tls-error",
        ),
        pytest.param(
            "handshake",
            ConnectionResetError,
            "connection_error",
            "connection reset during TLS handshake",
            id="handshake-reset",
        ),
    ],
)
def test_network_failure_reports_stage_and_diagnostic(
    failed_stage, exception_type, expected_status, diagnostic
):
    hostname = "example.test"
    port = 8443
    timeout = 2.5
    error = exception_type(diagnostic)
    tcp_socket = MagicMock(spec=socket.socket)
    tcp_socket.__enter__.return_value = tcp_socket
    tls_socket = MagicMock(spec=ssl.SSLSocket)
    tls_socket.__enter__.return_value = tls_socket

    def wrap_verified_socket(
        context, sock, *, server_hostname, do_handshake_on_connect
    ):
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert sock is tcp_socket
        assert server_hostname == hostname
        assert do_handshake_on_connect is False
        return tls_socket

    with (
        patch("socket.create_connection", return_value=tcp_socket) as connect,
        patch.object(
            ssl.SSLContext,
            "wrap_socket",
            autospec=True,
            side_effect=wrap_verified_socket,
        ) as wrap_socket,
    ):
        if failed_stage == "connect":
            connect.side_effect = error
        else:
            tls_socket.do_handshake.side_effect = error
        result = tls.audit_tls_connectivity(hostname, port=port, timeout=timeout)

    assert result["hostname"] == hostname
    assert result["port"] == port
    assert result["status"] == expected_status
    assert result["failed_stage"] == failed_stage
    assert result["tls_version"] is None
    assert result["cipher_suite"] is None
    assert result["verify_code"] is None
    assert isinstance(result["error_message"], str)
    assert diagnostic in result["error_message"]
    connect.assert_called_once_with((hostname, port), timeout=timeout)
    if failed_stage == "connect":
        wrap_socket.assert_not_called()
        tls_socket.do_handshake.assert_not_called()
    else:
        wrap_socket.assert_called_once()
        tls_socket.do_handshake.assert_called_once_with()


@pytest.fixture
def validation_network_mocks():
    tcp_socket = MagicMock(spec=socket.socket)
    tcp_socket.__enter__.return_value = tcp_socket
    tls_socket = MagicMock(spec=ssl.SSLSocket)
    tls_socket.__enter__.return_value = tls_socket
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    context = MagicMock(spec=ssl.SSLContext)
    context.wrap_socket.return_value = tls_socket

    with (
        patch.object(
            tls, "_create_verified_client_context", return_value=context
        ) as create_context,
        patch.object(socket, "getaddrinfo", return_value=[]) as resolve,
        patch.object(socket, "create_connection", return_value=tcp_socket) as connect,
    ):
        yield (
            create_context,
            resolve,
            connect,
            context.wrap_socket,
            tls_socket.do_handshake,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("hostname", "", id="empty-hostname"),
        pytest.param("hostname", " \t", id="blank-hostname"),
        pytest.param("hostname", "example .test", id="hostname-whitespace"),
        pytest.param("hostname", "example\x00.test", id="hostname-control"),
        pytest.param("hostname", "http://example.test", id="http-url"),
        pytest.param("hostname", "https://example.test", id="https-url"),
        pytest.param("hostname", "example.test/path", id="hostname-path"),
        pytest.param("hostname", "example.test?q=1", id="hostname-query"),
        pytest.param("hostname", "example.test#section", id="hostname-fragment"),
        pytest.param("hostname", "user:pass@example.test", id="hostname-credentials"),
        pytest.param("hostname", "example.test:443", id="hostname-port"),
        pytest.param("hostname", "example..test", id="dns-empty-label"),
        pytest.param("hostname", "-example.test", id="dns-leading-hyphen"),
        pytest.param("hostname", "999.1.2.3", id="malformed-ipv4"),
        pytest.param("hostname", "2001:db8:::1", id="malformed-ipv6"),
        pytest.param("port", 0, id="port-zero"),
        pytest.param("port", -1, id="port-negative"),
        pytest.param("port", 65536, id="port-too-large"),
        pytest.param("port", True, id="port-true"),
        pytest.param("port", False, id="port-false"),
        pytest.param("timeout", 0, id="timeout-zero"),
        pytest.param("timeout", -1, id="timeout-negative"),
        pytest.param("timeout", float("nan"), id="timeout-nan"),
        pytest.param("timeout", float("inf"), id="timeout-positive-infinity"),
        pytest.param("timeout", float("-inf"), id="timeout-negative-infinity"),
        pytest.param("timeout", True, id="timeout-true"),
        pytest.param("timeout", False, id="timeout-false"),
    ],
)
def test_invalid_input_is_rejected_before_network_activity(
    field, value, validation_network_mocks
):
    requested = {"hostname": "example.test", "port": 443, "timeout": 5.0}
    requested[field] = value
    create_context, resolve, connect, wrap_socket, handshake = validation_network_mocks

    result = tls.audit_tls_connectivity(**requested)

    assert result["hostname"] == requested["hostname"]
    assert result["port"] == requested["port"]
    assert type(result["port"]) is type(requested["port"])
    assert result["status"] == "invalid_input"
    assert result["failed_stage"] == "validation"
    assert result["tls_version"] is None
    assert result["cipher_suite"] is None
    assert result["verify_code"] is None
    diagnostic = result["error_message"]
    assert isinstance(diagnostic, str)
    assert field in diagnostic.casefold()
    assert diagnostic.strip().casefold() != field
    create_context.assert_not_called()
    resolve.assert_not_called()
    connect.assert_not_called()
    wrap_socket.assert_not_called()
    handshake.assert_not_called()


@pytest.mark.parametrize(
    ("hostname", "port", "timeout"),
    [
        pytest.param("example.test", 1, 1, id="dns-min-port-int-timeout"),
        pytest.param(
            "localhost", 65535, 0.25, id="single-label-max-port-float-timeout"
        ),
        pytest.param("192.0.2.1", 443, 2, id="ipv4"),
        pytest.param("2001:db8::1", 8443, 2.5, id="unbracketed-ipv6"),
    ],
)
def test_valid_endpoint_reaches_verified_handshake(
    hostname, port, timeout, validation_network_mocks
):
    create_context, _, connect, wrap_socket, handshake = validation_network_mocks

    result = tls.audit_tls_connectivity(hostname, port=port, timeout=timeout)

    assert result["status"] == "ok"
    assert result["failed_stage"] is None
    assert result["hostname"] == hostname
    assert result["port"] == port
    create_context.assert_called_once()
    connect.assert_called_once_with((hostname, port), timeout=timeout)
    wrap_socket.assert_called_once()
    assert wrap_socket.call_args.kwargs["server_hostname"] == hostname
    handshake.assert_called_once_with()


@pytest.mark.parametrize(
    ("hostname", "lookup_host", "tls_identity"),
    [
        pytest.param(
            "b\u00fccher.example",
            "xn--bcher-kva.example",
            "xn--bcher-kva.example",
            id="idna",
        ),
        pytest.param("example.test.", "example.test.", "example.test", id="root-dot"),
        pytest.param(
            "b\u00fccher.example.",
            "xn--bcher-kva.example.",
            "xn--bcher-kva.example",
            id="idna-with-root-dot",
        ),
        pytest.param(
            "b\u00fccher\u3002example\uff0e",
            "xn--bcher-kva.example.",
            "xn--bcher-kva.example",
            id="idna-recognized-separators",
        ),
        pytest.param(
            "xn--bcher-kva.example",
            "xn--bcher-kva.example",
            "xn--bcher-kva.example",
            id="preencoded-idna",
        ),
        pytest.param(
            "XN--FA-HIA.test.",
            "XN--FA-HIA.test.",
            "XN--FA-HIA.test",
            id="preencoded-idna2008-uppercase-root-dot",
        ),
    ],
)
def test_normalized_hostname_reaches_lookup_and_tls(
    hostname, lookup_host, tls_identity, validation_network_mocks
):
    create_context, _, connect, wrap_socket, handshake = validation_network_mocks

    result = tls.audit_tls_connectivity(hostname, port=8443, timeout=2.5)

    assert result["status"] == "ok"
    assert result["hostname"] == hostname
    assert result["port"] == 8443
    create_context.assert_called_once()
    connect.assert_called_once_with((lookup_host, 8443), timeout=2.5)
    wrap_socket.assert_called_once()
    assert wrap_socket.call_args.kwargs["server_hostname"] == tls_identity
    handshake.assert_called_once_with()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("hostname", "example.test..", id="multiple-root-dots"),
        pytest.param("hostname", "example-.test", id="dns-trailing-hyphen"),
        pytest.param("hostname", "a" * 64 + ".test", id="dns-label-too-long"),
        pytest.param("hostname", ".".join(["a" * 63] * 4), id="dns-name-too-long"),
        pytest.param("hostname", "fe80::1%3", id="scoped-ipv6"),
        pytest.param("hostname", "127.1", id="abbreviated-ipv4"),
        pytest.param("hostname", "2130706433", id="integer-ipv4"),
        pytest.param("hostname", "0x7f000001", id="hexadecimal-ipv4"),
        pytest.param("hostname", "0177.0.0.1", id="octal-ipv4"),
        pytest.param(
            "hostname",
            "\uff11\uff12\uff17.0.0.1",
            id="idna-mapped-ipv4",
        ),
        pytest.param("hostname", "ex\u034fample.test", id="idna-ignored-character"),
        pytest.param("hostname", "example.test\uff1a443", id="idna-mapped-colon"),
        pytest.param("hostname", "example\u2024test", id="idna-introduced-separator"),
        pytest.param("hostname", "example\u2024", id="idna-introduced-root-dot"),
        pytest.param("hostname", "xn--0.test", id="malformed-punycode"),
        pytest.param("hostname", "example.XN--0.", id="malformed-punycode-uppercase"),
        pytest.param(
            "hostname",
            "https://audit-user:fixture-secret@example.test",
            id="credentials-omitted-from-diagnostic",
        ),
        pytest.param("port", 443.0, id="float-port"),
        pytest.param("port", "443", id="text-port"),
        pytest.param("port", None, id="none-port"),
        pytest.param("timeout", "5", id="text-timeout"),
        pytest.param("timeout", None, id="none-timeout"),
        pytest.param("timeout", 5 + 0j, id="complex-timeout"),
        pytest.param("timeout", 1e100, id="oversize-float-timeout"),
        pytest.param("timeout", 10**1000, id="oversize-int-timeout"),
        pytest.param("timeout", 2147483.6470000003, id="timeout-over-socket-limit"),
    ],
)
def test_invalid_endpoint_edge_cases_are_rejected_before_network_activity(
    field, value, validation_network_mocks
):
    requested = {"hostname": "example.test", "port": 443, "timeout": 5.0}
    requested[field] = value
    create_context, resolve, connect, wrap_socket, handshake = validation_network_mocks

    result = tls.audit_tls_connectivity(**requested)

    diagnostic = result["error_message"]
    assert result == {
        "hostname": requested["hostname"],
        "port": requested["port"],
        "status": "invalid_input",
        "failed_stage": "validation",
        "tls_version": None,
        "cipher_suite": None,
        "error_message": diagnostic,
        "verify_code": None,
    }
    assert type(result["port"]) is type(requested["port"])
    assert isinstance(diagnostic, str)
    assert field in diagnostic.casefold()
    assert diagnostic.strip().casefold() != field
    assert "fixture-secret" not in diagnostic
    create_context.assert_not_called()
    resolve.assert_not_called()
    connect.assert_not_called()
    wrap_socket.assert_not_called()
    handshake.assert_not_called()


def test_socket_timeout_limit_is_accepted(validation_network_mocks):
    _, _, connect, _, handshake = validation_network_mocks
    timeout = 2147483.647

    result = tls.audit_tls_connectivity("example.test", timeout=timeout)

    assert result["status"] == "ok"
    connect.assert_called_once_with(("example.test", 443), timeout=timeout)
    handshake.assert_called_once_with()


@pytest.mark.parametrize(
    ("failure_point", "exception_type", "expected_result"),
    [
        pytest.param(None, None, ("ok", None), id="successful-handshake"),
        pytest.param(
            "connect",
            ConnectionRefusedError,
            ("connection_error", "connect"),
            id="tcp-connect-failure",
        ),
        pytest.param(
            "wrap",
            ssl.SSLError,
            ("tls_handshake_error", "handshake"),
            id="tls-wrap-failure",
        ),
        pytest.param(
            "settimeout",
            OSError,
            ("connection_error", "handshake"),
            id="tls-timeout-configuration-failure",
        ),
        pytest.param(
            "handshake",
            ssl.SSLCertVerificationError,
            ("certificate_verification_failed", "handshake"),
            id="certificate-verification-failure",
        ),
        pytest.param(
            "handshake",
            TimeoutError,
            ("timeout", "handshake"),
            id="tls-handshake-timeout",
        ),
        pytest.param(
            "handshake",
            ssl.SSLError,
            ("tls_handshake_error", "handshake"),
            id="tls-handshake-failure",
        ),
        pytest.param(
            "handshake",
            ConnectionResetError,
            ("connection_error", "handshake"),
            id="handshake-connection-reset",
        ),
        pytest.param("version", OSError, ("ok", None), id="tls-version-read-failure"),
        pytest.param("cipher", OSError, ("ok", None), id="cipher-suite-read-failure"),
        pytest.param("tls_exit", OSError, ("ok", None), id="tls-context-exit-failure"),
    ],
)
def test_socket_context_cleanup(failure_point, exception_type, expected_result):
    tcp_socket = MagicMock(spec=socket.socket, name="tcp_socket")
    tls_socket = MagicMock(spec=ssl.SSLSocket, name="tls_socket")
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    lifecycle = MagicMock()
    for name, socket_mock in (("tcp", tcp_socket), ("tls", tls_socket)):
        socket_mock.__enter__.return_value = socket_mock
        lifecycle.attach_mock(socket_mock.__enter__, f"{name}_enter")
        lifecycle.attach_mock(socket_mock.__exit__, f"{name}_exit")

    context = MagicMock(spec=ssl.SSLContext)
    context.wrap_socket.return_value = tls_socket
    error = (
        exception_type("injected socket lifecycle failure") if exception_type else None
    )

    with (
        patch.object(socket, "create_connection", return_value=tcp_socket) as connect,
        patch.object(tls, "_create_verified_client_context", return_value=context),
    ):
        operations = {
            "connect": connect,
            "wrap": context.wrap_socket,
            "settimeout": tls_socket.settimeout,
            "handshake": tls_socket.do_handshake,
            "version": tls_socket.version,
            "cipher": tls_socket.cipher,
            "tls_exit": tls_socket.__exit__,
        }
        if error is not None:
            operations[failure_point].side_effect = error

        result = tls.audit_tls_connectivity("example.test")
        assert (result["status"], result["failed_stage"]) == expected_result
        operational_diagnostics = {
            "version": "tls_version_unavailable",
            "cipher": "cipher_metadata_unavailable",
            "tls_exit": "tls_close_failed",
        }
        if failure_point in operational_diagnostics:
            assert result["diagnostics"] == [operational_diagnostics[failure_point]]
            assert result["error_message"] is None
            assert result["tls_version"] == (
                None if failure_point == "version" else "TLSv1.3"
            )
            assert result["cipher_suite"] == (
                None if failure_point == "cipher" else "TLS_AES_128_GCM_SHA256"
            )

    connect.assert_called_once()
    if failure_point == "connect":
        context.wrap_socket.assert_not_called()
        expected_lifecycle = []
    else:
        context.wrap_socket.assert_called_once()
        if failure_point == "wrap":
            expected_lifecycle = ["tcp_enter", "tcp_exit"]
        else:
            expected_lifecycle = ["tcp_enter", "tls_enter", "tls_exit", "tcp_exit"]

    assert [entry[0] for entry in lifecycle.mock_calls] == expected_lifecycle


_LOOPBACK = "127.0.0.1"
_LOCAL_TLS_TIMEOUT = 5.0
# The server can block in accept, handshake, and the EOF check.
_LOCAL_TLS_WAIT = 3 * _LOCAL_TLS_TIMEOUT + 1


@pytest.fixture(scope="module")
def local_tls_certificate(tmp_path_factory, request):
    x509 = pytest.importorskip(
        "cryptography.x509",
        reason="Temporary TLS certificate generation requires cryptography",
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebGuard Test CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)  # noqa: UP017 - Keep Python 3.10 compatibility.

    def certificate(subject, issuer, key, lifetime=timedelta(hours=1)):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + lifetime)
        )

    ca_certificate = (
        certificate(ca_name, ca_name, ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_lifetime = getattr(request, "param", timedelta(hours=1))
    server_certificate = (
        certificate(server_name, ca_name, server_key, leaf_lifetime)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    temp_root = tmp_path_factory.getbasetemp().resolve()
    assert not temp_root.is_relative_to(Path(__file__).resolve().parents[1])
    with TemporaryDirectory(dir=temp_root, prefix="webguard-local-tls-") as directory:
        certificate_path = Path(directory) / "server-cert.pem"
        key_path = Path(directory) / "server-key.pem"
        certificate_path.write_bytes(
            server_certificate.public_bytes(serialization.Encoding.PEM)
        )
        key_path.write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # The auditor closes after the handshake, so avoid sending resumption tickets.
        context.num_tickets = 0
        context.load_cert_chain(certificate_path, key_path)
        yield (
            context,
            ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        )
    assert not Path(directory).exists()


def _observe_local_tls(listener, context, *, include_secret_bits=False):
    peer, address = listener.accept()
    with peer:
        assert address[0] == _LOOPBACK
        peer.settimeout(_LOCAL_TLS_TIMEOUT)
        with context.wrap_socket(
            peer, server_side=True, do_handshake_on_connect=False
        ) as connection:
            try:
                connection.do_handshake()
            except (
                ssl.SSLError,
                ConnectionAbortedError,
                ConnectionResetError,
            ) as error:
                # Winsock can reset the connection before the server reads the alert.
                observation = error
            else:
                version, cipher = connection.version(), connection.cipher()
                assert version and cipher
                observation = version, cipher[0], connection.recv(1)
                if include_secret_bits:
                    observation += (cipher[2],)
        assert connection.fileno() == -1
    assert peer.fileno() == -1
    return observation


@pytest.fixture
def local_tls_server(local_tls_certificate, request, monkeypatch):
    context, ca_pem = local_tls_certificate
    protocol_range = getattr(request, "param", None)
    connection_count = 1 if protocol_range is None else 2
    close_first = False
    if protocol_range is not None:
        minimum, maximum, close_first = protocol_range
        monkeypatch.setattr(context, "minimum_version", minimum)
        monkeypatch.setattr(context, "maximum_version", maximum)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(_LOCAL_TLS_TIMEOUT)
        listener.bind((_LOOPBACK, 0))
        listener.listen(1)
        host, port = listener.getsockname()
        assert host == _LOOPBACK
        observation = Future()

        def serve():
            try:
                seen = []
                if close_first:
                    peer, address = listener.accept()
                    with peer:
                        assert address[0] == _LOOPBACK
                    assert peer.fileno() == -1
                    seen.append(None)
                for _ in range(connection_count - len(seen)):
                    seen.append(
                        _observe_local_tls(
                            listener,
                            context,
                            include_secret_bits=protocol_range is not None,
                        )
                    )
                observation.set_result(seen[0] if protocol_range is None else seen)
            except Exception as error:  # noqa: BLE001 - Relay worker failures to pytest.
                observation.set_exception(error)

        server = Thread(target=serve, name="webguard-loopback-tls", daemon=True)
        server.start()
        try:
            yield port, ca_pem, observation
        finally:
            server.join(timeout=connection_count * _LOCAL_TLS_WAIT)
            assert not server.is_alive(), "Local TLS server did not stop"
    assert listener.fileno() == -1


def _pin_local_tls_connection(monkeypatch, hostname, port):
    create_connection = socket.create_connection
    endpoint = (_LOOPBACK, port)

    def connect(address, *, timeout):
        assert address == (hostname, port)
        peer = create_connection(endpoint, timeout=timeout)
        if peer.getpeername() != endpoint:
            peer.close()
            pytest.fail("TLS test connected to an unexpected peer")
        return peer

    monkeypatch.setattr(socket, "create_connection", connect)


@pytest.mark.parametrize(
    ("hostname", "trust_test_ca", "expected_status"),
    [
        pytest.param("localhost", True, "ok", id="trusted-matching-hostname"),
        pytest.param(
            "localhost", False, "certificate_verification_failed", id="untrusted-ca"
        ),
        pytest.param(
            _LOOPBACK,
            True,
            "certificate_verification_failed",
            id="trusted-mismatched-hostname",
        ),
    ],
)
def test_local_tls_integration(
    hostname,
    trust_test_ca,
    expected_status,
    local_tls_server,
    monkeypatch,
    record_property,
):
    port, ca_pem, server_observation = local_tls_server
    _pin_local_tls_connection(monkeypatch, hostname, port)

    client_sockets = []
    client_peers = []

    class ObservedClientSocket(ssl.SSLSocket):
        def __enter__(self):
            client_sockets.append(self)
            client_peers.append(self.getpeername())
            return super().__enter__()

    context = tls._create_verified_client_context()
    if trust_test_ca:
        context.load_verify_locations(cadata=ca_pem)
    context.sslsocket_class = ObservedClientSocket
    monkeypatch.setattr(tls, "_create_verified_client_context", lambda: context)

    result = tls.audit_tls_connectivity(hostname, port, timeout=_LOCAL_TLS_TIMEOUT)
    assert result["status"] == expected_status, result
    server = server_observation.result(timeout=_LOCAL_TLS_WAIT)
    assert (result["hostname"], result["port"]) == (hostname, port)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert client_peers == [(_LOOPBACK, port)]
    assert len(client_sockets) == 1 and client_sockets[0].fileno() == -1
    if expected_status == "ok":
        assert isinstance(server, tuple), server
        version, cipher, eof = server
        assert result["failed_stage"] is None
        assert (result["tls_version"], result["cipher_suite"]) == (version, cipher)
        assert eof == b""
        record_property("tls_version", version)
        record_property("cipher_suite", cipher)
    else:
        assert isinstance(server, OSError)
        assert result["failed_stage"] == "handshake"
        assert result["verify_code"] is not None and result["error_message"]
        assert result["tls_version"] is result["cipher_suite"] is None
        record_property("verify_code", result["verify_code"])
        record_property("verify_message", result["error_message"])


@pytest.fixture
def fixed_leaf_der():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    expires = datetime.fromisoformat("2032-06-01T00:00:00+00:00")
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        )
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture CA")]))
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(expires - timedelta(days=90))
        .not_valid_after(expires)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.test"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return leaf.public_bytes(serialization.Encoding.DER), expires


@pytest.mark.parametrize(
    ("remaining", "warning_days", "expiration_status"),
    [
        (timedelta(days=30, microseconds=1), 30, "current"),
        (timedelta(days=30), 30, "expiring_soon"),
        (timedelta(0), 30, "expired"),
        (timedelta(seconds=-1), 30, "expired"),
        (timedelta(microseconds=1), 0, "current"),
        pytest.param(
            timedelta(days=31), 10**400, "expiring_soon", id="large-threshold"
        ),
    ],
)
def test_certificate_metadata_from_verified_socket(
    fixed_leaf_der, validation_network_mocks, remaining, warning_days, expiration_status
):
    from cryptography import x509

    der, expires = fixed_leaf_der
    _, _, connect, wrap, handshake = validation_network_mocks
    sock = wrap.return_value
    parse_der = x509.load_der_x509_certificate

    def capture(*, binary_form):
        assert binary_form is True
        handshake.assert_called_once()
        sock.__exit__.assert_not_called()
        return der

    def parse(data):
        sock.__exit__.assert_called_once()
        return parse_der(data)

    sock.getpeercert.side_effect = capture
    with (
        patch.object(tls, "datetime", create=True) as clock,
        patch.object(x509, "load_der_x509_certificate", side_effect=parse),
    ):
        clock.now.return_value = expires - remaining
        result = tls.audit_tls_certificate("example.test", warning_days=warning_days)

    connect.assert_called_once_with(("example.test", 443), timeout=5.0)
    sock.getpeercert.assert_called_once_with(binary_form=True)
    assert result["connectivity"]["status"] == "ok"
    assert result["certificate_status"] == "ok"
    assert result["certificate_error"] is None
    assert result["certificate"] == {
        "subject": "CN=example.test",
        "issuer": "CN=Fixture CA",
        "serial_number": "1234",
        "sans": [
            {"type": "dns", "value": "example.test"},
            {"type": "ip", "value": "127.0.0.1"},
        ],
        "not_valid_before": "2032-03-03T00:00:00+00:00",
        "not_valid_after": "2032-06-01T00:00:00+00:00",
        "remaining_seconds": remaining.total_seconds(),
        "expiration_status": expiration_status,
        "sha256_fingerprint": sha256(der).hexdigest(),
    }
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("warning_days", [True, -1, 1.5, "30"])
def test_invalid_certificate_warning_threshold(warning_days, validation_network_mocks):
    result = tls.audit_tls_certificate("example.test", warning_days=warning_days)

    assert result["certificate_status"] == "invalid_options"
    assert result["connectivity"] is result["certificate"] is None
    assert "warning_days" in result["certificate_error"]
    for operation in validation_network_mocks:
        operation.assert_not_called()


@pytest.mark.parametrize(
    "der",
    [None, b"invalid DER", OSError("read failed")],
    ids=["missing", "malformed", "read-error"],
)
def test_certificate_metadata_error_keeps_connectivity(der, validation_network_mocks):
    _, _, connect, wrap, _ = validation_network_mocks
    if isinstance(der, OSError):
        wrap.return_value.getpeercert.side_effect = der
    else:
        wrap.return_value.getpeercert.return_value = der

    result = tls.audit_tls_certificate("example.test")

    assert result["connectivity"]["status"] == "ok"
    assert result["certificate_status"] == "metadata_error"
    assert result["certificate"] is None
    assert result["certificate_error"]
    connect.assert_called_once()


def test_certificate_is_not_read_after_verification_failure(validation_network_mocks):
    _, _, connect, wrap, handshake = validation_network_mocks
    handshake.side_effect = ssl.SSLCertVerificationError("certificate rejected")

    result = tls.audit_tls_certificate("example.test")

    assert result["connectivity"]["status"] == "certificate_verification_failed"
    assert result["certificate_status"] == "not_collected"
    assert result["certificate"] is result["certificate_error"] is None
    connect.assert_called_once()
    wrap.return_value.getpeercert.assert_not_called()


@pytest.mark.parametrize(
    ("local_tls_certificate", "hostname", "trust_ca", "warning_days", "expected"),
    [
        pytest.param(timedelta(hours=1), "localhost", True, 0, "current", id="trusted"),
        pytest.param(
            timedelta(minutes=5),
            "localhost",
            True,
            1,
            "expiring_soon",
            id="near-expiry",
        ),
        pytest.param(timedelta(minutes=-1), "localhost", True, 30, None, id="expired"),
        pytest.param(timedelta(hours=1), "localhost", False, 30, None, id="untrusted"),
        pytest.param(timedelta(hours=1), _LOOPBACK, True, 30, None, id="mismatch"),
    ],
    indirect=["local_tls_certificate"],
)
def test_local_certificate_audit(
    local_tls_server, hostname, trust_ca, warning_days, expected, monkeypatch
):
    port, ca_pem, observation = local_tls_server
    context = tls._create_verified_client_context()
    if trust_ca:
        context.load_verify_locations(cadata=ca_pem)
    monkeypatch.setattr(tls, "_create_verified_client_context", lambda: context)
    _pin_local_tls_connection(monkeypatch, hostname, port)

    result = tls.audit_tls_certificate(
        hostname, port, timeout=_LOCAL_TLS_TIMEOUT, warning_days=warning_days
    )

    server = observation.result(timeout=_LOCAL_TLS_WAIT)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    if expected is None:
        assert isinstance(server, OSError)
        assert result["connectivity"]["status"] == "certificate_verification_failed"
        assert result["certificate_status"] == "not_collected"
        assert result["certificate"] is None
    else:
        assert isinstance(server, tuple) and server[2] == b""
        assert result["connectivity"]["status"] == result["certificate_status"] == "ok"
        assert result["certificate"]["expiration_status"] == expected
        assert result["certificate"]["sans"] == [{"type": "dns", "value": "localhost"}]


def test_local_certificate_rejects_dns_hostname_mismatch(
    local_tls_server, monkeypatch, record_property
):
    hostname = "mismatch.invalid"
    port, ca_pem, observation = local_tls_server
    _pin_local_tls_connection(monkeypatch, hostname, port)
    client_sockets = []

    class ObservedClientSocket(ssl.SSLSocket):
        def __enter__(self):
            peer = self.getpeername()
            assert peer == (_LOOPBACK, port)
            assert self.server_hostname == hostname
            client_sockets.append(self)
            record_property("tcp_peer", peer)
            return super().__enter__()

    context = tls._create_verified_client_context()
    context.load_verify_locations(cadata=ca_pem)
    context.sslsocket_class = ObservedClientSocket
    monkeypatch.setattr(tls, "_create_verified_client_context", lambda: context)

    result = tls.audit_tls_certificate(hostname, port, timeout=_LOCAL_TLS_TIMEOUT)

    connectivity = result["connectivity"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert (connectivity["hostname"], connectivity["port"]) == (hostname, port)
    assert connectivity["status"] == "certificate_verification_failed"
    assert connectivity["failed_stage"] == "handshake"
    assert connectivity["verify_code"] == 62
    assert connectivity["tls_version"] is connectivity["cipher_suite"] is None
    assert result["certificate_status"] == "not_collected"
    assert result["certificate"] is result["certificate_error"] is None
    assert isinstance(observation.result(timeout=_LOCAL_TLS_WAIT), OSError)
    assert len(client_sockets) == 1 and client_sockets[0].fileno() == -1
    record_property("verify_code", connectivity["verify_code"])


@pytest.fixture
def protocol_network_mocks(monkeypatch):
    contexts = []
    handshakes = []
    client_ciphers = [{"name": "TLS_AES_128_GCM_SHA256"}]

    def create_context():
        context = MagicMock(spec=ssl.SSLContext)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.security_level = 2
        context.options = ssl.OP_NO_SSLv3
        context.get_ciphers.return_value = client_ciphers
        contexts.append(context)
        return context

    def prepare_probe(negotiated_version, *, cipher=None, error=None):
        tls_socket = MagicMock(spec=ssl.SSLSocket)
        tls_socket.__enter__.return_value = tls_socket
        tls_socket.version.return_value = negotiated_version
        tls_socket.cipher.return_value = cipher

        def handshake():
            handshakes.append(tls_socket)
            if error is not None:
                raise error

        tls_socket.do_handshake.side_effect = handshake
        return tls_socket

    tcp_socket = MagicMock(spec=socket.socket)
    tcp_socket.__enter__.return_value = tcp_socket
    resolve = MagicMock(return_value=[])
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with (
        patch.object(
            tls, "_create_verified_client_context", side_effect=create_context
        ) as factory,
        patch.object(socket, "create_connection", return_value=tcp_socket) as connect,
    ):
        yield factory, contexts, connect, handshakes, prepare_probe


def _set_protocol_context_policy(factory, *, minimum=None, disable=0):
    create_context = factory.side_effect

    def configure():
        context = create_context()
        if minimum is not None:
            context.minimum_version = minimum
        context.options |= disable
        return context

    factory.side_effect = configure


def test_protocol_audit_probes_modern_versions_in_order(protocol_network_mocks):
    factory, contexts, connect, handshakes, prepare_probe = protocol_network_mocks
    connect_calls_at_handshake = []
    sockets = [
        prepare_probe(
            "TLSv1.2", cipher=("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
        ),
        prepare_probe("TLSv1.3", cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)),
    ]
    create_context = factory.side_effect

    def configure_next_probe():
        context = create_context()
        requested = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)[len(handshakes)]
        tls_socket = sockets[len(handshakes)]

        def wrap(tcp_socket, *, server_hostname, do_handshake_on_connect):
            assert tcp_socket is connect.return_value
            assert server_hostname == "example.test"
            assert do_handshake_on_connect is False
            assert context.minimum_version == context.maximum_version == requested
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname is True
            assert context.security_level == 2
            assert context.options == ssl.OP_NO_SSLv3
            assert context.get_ciphers() == [{"name": "TLS_AES_128_GCM_SHA256"}]
            context.set_ciphers.assert_not_called()
            return tls_socket

        context.wrap_socket.side_effect = wrap
        return context

    for tls_socket in sockets:
        handshake = tls_socket.do_handshake.side_effect

        def observe_handshake(handshake=handshake):
            connect_calls_at_handshake.append(connect.call_count)
            handshake()

        tls_socket.do_handshake.side_effect = observe_handshake
    factory.side_effect = configure_next_probe

    result = tls.audit_tls_protocols("example.test", 8443, timeout=2)

    assert result["status"] == "ok"
    assert [
        (probe["requested_version"], probe["outcome"]) for probe in result["probes"]
    ] == [
        ("TLSv1.2", "confirmed_supported"),
        ("TLSv1.3", "confirmed_supported"),
    ]
    assert factory.call_count == 2 and contexts[0] is not contexts[1]
    assert handshakes == sockets
    assert connect_calls_at_handshake == [1, 2]
    assert connect.call_count == 2
    for call in connect.call_args_list:
        assert call.args == (("example.test", 8443),)
        assert call.kwargs["timeout"] == 2
    for tls_socket in sockets:
        tls_socket.settimeout.assert_called_with(2)
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize(
    ("minimum", "disable", "runtime_versions"),
    [
        pytest.param(ssl.TLSVersion.TLSv1_2, 0, True, id="existing-minimum"),
        pytest.param(
            ssl.TLSVersion.TLSv1,
            ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,
            True,
            id="version-disable-flags",
        ),
        pytest.param(ssl.TLSVersion.TLSv1, 0, False, id="missing-build-support"),
    ],
)
def test_protocol_audit_legacy_opt_in_preserves_client_policy(
    protocol_network_mocks, monkeypatch, minimum, disable, runtime_versions
):
    factory, contexts, connect, handshakes, prepare_probe = protocol_network_mocks
    monkeypatch.setattr(ssl, "HAS_TLSv1", runtime_versions)
    monkeypatch.setattr(ssl, "HAS_TLSv1_1", runtime_versions)
    _set_protocol_context_policy(factory, minimum=minimum, disable=disable)
    create_context = factory.side_effect
    sockets = [prepare_probe("TLSv1.2"), prepare_probe("TLSv1.3")]

    def configure():
        context = create_context()
        context.wrap_socket.side_effect = lambda *args, **kwargs: sockets[
            len(handshakes)
        ]
        return context

    factory.side_effect = configure
    result = tls.audit_tls_protocols("example.test", probe_legacy=True)

    assert {
        probe["requested_version"]: probe["outcome"] for probe in result["probes"]
    } == {
        "TLSv1": "client_restricted",
        "TLSv1.1": "client_restricted",
        "TLSv1.2": "confirmed_supported",
        "TLSv1.3": "confirmed_supported",
    }
    assert len(result["probes"]) == 4
    assert connect.call_count == 2
    assert handshakes == sockets
    assert result["recommendations"] == []
    for context in contexts:
        assert context.minimum_version >= minimum
        assert context.options == ssl.OP_NO_SSLv3 | disable
        assert context.security_level == 2
        context.set_ciphers.assert_not_called()


def _ssl_error_with_reason(reason):
    error = ssl.SSLError(reason)
    error.reason = reason
    return error


@pytest.mark.parametrize(
    ("error", "actual_version", "outcome", "recommendations"),
    [
        pytest.param(None, "TLSv1.2", "inconclusive", [], id="version-mismatch"),
        pytest.param(
            _ssl_error_with_reason("TLSV1_ALERT_PROTOCOL_VERSION"),
            None,
            "server_rejected",
            ["review_tls_1_3"],
            id="explicit-peer-version-alert",
        ),
        pytest.param(
            _ssl_error_with_reason("NO_CIPHERS_AVAILABLE"),
            None,
            "client_restricted",
            [],
            id="local-cipher-policy",
        ),
        pytest.param(
            ssl.SSLCertVerificationError("untrusted peer"),
            None,
            "inconclusive",
            [],
            id="certificate-verification",
        ),
        pytest.param(TimeoutError("timed out"), None, "inconclusive", [], id="timeout"),
        pytest.param(
            ConnectionResetError("peer reset"),
            None,
            "inconclusive",
            [],
            id="reset",
        ),
        pytest.param(
            _ssl_error_with_reason("SSLV3_ALERT_HANDSHAKE_FAILURE"),
            None,
            "inconclusive",
            [],
            id="ambiguous-peer-alert",
        ),
        pytest.param(
            _ssl_error_with_reason("UNSUPPORTED_PROTOCOL"),
            None,
            "inconclusive",
            [],
            id="ambiguous-unsupported-protocol",
        ),
    ],
)
def test_protocol_audit_classifies_tls13_evidence(
    protocol_network_mocks, error, actual_version, outcome, recommendations
):
    factory, _, _, handshakes, prepare_probe = protocol_network_mocks
    create_context = factory.side_effect
    sockets = [prepare_probe("TLSv1.2"), prepare_probe(actual_version, error=error)]

    def configure():
        context = create_context()
        context.wrap_socket.return_value = sockets[len(handshakes)]
        return context

    factory.side_effect = configure
    result = tls.audit_tls_protocols("example.test")

    tls12, tls13 = result["probes"]
    assert tls12["outcome"] == "confirmed_supported"
    assert tls13["requested_version"] == "TLSv1.3"
    assert tls13["outcome"] == outcome
    assert tls13["negotiated_version"] == actual_version
    assert tls13["evidence_code"]
    assert [item["code"] for item in result["recommendations"]] == recommendations
    if error is not None:
        sockets[1].version.assert_not_called()
        sockets[1].cipher.assert_not_called()


@pytest.mark.parametrize(
    ("cipher", "name", "bits"),
    [
        pytest.param(
            ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 40),
            "TLS_AES_128_GCM_SHA256",
            40,
            id="only-observed-suite-and-bits",
        ),
        pytest.param(
            ("TLS_AES_128_GCM_SHA256", "TLSv1.3", None),
            "TLS_AES_128_GCM_SHA256",
            None,
            id="missing-bits",
        ),
        pytest.param(None, None, None, id="missing-cipher-tuple"),
    ],
)
def test_protocol_audit_reports_only_observed_cipher_evidence(
    protocol_network_mocks, cipher, name, bits
):
    factory, _, _, handshakes, prepare_probe = protocol_network_mocks
    create_context = factory.side_effect
    sockets = [prepare_probe("TLSv1.2"), prepare_probe("TLSv1.3", cipher=cipher)]

    def configure():
        context = create_context()
        context.wrap_socket.return_value = sockets[len(handshakes)]
        return context

    factory.side_effect = configure
    result = tls.audit_tls_protocols("example.test")

    probe = result["probes"][1]
    assert probe["outcome"] == "confirmed_supported"
    assert probe["negotiated_version"] == "TLSv1.3"
    assert probe["cipher_suite"] == name
    assert probe["secret_bits"] == bits
    assert "supported_ciphers" not in probe and "supported_ciphers" not in result
    assert result["recommendations"] == []
    json.dumps(result, allow_nan=False)


def test_protocol_audit_recommends_disabling_confirmed_legacy_tls(
    protocol_network_mocks, monkeypatch
):
    factory, _, connect, handshakes, prepare_probe = protocol_network_mocks
    monkeypatch.setattr(ssl, "HAS_TLSv1", True)
    monkeypatch.setattr(ssl, "HAS_TLSv1_1", True)
    _set_protocol_context_policy(factory, minimum=ssl.TLSVersion.TLSv1)
    create_context = factory.side_effect
    sockets = {
        ssl.TLSVersion.TLSv1: prepare_probe("TLSv1"),
        ssl.TLSVersion.TLSv1_1: prepare_probe("TLSv1.1"),
        ssl.TLSVersion.TLSv1_2: prepare_probe("TLSv1.2"),
        ssl.TLSVersion.TLSv1_3: prepare_probe("TLSv1.3"),
    }

    def configure():
        context = create_context()
        context.wrap_socket.side_effect = lambda *args, **kwargs: sockets[
            context.minimum_version
        ]
        return context

    factory.side_effect = configure
    result = tls.audit_tls_protocols("example.test", probe_legacy=True)

    assert len(result["probes"]) == connect.call_count == 4
    assert len(handshakes) == 4
    assert {probe["requested_version"] for probe in result["probes"]} == {
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3",
    }
    assert all(probe["outcome"] == "confirmed_supported" for probe in result["probes"])
    assert "disable_legacy_tls" in {item["code"] for item in result["recommendations"]}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("hostname", "https://example.test", id="hostname-url"),
        pytest.param("hostname", "xn--0.test", id="malformed-a-label"),
        pytest.param("port", True, id="boolean-port"),
        pytest.param("port", 65536, id="out-of-range-port"),
        pytest.param("timeout", float("nan"), id="nonfinite-timeout"),
        pytest.param("timeout", 0, id="zero-timeout"),
        pytest.param("probe_legacy", 1, id="integer-opt-in"),
        pytest.param("probe_legacy", "false", id="string-opt-in"),
        pytest.param("probe_legacy", None, id="null-opt-in"),
    ],
)
def test_protocol_audit_validates_input_before_network_activity(
    field, value, validation_network_mocks
):
    options = {
        "hostname": "example.test",
        "port": 443,
        "timeout": 3,
        "probe_legacy": False,
    }
    options[field] = value

    result = tls.audit_tls_protocols(**options)

    assert result["status"] == "invalid_input"
    assert result["probes"] == []
    assert result["recommendations"] == []
    for network_operation in validation_network_mocks:
        network_operation.assert_not_called()
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize(
    ("options", "expected_port"),
    [
        pytest.param({"port": 1 << 15000}, None, id="oversized-port"),
        pytest.param({"port": True}, None, id="boolean-port"),
        pytest.param({"port": 0}, None, id="zero-port"),
        pytest.param({"port": -1}, None, id="negative-port"),
        pytest.param({"port": 65536}, None, id="out-of-range-port"),
        pytest.param({"port": float("nan")}, None, id="nonfinite-port"),
        pytest.param({"hostname": object()}, 443, id="nonserializable-hostname"),
        pytest.param({"timeout": float("inf")}, 443, id="infinite-timeout"),
        pytest.param({"probe_legacy": object()}, 443, id="nonserializable-option"),
    ],
)
def test_protocol_audit_rejected_input_is_strict_json(
    options, expected_port, validation_network_mocks
):
    result = tls.audit_tls_protocols(**({"hostname": "example.test"} | options))

    assert result["status"] == "invalid_input"
    assert result["probes"] == []
    assert result["recommendations"] == []
    for network_operation in validation_network_mocks:
        network_operation.assert_not_called()
    decoded = json.loads(json.dumps(result, allow_nan=False))
    assert decoded["target"]["port"] == expected_port


_TLS12 = ssl.TLSVersion.TLSv1_2
_TLS13 = ssl.TLSVersion.TLSv1_3
_BOTH_MODERN_VERSIONS = (_TLS12, _TLS13, False)


@pytest.mark.skipif(
    not (ssl.HAS_TLSv1_2 and ssl.HAS_TLSv1_3),
    reason="Both TLS 1.2 and TLS 1.3 are required for the loopback probe tests",
)
@pytest.mark.parametrize(
    ("local_tls_server", "hostname", "trust_ca", "expected", "recommendations"),
    [
        pytest.param(
            (_TLS12, _TLS12, False),
            "localhost",
            True,
            ("confirmed_supported", "server_rejected"),
            ["review_tls_1_3"],
            id="tls12-only",
        ),
        pytest.param(
            (_TLS13, _TLS13, False),
            "localhost",
            True,
            ("server_rejected", "confirmed_supported"),
            [],
            id="tls13-only",
        ),
        pytest.param(
            _BOTH_MODERN_VERSIONS,
            "localhost",
            True,
            ("confirmed_supported", "confirmed_supported"),
            [],
            id="both-versions",
        ),
        pytest.param(
            (_TLS12, _TLS13, True),
            "localhost",
            True,
            ("inconclusive", "confirmed_supported"),
            [],
            id="tcp-close-before-tls",
        ),
        pytest.param(
            _BOTH_MODERN_VERSIONS,
            "localhost",
            False,
            ("inconclusive", "inconclusive"),
            [],
            id="untrusted-ca",
        ),
        pytest.param(
            _BOTH_MODERN_VERSIONS,
            _LOOPBACK,
            True,
            ("inconclusive", "inconclusive"),
            [],
            id="trusted-ip-mismatch",
        ),
    ],
    indirect=["local_tls_server"],
)
def test_local_tls_protocol_integration(
    local_tls_server,
    hostname,
    trust_ca,
    expected,
    recommendations,
    monkeypatch,
    record_property,
):
    port, ca_pem, server_observation = local_tls_server
    _pin_local_tls_connection(monkeypatch, hostname, port)

    tcp_sockets = []
    client_sockets = []
    client_contexts = []
    create_connection = socket.create_connection
    create_verified_context = tls._create_verified_client_context

    class ObservedClientSocket(ssl.SSLSocket):
        def __enter__(self):
            assert self.getpeername() == (_LOOPBACK, port)
            client_sockets.append(self)
            return super().__enter__()

        def do_handshake(self, *args, **kwargs):
            assert self.gettimeout() == _LOCAL_TLS_TIMEOUT
            return super().do_handshake(*args, **kwargs)

    def create_client_context():
        context = create_verified_context()
        if trust_ca:
            context.load_verify_locations(cadata=ca_pem)
        context.sslsocket_class = ObservedClientSocket
        client_contexts.append(
            (context, context.security_level, context.options, context.get_ciphers())
        )
        return context

    def connect(address, *, timeout):
        assert address == (hostname, port) and timeout == _LOCAL_TLS_TIMEOUT
        peer = create_connection(address, timeout=timeout)
        tcp_sockets.append(peer)
        return peer

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(tls, "_create_verified_client_context", create_client_context)
    result = tls.audit_tls_protocols(hostname, port, timeout=_LOCAL_TLS_TIMEOUT)
    record_property("protocol_result", json.dumps(result, allow_nan=False))
    server = server_observation.result(timeout=2 * _LOCAL_TLS_WAIT)

    assert result["status"] == "ok"
    assert result["not_probed"] == ["TLSv1", "TLSv1.1"]
    assert [item["code"] for item in result["recommendations"]] == recommendations
    probes = result["probes"]
    assert [probe["requested_version"] for probe in probes] == ["TLSv1.2", "TLSv1.3"]
    assert len(tcp_sockets) == len(client_sockets) == len(client_contexts) == 2
    assert client_contexts[0][0] is not client_contexts[1][0]
    for (context, level, options, ciphers), version in zip(
        client_contexts, (_TLS12, _TLS13), strict=True
    ):
        assert context.minimum_version == context.maximum_version == version
        assert (
            context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        )
        assert (context.security_level, context.options, context.get_ciphers()) == (
            level,
            options,
            ciphers,
        )
    assert all(peer.fileno() == -1 for peer in tcp_sockets + client_sockets)

    for probe, observed, outcome in zip(probes, server, expected, strict=True):
        assert probe["outcome"] == outcome, (probe, observed)
        if outcome == "confirmed_supported":
            version, cipher, eof, bits = observed
            assert version == probe["requested_version"] == probe["negotiated_version"]
            assert cipher == probe["cipher_suite"]
            assert bits == probe["secret_bits"] and bits > 0
            assert eof == b""
            assert probe["failed_stage"] is probe["verify_code"] is None
            continue

        assert (
            probe["negotiated_version"]
            is probe["cipher_suite"]
            is probe["secret_bits"]
            is None
        )
        assert probe["failed_stage"] == "handshake" and probe["error_message"]
        if outcome == "server_rejected":
            assert isinstance(observed, OSError)
            assert probe["evidence_code"] == "TLSV1_ALERT_PROTOCOL_VERSION"
            assert probe["verify_code"] is None
        elif observed is None:
            assert probe["evidence_code"] in {
                "UNEXPECTED_EOF_WHILE_READING",
                "tls_handshake_error",
                "connection_error",
            }
            assert probe["verify_code"] is None
        else:
            assert isinstance(observed, OSError)
            assert probe["evidence_code"] == "certificate_verification_failed"
            assert probe["verify_code"] is not None


_SHARED_INVALID_SOURCE_HOSTNAMES = (
    pytest.param("192.0x.2.1", id="bare-hex-middle"),
    pytest.param("192.0X.2.1.", id="uppercase-bare-hex-root-dot"),
    pytest.param("0x.0.2.1", id="bare-hex-first"),
    pytest.param("192.0.2.0x", id="bare-hex-last"),
    pytest.param("0X", id="bare-hex-single"),
    pytest.param("xn--a.test", id="decoded-control"),
    pytest.param("XN--A.TeSt.", id="uppercase-decoded-control-root-dot"),
)


@pytest.mark.parametrize("hostname", _SHARED_INVALID_SOURCE_HOSTNAMES)
@pytest.mark.parametrize(
    "audit",
    [tls.audit_tls_connectivity, tls.audit_tls_certificate, tls.audit_tls_protocols],
    ids=["connectivity", "certificate", "protocols"],
)
def test_shared_source_validation_rejects_invalid_tls_hostnames(
    audit, hostname, validation_network_mocks
):
    create_context, _, connect, _, _ = validation_network_mocks
    context = create_context.return_value
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    context.options = 0
    connect.side_effect = ConnectionRefusedError(
        "Unexpected connection after validation"
    )

    result = audit(hostname, port=443)

    if audit is tls.audit_tls_certificate:
        assert result["certificate_status"] == "not_collected"
        assert result["certificate"] is result["certificate_error"] is None
        result = result["connectivity"]
    assert result["status"] == "invalid_input", (result, connect.call_args_list)
    if audit is tls.audit_tls_protocols:
        assert result["target"] == {"hostname": hostname, "port": 443}
        assert (
            result["probes"] == result["not_probed"] == result["recommendations"] == []
        )
    else:
        assert result["hostname"] == hostname and result["port"] == 443
        assert result["failed_stage"] == "validation"
        assert (
            result["tls_version"]
            is result["cipher_suite"]
            is result["verify_code"]
            is None
        )
    assert "hostname" in result["error_message"].casefold()
    for operation in validation_network_mocks:
        operation.assert_not_called()


@pytest.mark.parametrize(
    ("hostname", "identity"),
    [
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("example.test", "example.test"),
        ("lab.0X.TeSt.", "lab.0X.TeSt"),
        ("ExAmPle.TeSt.", "ExAmPle.TeSt"),
        ("xn--bcher-kva.test", "xn--bcher-kva.test"),
        ("XN--FA-HIA.test.", "XN--FA-HIA.test"),
    ],
)
def test_shared_source_validation_preserves_valid_lookup_and_identity(
    hostname, identity
):
    assert tls._validate_endpoint(hostname, 443, 2.0) == (hostname, identity)


# Run with a private environment so the configured destination never affects pytest.
_KEYLOG_CHILD = r"""
import ctypes
from ctypes import wintypes
from hashlib import sha256
import json
import os
import socket
import ssl
import sys
from unittest.mock import patch

from webguard.auditors import https, tls

kind, hostname, port, lock_flag = sys.argv[1:]
port = int(port)
destination = os.environ.get("SSLKEYLOGFILE")
contexts = []
armed_before_wrap = []
original_new = ssl.SSLContext.__new__
original_wrap = ssl.SSLContext.wrap_socket
connect = socket.create_connection
loopback = port != 0

def guard(event, args):
    if not event.startswith("socket."):
        return
    if not loopback:
        raise AssertionError("Offline key-log check attempted networking")
    if event in {"socket.connect", "socket.bind", "socket.sendto"}:
        assert args[1][0] == "127.0.0.1"
    elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
        assert args[0] == "127.0.0.1"

def new_context(cls, protocol):
    context = original_new(cls, protocol)
    contexts.append(context)
    return context

def guarded_wrap(context, *args, **kwargs):
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    armed = context.keylog_filename is not None
    armed_before_wrap.append(armed)
    assert not armed, "Client context enabled TLS key logging before handshake"
    return original_wrap(context, *args, **kwargs)

def open_connection(address, *args, **kwargs):
    if not loopback:
        raise ConnectionRefusedError("offline test")
    assert address == (hostname, port)
    return connect(("127.0.0.1", port), *args, **kwargs)

def profile(context):
    attrs = (
        "verify_mode", "check_hostname", "hostname_checks_common_name", "verify_flags",
        "minimum_version", "maximum_version", "options", "security_level",
    )
    return {
        **{attr: getattr(context, attr) for attr in attrs},
        "ciphers": context.get_ciphers(),
        "ca_fingerprints": sorted(
            sha256(cert).hexdigest() for cert in context.get_ca_certs(binary_form=True)
        ),
    }

def audit():
    if kind == "stock":
        return profile(ssl.create_default_context())
    if kind == "connectivity":
        return tls.audit_tls_connectivity(hostname, port or 443)
    if kind == "certificate":
        return tls.audit_tls_certificate(hostname, port or 443)["connectivity"]
    if kind == "protocols":
        return tls.audit_tls_protocols(hostname, port or 443)
    if kind == "https":
        return https.audit_https_availability(hostname, port or 443)
    return https.audit_http_redirect(
        hostname, port or None, source_scheme="http" if kind == "plaintext" else "https"
    )["probe"]

handle = None
if lock_flag == "lock":
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Share mode zero denies other handles read and write access.
    handle = kernel.CreateFileW(destination, 0x80000000, 0, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

sys.addaudithook(guard)
error = None
result = None
try:
    with (
        patch.object(ssl.SSLContext, "__new__", staticmethod(new_context)),
        patch.object(ssl.SSLContext, "wrap_socket", guarded_wrap),
        patch.object(socket, "create_connection", open_connection),
    ):
        result = audit()
except OSError as exc:
    error = type(exc).__name__
finally:
    if handle is not None:
        assert kernel.CloseHandle(handle)

if kind != "stock" and result is not None and not loopback:
    result = None

print(json.dumps({
    "error": error,
    "result": result,
    "count": len(contexts),
    "distinct": len({id(context) for context in contexts}),
    "profiles": [profile(context) for context in contexts],
    "attached": [context.keylog_filename is not None for context in contexts],
    "armed_before_wrap": armed_before_wrap,
    "environment_unchanged": os.environ.get("SSLKEYLOGFILE") == destination,
}))
"""


@pytest.fixture
def keylog_sandbox():
    parent_setting = os.environ.get("SSLKEYLOGFILE")
    with TemporaryDirectory() as directory:
        yield Path(directory)
    assert not Path(directory).exists()
    assert os.environ.get("SSLKEYLOGFILE") == parent_setting


def run_keylog_child(
    kind, destination, *, hostname="example.test", port=0, ca_file=None, locked=False
):
    env = os.environ.copy()
    env.pop("SSLKEYLOGFILE", None)
    if destination is not None:
        env["SSLKEYLOGFILE"] = str(destination)
    if port:
        env.pop("SSL_CERT_FILE", None)
        env.pop("SSL_CERT_DIR", None)
    if ca_file is not None:
        env["SSL_CERT_FILE"] = str(ca_file)

    child = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            _KEYLOG_CHILD,
            kind,
            hostname,
            str(port),
            "lock" if locked else "unlocked",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    observed = json.loads(child.stdout)
    assert observed["environment_unchanged"]
    return observed


@pytest.mark.parametrize(
    "kind", ["connectivity", "certificate", "protocols", "https", "redirect"]
)
@pytest.mark.parametrize("existing", [False, True], ids=["absent", "sentinel"])
def test_keylog_red_public_audit_leaves_destination_untouched(
    keylog_sandbox, kind, existing
):
    destination = keylog_sandbox / "keylog"
    sentinel = b"WebGuard sentinel\n"
    if existing:
        destination.write_bytes(sentinel)
        before = destination.stat().st_mtime_ns

    observed = run_keylog_child(kind, destination)

    assert observed["error"] is None
    assert observed["count"] >= 1
    if existing:
        unchanged = destination.read_bytes() == sentinel
        assert unchanged, "Context creation changed the sentinel"
        assert destination.stat().st_mtime_ns == before
    else:
        assert not destination.exists(), "Context creation created the destination"
    assert not any(observed["attached"])


@pytest.mark.skipif(
    sys.platform != "win32", reason="Uses Windows exclusive file sharing"
)
def test_keylog_red_exclusively_locked_sentinel_does_not_block_context(keylog_sandbox):
    destination = keylog_sandbox / "locked-keylog"
    sentinel = b"WebGuard locked sentinel\n"
    destination.write_bytes(sentinel)

    observed = run_keylog_child("connectivity", destination, locked=True)

    unchanged = destination.read_bytes() == sentinel
    assert unchanged
    assert observed["error"] is None, (
        "Context creation attempted to open the locked sentinel"
    )
    assert observed["count"] == 1
    assert observed["profiles"][0]["verify_mode"] == ssl.CERT_REQUIRED
    assert observed["profiles"][0]["check_hostname"]
    assert observed["attached"] == [False]


@pytest.mark.skipif(
    not (ssl.HAS_TLSv1_2 and ssl.HAS_TLSv1_3), reason="Requires both modern TLS probes"
)
def test_keylog_red_protocol_probes_get_distinct_contexts():
    observed = run_keylog_child("protocols", None)

    assert observed["error"] is None
    assert observed["count"] == observed["distinct"] == 2
    assert observed["attached"] == [False, False]


def test_keylog_red_plaintext_redirect_never_creates_tls_context(keylog_sandbox):
    destination = keylog_sandbox / "plaintext-keylog"

    observed = run_keylog_child("plaintext", destination)

    assert observed["error"] is None
    assert observed["count"] == 0
    assert not destination.exists()


def test_keylog_red_verified_context_matches_stock_runtime_policy(keylog_sandbox):
    stock = run_keylog_child("stock", None)["result"]
    observed = run_keylog_child("connectivity", keylog_sandbox / "parity-keylog")

    assert observed["error"] is None
    assert stock["verify_mode"] == ssl.CERT_REQUIRED
    assert stock["check_hostname"]
    assert stock["ca_fingerprints"]
    assert observed["profiles"] == [stock]


@pytest.mark.skipif(
    not (ssl.HAS_TLSv1_2 and ssl.HAS_TLSv1_3), reason="Requires both modern TLS probes"
)
@pytest.mark.parametrize("local_tls_server", [(_TLS12, _TLS12, False)], indirect=True)
def test_keylog_red_loopback_protocols_preserve_version_restriction(
    local_tls_server, keylog_sandbox
):
    port, ca_pem, server_observation = local_tls_server
    ca_file = keylog_sandbox / "ca.pem"
    ca_file.write_text(ca_pem, encoding="ascii")
    destination = keylog_sandbox / "protocol-keylog"

    observed = run_keylog_child(
        "protocols", destination, hostname="localhost", port=port, ca_file=ca_file
    )

    assert observed["error"] is None
    assert [probe["outcome"] for probe in observed["result"]["probes"]] == [
        "confirmed_supported",
        "server_rejected",
    ]
    assert observed["result"]["probes"][0]["negotiated_version"] == "TLSv1.2"
    assert observed["count"] == observed["distinct"] == 2
    server_observation.result(timeout=_LOCAL_TLS_WAIT)
    assert not destination.exists(), (
        "Protocol contexts touched the destination before handshake"
    )
    assert observed["armed_before_wrap"] == [False, False]


_SETUP_DIAGNOSTIC = "Could not initialize the local TLS client context."
_SETUP_MARKER = r"C:\synthetic\private-path password=setup-test-marker"
_SETUP_ERRORS = (
    OSError,
    PermissionError,
    ssl.SSLError,
    ssl.SSLCertVerificationError,
    TimeoutError,
)
_SETUP_UNEXPECTED = (ValueError, TypeError, RuntimeError, KeyboardInterrupt)


def setup_failure(error_type):
    error = error_type(_SETUP_MARKER)
    if isinstance(error, ssl.SSLCertVerificationError):
        error.verify_code = 62
    return error


@pytest.fixture
def setup_failure_io(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail(
            "Failed context setup attempted networking or created a fallback context"
        )

    for name in ("getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, blocked)
    for name in ("connect", "connect_ex", "send", "sendall"):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(ssl, "create_default_context", blocked)
    monkeypatch.setattr(ssl.SSLContext, "__new__", staticmethod(blocked))
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", blocked)


_TLS_SETUP_AUDITORS = [
    pytest.param("connectivity", tls.audit_tls_connectivity, id="connectivity"),
    pytest.param("certificate", tls.audit_tls_certificate, id="certificate"),
    pytest.param("protocols", tls.audit_tls_protocols, id="protocols"),
]


def assert_setup_failure_probe(probe, version):
    assert probe == {
        "requested_version": version,
        "outcome": "inconclusive",
        "evidence_code": "tls_setup_error",
        "negotiated_version": None,
        "cipher_suite": None,
        "secret_bits": None,
        "failed_stage": "tls_setup",
        "error_message": _SETUP_DIAGNOSTIC,
        "verify_code": None,
    }


@pytest.mark.parametrize(("kind", "audit"), _TLS_SETUP_AUDITORS)
@pytest.mark.parametrize("error_type", _SETUP_ERRORS)
def test_context_setup_red_tls_returns_local_failure(
    setup_failure_io, monkeypatch, kind, audit, error_type
):
    monkeypatch.setattr(ssl, "HAS_TLSv1_2", True)
    monkeypatch.setattr(ssl, "HAS_TLSv1_3", True)
    factory = MagicMock(side_effect=setup_failure(error_type))
    monkeypatch.setattr(tls, "_create_verified_client_context", factory)

    result = audit("example.test")

    assert "setup-test-marker" not in json.dumps(result, allow_nan=False)
    if kind == "protocols":
        assert factory.call_count == 2
        assert result["status"] == "ok"
        assert result["error_message"] is None
        assert result["recommendations"] == []
        assert len(result["probes"]) == 2
        for probe, version in zip(
            result["probes"], ("TLSv1.2", "TLSv1.3"), strict=True
        ):
            assert_setup_failure_probe(probe, version)
    else:
        factory.assert_called_once_with()
        if kind == "certificate":
            assert result["certificate_status"] == "not_collected"
            assert result["certificate"] is result["certificate_error"] is None
            result = result["connectivity"]
        assert result["status"] == "tls_setup_error"
        assert result["failed_stage"] == "tls_setup"
        assert result["error_message"] == _SETUP_DIAGNOSTIC
        assert (
            result["tls_version"]
            is result["cipher_suite"]
            is result["verify_code"]
            is None
        )


@pytest.mark.parametrize(("kind", "audit"), _TLS_SETUP_AUDITORS)
@pytest.mark.parametrize("error_type", _SETUP_UNEXPECTED)
def test_context_setup_red_tls_propagates_unexpected_failures(
    setup_failure_io, monkeypatch, kind, audit, error_type
):
    monkeypatch.setattr(ssl, "HAS_TLSv1_2", True)
    error = setup_failure(error_type)
    factory = MagicMock(side_effect=error)
    monkeypatch.setattr(tls, "_create_verified_client_context", factory)

    with pytest.raises(error_type) as raised:
        audit("example.test")
    assert raised.value is error
    factory.assert_called_once_with()


@pytest.mark.parametrize("failed_index", [0, 1], ids=["first-fails", "second-fails"])
def test_context_setup_red_protocol_keeps_independent_success(
    protocol_network_mocks, monkeypatch, failed_index
):
    monkeypatch.setattr(ssl, "HAS_TLSv1_2", True)
    monkeypatch.setattr(ssl, "HAS_TLSv1_3", True)
    factory, contexts, connect, handshakes, prepare_probe = protocol_network_mocks
    create_context = factory.side_effect
    tcp_socket = connect.return_value
    success_index = 1 - failed_index
    versions = ("TLSv1.2", "TLSv1.3")
    cipher = (
        ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
        if success_index == 0
        else ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    )
    verified_socket = prepare_probe(versions[success_index], cipher=cipher)

    def make_context():
        if factory.call_count == failed_index + 1:
            raise setup_failure(PermissionError)
        context = create_context()
        context.wrap_socket.return_value = verified_socket
        return context

    def connect_successful_probe(*args, **kwargs):
        assert factory.call_count == success_index + 1
        return tcp_socket

    factory.side_effect = make_context
    connect.side_effect = connect_successful_probe

    result = tls.audit_tls_protocols("example.test")

    assert factory.call_count == 2
    assert len(contexts) == 1
    assert connect.call_count == 1
    assert handshakes == [verified_socket]
    assert result["status"] == "ok"
    assert result["recommendations"] == []
    assert_setup_failure_probe(result["probes"][failed_index], versions[failed_index])
    success = result["probes"][success_index]
    assert success["outcome"] == "confirmed_supported"
    assert success["evidence_code"] == "verified_handshake"
    assert success["negotiated_version"] == versions[success_index]
    assert success["cipher_suite"] == cipher[0]
    assert success["secret_bits"] == 128


@pytest.mark.parametrize(
    ("version_fault", "cipher_fault", "diagnostics"),
    [
        (True, False, {"tls_version_unavailable"}),
        (False, True, {"cipher_metadata_unavailable"}),
        (True, True, {"tls_version_unavailable", "cipher_metadata_unavailable"}),
    ],
    ids=["version", "cipher", "both"],
)
def test_secondary_failure_red_certificate_still_reads_der(
    fixed_leaf_der, validation_network_mocks, version_fault, cipher_fault, diagnostics
):
    _, resolve, _, wrap, handshake = validation_network_mocks
    peer = wrap.return_value
    der, _ = fixed_leaf_der
    peer.getpeercert.return_value = der
    if version_fault:
        peer.version.side_effect = OSError("synthetic private version path")
    if cipher_fault:
        peer.cipher.side_effect = ssl.SSLError("synthetic private cipher path")

    result = tls.audit_tls_certificate("example.test")

    handshake.assert_called_once_with()
    peer.getpeercert.assert_called_once_with(binary_form=True)
    resolve.assert_not_called()
    assert result["certificate_status"] == "ok"
    assert result["certificate"]["sha256_fingerprint"] == sha256(der).hexdigest()
    assert result["certificate_error"] is None
    connection = result["connectivity"]
    assert (connection["status"], connection["failed_stage"]) == ("ok", None)
    assert connection["tls_version"] == (None if version_fault else "TLSv1.3")
    assert connection["cipher_suite"] == (
        None if cipher_fault else "TLS_AES_128_GCM_SHA256"
    )
    assert len(connection["diagnostics"]) == len(diagnostics)
    assert set(connection["diagnostics"]) == diagnostics
    assert "synthetic private" not in json.dumps(result, allow_nan=False)


@pytest.mark.parametrize(
    ("der", "diagnostic"),
    [
        (
            OSError("synthetic private DER path"),
            "Unable to read verified certificate DER",
        ),
        (b"invalid certificate DER", "Unable to parse verified certificate metadata"),
    ],
    ids=["read", "parse"],
)
def test_secondary_failure_red_retains_existing_der_failure(
    validation_network_mocks, der, diagnostic
):
    _, _, _, wrap, handshake = validation_network_mocks
    peer = wrap.return_value
    if isinstance(der, OSError):
        peer.getpeercert.side_effect = der
    else:
        peer.getpeercert.return_value = der

    result = tls.audit_tls_certificate("example.test")

    handshake.assert_called_once_with()
    assert result["certificate_status"] == "metadata_error"
    assert result["certificate"] is None
    assert result["certificate_error"] == diagnostic
    assert result["connectivity"]["status"] == "ok"
    assert "diagnostics" not in result["connectivity"]


@pytest.mark.parametrize(
    ("field", "error_type"), [("version", RuntimeError), ("cipher", ValueError)]
)
def test_secondary_failure_red_unexpected_metadata_errors_propagate(
    validation_network_mocks, field, error_type
):
    _, _, connect, wrap, handshake = validation_network_mocks
    peer = wrap.return_value
    tcp = connect.return_value
    error = error_type("unexpected metadata defect")
    getattr(peer, field).side_effect = error

    with pytest.raises(error_type) as raised:
        tls.audit_tls_connectivity("example.test")

    assert raised.value is error
    handshake.assert_called_once_with()
    peer.__exit__.assert_called_once()
    tcp.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("failed_index", "field", "error_type", "diagnostic"),
    [
        (0, "version", OSError, "tls_version_unavailable"),
        (1, "version", OSError, "tls_version_unavailable"),
        (0, "cipher", ssl.SSLError, "cipher_metadata_unavailable"),
    ],
    ids=["first-version", "second-version", "first-cipher"],
)
def test_secondary_failure_red_protocol_preserves_observed_probes(
    protocol_network_mocks, failed_index, field, error_type, diagnostic
):
    factory, contexts, connect, handshakes, prepare_probe = protocol_network_mocks
    versions = ("TLSv1.2", "TLSv1.3")
    ciphers = ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256")
    sockets = [
        prepare_probe(version, cipher=(cipher, version, 128))
        for version, cipher in zip(versions, ciphers, strict=True)
    ]
    getattr(sockets[failed_index], field).side_effect = error_type(
        "synthetic private metadata path"
    )
    create_context = factory.side_effect

    def configure_probe():
        context = create_context()
        context.wrap_socket.return_value = sockets[len(contexts) - 1]
        return context

    factory.side_effect = configure_probe

    result = tls.audit_tls_protocols("example.test")

    assert result["status"] == "ok"
    assert result["not_probed"] == ["TLSv1", "TLSv1.1"]
    assert result["recommendations"] == []
    assert factory.call_count == connect.call_count == len(contexts) == 2
    assert contexts[0] is not contexts[1]
    assert handshakes == sockets
    assert [probe["requested_version"] for probe in result["probes"]] == list(versions)
    failed = result["probes"][failed_index]
    successful = result["probes"][1 - failed_index]
    assert successful["outcome"] == "confirmed_supported"
    assert successful["negotiated_version"] == versions[1 - failed_index]
    assert "diagnostics" not in successful
    assert failed["diagnostics"] == [diagnostic]
    assert failed["failed_stage"] is failed["verify_code"] is None
    if field == "version":
        assert failed["outcome"] == "inconclusive"
        assert failed["evidence_code"] == "tls_version_unavailable"
        assert failed["negotiated_version"] is None
        assert failed["cipher_suite"] == ciphers[failed_index]
        assert failed["secret_bits"] == 128
    else:
        assert failed["outcome"] == "confirmed_supported"
        assert failed["evidence_code"] == "verified_handshake"
        assert failed["negotiated_version"] == versions[failed_index]
        assert failed["cipher_suite"] is failed["secret_bits"] is None
    assert "synthetic private" not in json.dumps(result, allow_nan=False)


@pytest.mark.parametrize(
    ("primary", "tls_close", "tcp_close", "status", "stage", "verify_code"),
    [
        (None, False, True, "ok", None, None),
        ("wrap", False, True, "tls_handshake_error", "handshake", None),
        ("handshake", True, False, "tls_handshake_error", "handshake", None),
        ("certificate", True, True, "certificate_verification_failed", "handshake", 62),
    ],
    ids=[
        "tcp-after-success",
        "tcp-after-wrap",
        "tls-after-handshake",
        "both-after-certificate",
    ],
)
def test_secondary_failure_red_tls_cleanup_preserves_primary_result(
    validation_network_mocks, primary, tls_close, tcp_close, status, stage, verify_code
):
    _, _, connect, wrap, handshake = validation_network_mocks
    tcp, peer = connect.return_value, wrap.return_value
    lifecycle = MagicMock()
    lifecycle.attach_mock(peer.__exit__, "tls_exit")
    lifecycle.attach_mock(tcp.__exit__, "tcp_exit")
    if primary == "wrap":
        wrap.side_effect = ssl.SSLError("synthetic wrap failure")
    elif primary == "handshake":
        handshake.side_effect = ssl.SSLError("synthetic handshake failure")
    elif primary == "certificate":
        error = ssl.SSLCertVerificationError("synthetic peer rejection")
        error.verify_code = 62
        handshake.side_effect = error
    if tls_close:
        peer.__exit__.side_effect = OSError("synthetic private TLS cleanup path")
    if tcp_close:
        tcp.__exit__.side_effect = OSError("synthetic private TCP cleanup path")

    result = tls.audit_tls_connectivity("example.test")

    assert (result["status"], result["failed_stage"], result["verify_code"]) == (
        status,
        stage,
        verify_code,
    )
    expected = {
        code
        for enabled, code in (
            (tls_close, "tls_close_failed"),
            (tcp_close, "tcp_close_failed"),
        )
        if enabled
    }
    assert len(result["diagnostics"]) == len(expected)
    assert set(result["diagnostics"]) == expected
    assert [entry[0] for entry in lifecycle.mock_calls] == (
        ["tcp_exit"] if primary == "wrap" else ["tls_exit", "tcp_exit"]
    )
    assert "synthetic private" not in json.dumps(result, allow_nan=False)
    if verify_code is not None:
        peer.getpeercert.assert_not_called()


def test_secondary_failure_red_tcp_close_cannot_mask_unexpected_tls_exit(
    validation_network_mocks,
):
    _, _, connect, wrap, _ = validation_network_mocks
    tcp, peer = connect.return_value, wrap.return_value
    lifecycle = MagicMock()
    lifecycle.attach_mock(peer.__exit__, "tls_exit")
    lifecycle.attach_mock(tcp.__exit__, "tcp_exit")
    unexpected = RuntimeError("unexpected TLS context exit defect")
    peer.__exit__.side_effect = unexpected
    tcp.__exit__.side_effect = OSError("synthetic secondary TCP cleanup error")

    with pytest.raises(RuntimeError) as raised:
        tls.audit_tls_connectivity("example.test")

    assert raised.value is unexpected
    assert [entry[0] for entry in lifecycle.mock_calls] == ["tls_exit", "tcp_exit"]


@pytest.fixture
def verified_dependency_peer(validation_network_mocks):
    _, resolve, connect, wrap, handshake = validation_network_mocks
    peer = wrap.return_value
    yield peer
    connect.assert_called_once_with(("example.test", 443), timeout=5.0)
    handshake.assert_called_once_with()
    peer.getpeercert.assert_called_once_with(binary_form=True)
    peer.__exit__.assert_called_once()
    resolve.assert_not_called()


def assert_dependency_audit_evidence(result):
    connectivity = result["connectivity"]
    assert connectivity["status"] == "ok"
    assert connectivity["failed_stage"] is None
    assert connectivity["tls_version"] == "TLSv1.3"
    assert connectivity["cipher_suite"] == "TLS_AES_128_GCM_SHA256"
    assert json.loads(json.dumps(result, allow_nan=False)) == result


@pytest.mark.parametrize(
    "absent",
    [
        pytest.param({"not_valid_before_utc"}, id="missing-start"),
        pytest.param({"not_valid_after_utc"}, id="missing-end"),
        pytest.param(
            {"not_valid_before_utc", "not_valid_after_utc"}, id="missing-both"
        ),
    ],
)
def test_cycle6_dependency_missing_validity_api(
    fixed_leaf_der, verified_dependency_peer, absent
):
    from cryptography import x509

    der, _ = fixed_leaf_der
    leaf = x509.load_der_x509_certificate(der)
    certificate_fields = {
        "extensions": leaf.extensions,
        "subject": leaf.subject,
        "issuer": leaf.issuer,
        "serial_number": leaf.serial_number,
        "not_valid_before_utc": leaf.not_valid_before_utc,
        "not_valid_after_utc": leaf.not_valid_after_utc,
    }
    for name in absent:
        del certificate_fields[name]
    certificate = type("SimulatedCertificate", (), certificate_fields)()
    verified_dependency_peer.getpeercert.return_value = der
    with patch.object(x509, "load_der_x509_certificate", return_value=certificate):
        result = tls.audit_tls_certificate("example.test")

    assert_dependency_audit_evidence(result)
    assert result["certificate_status"] == "metadata_error"
    assert result["certificate"] is None
    assert (
        result["certificate_error"]
        == "cryptography is required for certificate metadata"
    )


@pytest.mark.parametrize("error_type", [ImportError, RuntimeError, AttributeError])
def test_cycle6_dependency_unexpected_parser_error_propagates(
    verified_dependency_peer, error_type
):
    from cryptography import x509

    verified_dependency_peer.getpeercert.return_value = b"synthetic DER"
    error = error_type("unexpected failure inside the certificate parser")
    with (
        patch.object(x509, "load_der_x509_certificate", side_effect=error),
        pytest.raises(error_type) as caught,
    ):
        tls.audit_tls_certificate("example.test")

    assert caught.value is error


@pytest.mark.parametrize("field", ["subject", "not_valid_after_utc"])
def test_cycle6_dependency_an_existing_metadata_property_can_raise(
    fixed_leaf_der, verified_dependency_peer, field
):
    from cryptography import x509

    der, _ = fixed_leaf_der
    leaf = x509.load_der_x509_certificate(der)
    error = AttributeError("unexpected failure while using an existing property")

    class SimulatedCertificate:
        extensions = leaf.extensions
        subject = leaf.subject
        issuer = leaf.issuer
        serial_number = leaf.serial_number
        not_valid_before_utc = leaf.not_valid_before_utc
        not_valid_after_utc = leaf.not_valid_after_utc

    def broken_property(self):
        raise error

    setattr(SimulatedCertificate, field, property(broken_property))
    verified_dependency_peer.getpeercert.return_value = der
    with (
        patch.object(
            x509, "load_der_x509_certificate", return_value=SimulatedCertificate()
        ),
        pytest.raises(AttributeError) as caught,
    ):
        tls.audit_tls_certificate("example.test")

    assert caught.value is error


def test_cycle6_dependency_package_absent(verified_dependency_peer, monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography", None)
    verified_dependency_peer.getpeercert.return_value = b"synthetic DER"

    result = tls.audit_tls_certificate("example.test")

    assert_dependency_audit_evidence(result)
    assert result["certificate_status"] == "metadata_error"
    assert result["certificate"] is None
    assert (
        result["certificate_error"]
        == "cryptography is required for certificate metadata"
    )


@pytest.mark.parametrize(
    ("source", "status", "diagnostic"),
    [
        pytest.param("valid", "ok", None, id="supported-utc-apis"),
        pytest.param(
            "absent",
            "metadata_error",
            "Verified peer supplied no certificate DER",
            id="absent-der",
        ),
        pytest.param(
            "malformed",
            "metadata_error",
            "Unable to parse verified certificate metadata",
            id="malformed-der",
        ),
    ],
)
def test_cycle6_dependency_preserves_der_outcomes(
    fixed_leaf_der, verified_dependency_peer, source, status, diagnostic
):
    valid_der, expires = fixed_leaf_der
    verified_dependency_peer.getpeercert.return_value = {
        "valid": valid_der,
        "absent": None,
        "malformed": b"invalid DER",
    }[source]

    result = tls.audit_tls_certificate("example.test")

    assert_dependency_audit_evidence(result)
    assert result["certificate_status"] == status
    assert result["certificate_error"] == diagnostic
    if source == "valid":
        assert (
            datetime.fromisoformat(result["certificate"]["not_valid_after"]) == expires
        )
        assert (
            result["certificate"]["sha256_fingerprint"] == sha256(valid_der).hexdigest()
        )
    else:
        assert result["certificate"] is None
