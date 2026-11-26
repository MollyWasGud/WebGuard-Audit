"""Run the standalone Member 2 demo on authorized IPv4 loopback listeners."""

import json
import socket
import ssl
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer
from tempfile import TemporaryDirectory, gettempdir
from threading import Event, Thread
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from webguard.auditors import https, tls
from webguard.auditors.report_adapter import ReportInputError, to_safe_audit_report

LOOPBACK = "127.0.0.1"
HOSTNAME = "localhost"
WRONG_HOSTNAME = "mismatch.invalid"
TIMEOUT = 2.0


class DemoError(RuntimeError):
    """A demo invariant failed."""


def require(condition, message):
    if not condition:
        raise DemoError(message)


def install_loopback_guard():
    counts = {"loopback_operations": 0, "blocked_non_loopback_attempts": 0}

    def guard(event, args):
        if event in {"socket.connect", "socket.bind", "socket.sendto"}:
            address = args[1]
            host = address[0] if isinstance(address, tuple) else None
        elif event in {
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyaddr",
            "socket.gethostbyname_ex",
        }:
            host = args[0]
        else:
            return
        if host != LOOPBACK:
            counts["blocked_non_loopback_attempts"] += 1
            raise DemoError(
                "Network operation blocked outside the demo's IPv4 loopback address."
            )
        counts["loopback_operations"] += 1

    sys.addaudithook(guard)
    return counts


def demo_credentials(directory):
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebGuard Demo CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])

    def certificate(subject, key, lifetime):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + lifetime)
        )

    ca = (
        certificate(ca_name, ca_key, timedelta(hours=2))
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
    leaf = (
        certificate(leaf_name, leaf_key, timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False
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

    cert_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.num_tickets = 0
    context.load_cert_chain(cert_path, key_path)
    return context, ca.public_bytes(serialization.Encoding.PEM).decode("ascii")


class HeadHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.heads.append(f"{self.command} {self.path}")
        status, location = self.server.reply
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class LoopbackServer(TCPServer):
    def __init__(self, context):
        self.context = context
        self.heads = []
        self.reply = (200, None)
        self.handler_failed = False
        super().__init__((LOOPBACK, 0), HeadHandler)

    def get_request(self):
        peer, address = super().get_request()
        try:
            peer.settimeout(TIMEOUT)
            if self.context is not None:
                peer = self.context.wrap_socket(peer, server_side=True)
        except OSError:
            peer.close()
            raise
        return peer, address

    def handle_error(self, request, client_address):
        self.handler_failed = True


@contextmanager
def running_server(context=None):
    with LoopbackServer(context) as server:
        server.timeout = 0.05
        stop = Event()

        def serve():
            while not stop.is_set():
                server.handle_request()

        worker = Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            stop.set()
            worker.join(timeout=2 * TIMEOUT + 1)
            require(not worker.is_alive(), "Loopback server did not stop.")
    require(server.socket.fileno() == -1, "Loopback listener did not close.")
    require(not server.handler_failed, "Loopback request handler failed.")


def exercise_auditors(secure, plain, ca_pem):
    tls_port = secure.server_address[1]
    http_port = plain.server_address[1]
    secure.reply = (200, None)
    plain.reply = (302, f"https://{HOSTNAME}:{tls_port}/destination")
    allowed = {(HOSTNAME, tls_port), (WRONG_HOSTNAME, tls_port), (HOSTNAME, http_port)}
    connect = socket.create_connection
    create_context = tls._create_verified_client_context
    dialed = []
    adapted_reports = 0

    def pinned_connect(address, timeout):
        require(address in allowed, "Unexpected demo dial endpoint.")
        endpoint = (LOOPBACK, address[1])
        dialed.append(endpoint)
        peer = connect(endpoint, timeout=timeout)
        if peer.getpeername() != endpoint:
            peer.close()
            raise DemoError("Connected peer differs from the pinned endpoint.")
        return peer

    def trusted_context():
        context = create_context()
        context.load_verify_locations(cadata=ca_pem)
        return context

    def safe(kind, raw):
        nonlocal adapted_reports
        report = to_safe_audit_report(kind, raw)
        require(report["schema_version"] == 1, "Expected reporting schema version 1.")
        json.dumps(report, allow_nan=False)
        adapted_reports += 1
        return report["data"]

    def first_hop(scheme, source_port, target_port, expected):
        start = len(dialed)
        result = safe(
            "http_redirect",
            https.audit_http_redirect(
                HOSTNAME, source_port, source_scheme=scheme, timeout=TIMEOUT
            ),
        )
        redirect = result["redirect"]
        destination = redirect["destination"]
        require(
            redirect["outcome"] == expected
            and destination is not None
            and destination["port"] == target_port
            and destination["verification"] == "not_attempted",
            f"Expected {expected} redirect intent.",
        )
        hops = dialed[start:]
        require(
            hops == [(LOOPBACK, source_port)],
            "Redirect audit dialed beyond its source.",
        )
        return {
            "outcome": redirect["outcome"],
            "http_status": result["probe"]["http_status"],
            "verification": destination["verification"],
            "destination_dials": hops.count((LOOPBACK, target_port)),
        }

    with (
        patch.object(socket, "create_connection", pinned_connect),
        patch.object(tls, "_create_verified_client_context", trusted_context),
        patch.object(https, "_create_verified_client_context", trusted_context),
    ):
        connection = safe(
            "tls_connectivity",
            tls.audit_tls_connectivity(HOSTNAME, tls_port, timeout=TIMEOUT),
        )
        require(
            connection["status"] == "ok"
            and connection["tls_version"]
            and connection["cipher_suite"],
            "Verified TLS did not supply negotiation evidence.",
        )
        certificate = safe(
            "tls_certificate",
            tls.audit_tls_certificate(
                HOSTNAME, tls_port, timeout=TIMEOUT, warning_days=1
            ),
        )
        require(
            certificate["certificate_status"] == "ok"
            and certificate["certificate"]["expiration_status"] == "expiring_soon",
            "Trusted leaf did not classify as near expiry.",
        )
        mismatch = safe(
            "tls_certificate",
            tls.audit_tls_certificate(WRONG_HOSTNAME, tls_port, timeout=TIMEOUT),
        )
        mismatch_status = mismatch["connectivity"]["status"]
        require(
            mismatch_status == "certificate_verification_failed"
            and mismatch["connectivity"]["verify_code"] == 62
            and mismatch["certificate_status"] == "not_collected",
            "Expected real hostname mismatch rejection.",
        )
        protocols = safe(
            "tls_protocols",
            tls.audit_tls_protocols(
                HOSTNAME, tls_port, timeout=TIMEOUT, probe_legacy=True
            ),
        )
        require(
            any(
                probe["outcome"] == "confirmed_supported"
                for probe in protocols["probes"]
            ),
            "No verified protocol probe succeeded.",
        )
        raw_availability = https.audit_https_availability(
            HOSTNAME, tls_port, timeout=TIMEOUT
        )
        availability = safe("https_availability", raw_availability)
        require(
            availability["outcome"] == "available"
            and availability["http_status"] == 200
            and secure.heads == ["HEAD /"],
            "Expected a HEAD request and a final HTTPS 200 response.",
        )
        upgrade = first_hop("http", http_port, tls_port, "upgrade")
        secure.reply = (302, f"http://{HOSTNAME}:{http_port}/destination")
        downgrade = first_hop("https", tls_port, http_port, "downgrade")
        require(
            plain.heads == ["HEAD /"] and secure.heads == ["HEAD /", "HEAD /"],
            "Unexpected HTTP requests reached a demo listener.",
        )

    try:
        to_safe_audit_report(
            "https_availability", raw_availability | {"is_redirect": True}
        )
    except ReportInputError as error:
        rejection = str(error)
        require(
            rejection == "Invalid audit report input",
            "Unexpected report rejection message.",
        )
    else:
        raise DemoError("Contradictory report was accepted.")
    return {
        "tls_connectivity": {
            field: connection[field]
            for field in ("status", "tls_version", "cipher_suite")
        },
        "tls_certificate": {
            "certificate_status": certificate["certificate_status"],
            "expiration_status": certificate["certificate"]["expiration_status"],
            "hostname_mismatch_status": mismatch_status,
            "hostname_mismatch_verify_code": mismatch["connectivity"]["verify_code"],
        },
        "tls_protocols": [
            {
                field: probe[field]
                for field in (
                    "requested_version",
                    "outcome",
                    "evidence_code",
                    "negotiated_version",
                    "cipher_suite",
                )
            }
            for probe in protocols["probes"]
        ],
        "https_availability": {
            "outcome": availability["outcome"],
            "http_status": availability["http_status"],
            "observed_request": secure.heads[0],
        },
        "http_redirect": {"upgrade": upgrade, "downgrade": downgrade},
        "safe_reporting": {
            "schema_version": 1,
            "adapted_reports": adapted_reports,
            "contradictory_result": rejection,
        },
    }


def main():
    if len(sys.argv) != 1:
        print("This loopback demo does not accept target arguments.", file=sys.stderr)
        return 2

    counts = install_loopback_guard()
    try:
        temp_root = Path(gettempdir()).resolve()
        require(
            not temp_root.is_relative_to(Path(__file__).resolve().parents[1]),
            "Temporary certificate storage must be outside the repository.",
        )
        with TemporaryDirectory(
            dir=temp_root, prefix="webguard-tls-demo-"
        ) as temporary:
            directory = Path(temporary)
            context, ca_pem = demo_credentials(directory)
            with running_server(context) as secure, running_server() as plain:
                output = exercise_auditors(secure, plain, ca_pem)
        require(not directory.exists(), "Temporary certificate files were not removed.")
        require(
            counts["blocked_non_loopback_attempts"] == 0,
            "Network guard blocked an operation.",
        )
        output["verification"] = counts | {"resources_cleaned": True}
        print(json.dumps(output, indent=2, allow_nan=False))
    except DemoError as error:
        print(f"Demo failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Demo failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
