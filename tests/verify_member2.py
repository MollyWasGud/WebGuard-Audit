"""Run the designated Windows Member 2 suite with required loopback coverage."""

import ipaddress
import os
import socket
import sys
from pathlib import Path

import pytest

REQUIRED_LOOPBACK_NODEIDS = (
    "tests/test_tls.py::test_local_tls_integration[trusted-matching-hostname]",
    "tests/test_tls.py::test_local_tls_integration[untrusted-ca]",
    "tests/test_tls.py::test_local_tls_integration[trusted-mismatched-hostname]",
    "tests/test_tls.py::test_local_certificate_audit[trusted]",
    "tests/test_tls.py::test_local_certificate_audit[near-expiry]",
    "tests/test_tls.py::test_local_certificate_audit[expired]",
    "tests/test_tls.py::test_local_certificate_audit[untrusted]",
    "tests/test_tls.py::test_local_certificate_audit[mismatch]",
    "tests/test_tls.py::test_local_certificate_rejects_dns_hostname_mismatch",
    "tests/test_tls.py::test_local_tls_protocol_integration[tls12-only]",
    "tests/test_tls.py::test_local_tls_protocol_integration[tls13-only]",
    "tests/test_tls.py::test_local_tls_protocol_integration[both-versions]",
    "tests/test_tls.py::test_local_tls_protocol_integration[tcp-close-before-tls]",
    "tests/test_tls.py::test_local_tls_protocol_integration[untrusted-ca]",
    "tests/test_tls.py::test_local_tls_protocol_integration[trusted-ip-mismatch]",
    "tests/test_tls.py::test_keylog_red_loopback_protocols_preserve_version_restriction[local_tls_server0]",
    "tests/test_https.py::test_local_https_integration_response[ok]",
    "tests/test_https.py::test_local_https_integration_response[method-not-allowed]",
    "tests/test_https.py::test_local_https_integration_response[service-unavailable]",
    "tests/test_https.py::test_local_https_integration_response[malformed-status]",
    "tests/test_https.py::test_local_https_integration_response[truncated-head]",
    "tests/test_https.py::test_local_https_integration_response[control-character]",
    "tests/test_https.py::test_local_https_integration_response[continue-then-ok]",
    "tests/test_https.py::test_local_https_integration_response[unsupported-version]",
    "tests/test_https.py::test_local_https_integration_response[stalled]",
    "tests/test_https.py::test_local_https_integration_rejects_certificate_before_http[untrusted-ca]",
    "tests/test_https.py::test_local_https_integration_rejects_certificate_before_http[trusted-identity-mismatch]",
    "tests/test_https.py::test_local_https_integration_leaves_redirect_destination_uncontacted",
    "tests/test_https.py::test_local_redirect_integration_keeps_destination_uncontacted[upgrade]",
    "tests/test_https.py::test_local_redirect_integration_keeps_destination_uncontacted[downgrade]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[plaintext-no-upgrade]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[relative-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[duplicate-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[credential-bearing-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[ambiguous-ipv4-location]",
    "tests/test_https.py::test_local_redirect_integration_skips_assessment_on_tls_verification_failure[untrusted-ca]",
    "tests/test_https.py::test_local_redirect_integration_skips_assessment_on_tls_verification_failure[trusted-identity-mismatch]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[trusted]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[untrusted]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[mismatch]",
)
_PHASES = ("setup", "call", "teardown")


class _RequiredLoopbackCases:
    def __init__(self) -> None:
        self.collected: set[str] = set()
        self.reports: dict[str, dict[str, str]] = {
            nodeid: {} for nodeid in REQUIRED_LOOPBACK_NODEIDS
        }

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = {item.nodeid for item in session.items}

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        phases = self.reports.get(report.nodeid)
        if phases is None:
            return
        outcome = report.outcome
        if getattr(report, "wasxfail", None) is not None:
            outcome = "xfail/xpass"
        if phases.get(report.when, "passed") == "passed":
            phases[report.when] = outcome

    def unsuccessful(self) -> list[str]:
        failures = []
        for nodeid, reports in self.reports.items():
            if nodeid not in self.collected:
                failures.append(f"{nodeid}: not collected")
                continue
            phases = [
                f"{phase} {reports.get(phase, 'missing')}"
                for phase in _PHASES
                if reports.get(phase) != "passed"
            ]
            if phases:
                failures.append(f"{nodeid}: {', '.join(phases)}")
        return failures


def main() -> int:
    if os.environ.get("PYTEST_ADDOPTS"):
        print(
            "Designated verification requires PYTEST_ADDOPTS to be unset or empty.",
            file=sys.stderr,
        )
        return 1

    if os.environ.get("PYTEST_PLUGINS"):
        print(
            "Designated verification requires PYTEST_PLUGINS to be unset or empty.",
            file=sys.stderr,
        )
        return 1

    required = _RequiredLoopbackCases()
    status = pytest.main(
        [
            "--disable-plugin-autoload",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "-q",
            "tests/test_tls.py",
            "tests/test_https.py",
            "tests/test_report_adapter.py",
            "tests/test_member2_verification.py",
        ],
        plugins=[required],
    )
    unsuccessful = required.unsuccessful()
    total = len(REQUIRED_LOOPBACK_NODEIDS)
    print(
        f"Windows Member 2 verification: {total - len(unsuccessful)}/{total} required loopback cases passed"
    )
    for failure in unsuccessful:
        print(failure, file=sys.stderr)
    return int(status) or int(bool(unsuccessful))


def _run_windows_profile() -> int:
    if sys.platform != "win32":
        print(
            "The designated Member 2 verification profile requires Windows.",
            file=sys.stderr,
        )
        return 1

    loopback = blocked = 0
    resolve = socket.getaddrinfo

    def loopback_lookup(host, *args, **kwargs):
        # Resolve the test identity locally without consulting DNS.
        return resolve("127.0.0.1" if host == "localhost" else host, *args, **kwargs)

    def guard(event, args):
        nonlocal loopback, blocked
        if event in {"socket.connect", "socket.bind", "socket.sendto"}:
            address = args[1]
            host = address[0] if isinstance(address, tuple) else None
        elif event in {
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyaddr",
        }:
            host = args[0]
        else:
            return
        try:
            local = ipaddress.ip_address(host).is_loopback
        except (TypeError, ValueError):
            local = False
        if not local:
            blocked += 1
            raise AssertionError("Non-loopback operation blocked during verification")
        loopback += 1

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.addaudithook(guard)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket, "getaddrinfo", loopback_lookup)
        status = main()
    print(
        f"Parent loopback operations: {loopback}  Blocked non-loopback attempts: {blocked}"
    )
    return status or int(blocked > 0)


if __name__ == "__main__":
    raise SystemExit(_run_windows_profile())
