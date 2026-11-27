
"""Command-line interface for WebGuard Audit."""

import argparse
from time import monotonic
from urllib.parse import urlsplit

from webguard import __version__
from webguard.auditors import https, tls
from webguard.auditors.http_audit import audit as audit_http
from webguard.auditors.report_adapter import AuditKind, RawAuditResult
from webguard.core.audit_integration import integrate_audit_results
from webguard.reporting.html_report import generate_html_report
from webguard.reporting.json_report import generate_json_report
from webguard.security.authorization import confirm_authorization
from webguard.security.dialer import AuthorizedTransport, UnauthorizedDial
from webguard.security.fetcher import fetch
from webguard.security.scope_validator import approved_origin

# Policies that Module 1 (HTTP auditor) evaluates. POL-009 (TLS/HTTPS) belongs to Module 2.
HTTP_POLICIES = {"POL-002", "POL-003", "POL-004", "POL-005", "POL-006", "POL-007", "POL-008"}


_AUDIT_BUDGET = 20.0


def _operation_plan(scheme: str) -> list[tuple[str, str]]:
    if scheme == "http":
        return [
            ("http_headers", "HTTP security header analysis"),
            ("http_redirect", "First-hop HTTP redirect assessment"),
        ]
    return [
        ("tls_certificate", "Certificate and verified TLS connectivity"),
        ("tls_protocols", "Modern TLS protocol assessment"),
        ("http_redirect", "HTTPS availability and first-hop redirect assessment"),
    ]


def run_audit(target: str) -> int:
    """Execute the plan for one approved source and write local reports."""
    origin = approved_origin(target)
    if origin is None:
        print("[-] Target is invalid or outside the approved scope.")
        return 1

    parsed = urlsplit(origin)
    host, port = parsed.hostname, parsed.port
    if host is None or port is None:
        print("[-] Target has no explicit endpoint.")
        return 1
    transport = AuthorizedTransport(
        parsed.scheme, host, port, host, deadline=monotonic() + _AUDIT_BUDGET
    )
    tls_inputs: list[tuple[AuditKind, RawAuditResult]] = []
    unavailable = []
    http_findings = []
    checked = set()

    for kind, label in _operation_plan(parsed.scheme):
        print(f"[*] {label}")
        try:
            transport.checkpoint(_AUDIT_BUDGET)
            if kind == "http_headers":
                response = fetch(target, transport=transport)
            elif kind == "tls_certificate":
                tls_inputs.append(
                    (kind, tls.audit_tls_certificate(host, port, transport=transport))
                )
            elif kind == "tls_protocols":
                tls_inputs.append(
                    (kind, tls.audit_tls_protocols(host, port, transport=transport))
                )
            else:
                tls_inputs.append(
                    (
                        "http_redirect",
                        https.audit_http_redirect(
                            host, port, source_scheme=parsed.scheme, transport=transport
                        ),
                    )
                )
        except UnauthorizedDial:
            unavailable.append(f"{label} (unauthorized)")
        except TimeoutError:
            unavailable.append(f"{label} (deadline or operation timeout)")
        except OSError:
            unavailable.append(f"{label} (failed or refused)")
        else:
            if kind == "http_headers":
                http_findings = audit_http(response)
                checked = set(HTTP_POLICIES)
            continue
        print(f"[-] Could not audit the target: {unavailable[-1]}.")

    result = integrate_audit_results(http_findings, tls_inputs, checked)
    for label in unavailable:
        result["audit_coverage"].append(
            {
                "audit_kind": label,
                "coverage_status": "INCOMPLETE",
                "data_quality_issues": 0,
            }
        )
    partial = any(
        row["coverage_status"] == "INCOMPLETE" for row in result["audit_coverage"]
    )
    result["audit_coverage"].append(
        {
            "audit_kind": f"Audit scope: {origin}",
            "coverage_status": "INCOMPLETE" if partial else "COMPLETED",
            "data_quality_issues": 0,
        }
    )

    risk = result["risk_summary"]
    compliance = result["compliance_summary"]
    print(f"[+] Findings: {len(result['findings'])}")
    print(f"[+] Overall risk: {risk['overall_risk_level']} (score {risk['total_risk_score']})")
    print(
        f"[+] Compliance: {compliance['passed']} passed, {compliance['failed']} failed, "
        f"{compliance['not_checked']} not checked"
    )
    for finding in result["findings"]:
        print(f"    {finding.severity:<8} {finding.title}")

    print(f"[+] JSON report: {generate_json_report(result)}")
    print(f"[+] HTML report: {generate_html_report(result)}")
    if partial:
        print(
            "[!] Partial audit reports saved locally. Some operations were incomplete."
        )
    else:
        print("[*] Audit reports saved locally.")
    return int(partial)


def main():
    try:
        return execute_cli()

    except KeyboardInterrupt:
        print("\n[!] Kill switch activated.")
        print("[*] Audit cancelled by user.")
        return 130


def execute_cli():
    parser = argparse.ArgumentParser(
        prog="WebGuard Audit",
        description="Web Server and TLS Security Compliance Scanner",
        epilog=(
            "Examples:\n"
            "  python main.py --target http://127.0.0.1:8000\n"
            "  python main.py --target https://127.0.0.1:8443 --dry-run"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"WebGuard Audit {__version__}"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target URL to audit"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display the audit plan without scanning"
    )

    args = parser.parse_args()

    print("\n==========================")
    print("      WEBGUARD AUDIT")
    print("==========================")

    print("\n=== LEGAL DISCLAIMER ===")
    print("This tool is intended for authorized security auditing only.")
    print("Users must comply with Malaysia's Computer Crimes Act 1997 (Act 563).")
    print("Unauthorized access and misuse are prohibited.")

    # Validate target scope.
    origin = approved_origin(args.target)
    if origin is None:
        print("[-] Target is invalid or outside the approved scope.")
        return 1

    print("[+] Target is within the approved scope.")

    # Confirm authorization.
    if not confirm_authorization(origin):
        return 1

    # Handle dry-run mode.
    if args.dry_run:
        print("\n=== DRY-RUN MODE ===")
        print(f"Target: {origin}")
        print("Planned audit activities:")
        for index, (_, label) in enumerate(_operation_plan(urlsplit(origin).scheme), 1):
            print(f"{index}. {label}")
        print("Then score the available findings and write local reports.")
        print("\nNo network requests were performed.")
        return 0

    # Start the audit.
    print("\n[+] All safety checks passed.")
    print("[*] Starting audit...")

    return run_audit(args.target)
