
"""Command-line interface for WebGuard Audit."""

import argparse

from webguard import __version__
from webguard.auditors.http_audit import audit as audit_http
from webguard.core.audit_integration import integrate_audit_results
from webguard.reporting.html_report import generate_html_report
from webguard.reporting.json_report import generate_json_report
from webguard.security.authorization import confirm_authorization
from webguard.security.fetcher import FetchRefused, fetch
from webguard.security.scope_validator import validate_target

# Policies that Module 1 (HTTP auditor) evaluates. POL-009 (TLS/HTTPS) belongs to Module 2.
HTTP_POLICIES = {"POL-002", "POL-003", "POL-004", "POL-005", "POL-006", "POL-007", "POL-008"}


def run_audit(target: str) -> int:
    """Fetch the (already scope-checked) target once, audit it, score it and write local reports."""

    print("[*] Fetching the target once (direct connection, no proxy, no redirects)...")
    try:
        response = fetch(target)
    except (FetchRefused, OSError) as exc:
        print(f"[-] Could not audit the target: {exc}")
        return 1

    http_findings = audit_http(response)

    # HSTS only means something over HTTPS. Over plain HTTP it stays NOT_CHECKED instead of a false PASS.
    checked = set(HTTP_POLICIES)
    if response.is_https:
        checked.add("POL-001")

    # TLS reports come from Module 2. A plain-HTTP target has no TLS to inspect, so the list is empty
    # and TLS/HTTPS coverage is reported as not checked.
    result = integrate_audit_results(http_findings, [], checked)

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
    print("[*] Reports were saved locally. Nothing was sent anywhere.")
    return 0


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
        description="Web Server and TLS Security Compliance Scanner"
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

    # Validate target scope.
    if not validate_target(args.target):
        print("[-] Target is invalid or outside the approved scope.")
        return 1

    print("[+] Target is within the approved scope.")

    # Confirm authorization.
    if not confirm_authorization(args.target):
        return 1

    # Handle dry-run mode.
    if args.dry_run:
        print("\n=== DRY-RUN MODE ===")
        print(f"Target: {args.target}")
        print("Planned audit activities:")
        print("1. HTTP security header analysis")
        print("2. TLS and HTTPS analysis")
        print("3. Risk and compliance evaluation")
        print("4. Report generation")
        print("\nNo network requests were performed.")
        return 0

    # Start the audit.
    print("\n[+] All safety checks passed.")
    print("[*] Starting audit...")

    return run_audit(args.target)
