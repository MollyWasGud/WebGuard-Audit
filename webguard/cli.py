
"""Command-line interface for WebGuard Audit."""

import argparse

from webguard import __version__
from webguard.security.authorization import confirm_authorization
from webguard.security.scope_validator import validate_target


def run_audit(target: str):
    """Placeholder for future scanner integration."""

    print("[*] Scanner modules are not integrated yet.")
    print("[*] No network requests were performed.")


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

    run_audit(args.target)

    return 0
