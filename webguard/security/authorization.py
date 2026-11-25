
"""Authorization safeguards for WebGuard Audit."""


def confirm_authorization(target: str) -> bool:
    print("\n=== AUTHORIZATION REQUIRED ===")
    print(f"Target: {target}")
    print("Only audit systems you have permission to test.")

    try:
        response = input(
            "Do you have authorization? (yes/no): "
        ).strip().lower()

    except (KeyboardInterrupt, EOFError):
        print("\nAuthorization cancelled.")
        return False

    if response == "yes":
        print("[+] Authorization confirmed.")
        return True

    print("[-] Authorization denied. Audit cancelled.")
    return False
