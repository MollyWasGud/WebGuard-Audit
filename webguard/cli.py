import argparse

from webguard import __version__


def main():
    parser = argparse.ArgumentParser(
        prog="WebGuard Audit",
        description="Web Server and TLS Security Compliance Scanner"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"WebGuard Audit {__version__}"
    )

    parser.parse_args()
    print("Welcome to WebGuard Audit!")