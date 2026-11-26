"""Before/after demo: audit a weak local server, then a hardened one.   python3 demo/run_demo.py"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from demo.loopback_fetch import fetch
from demo.servers import HardenedHandler, WeakHandler, start
from webguard.auditors.http_audit import audit, summarize


def show(label: str, handler) -> dict:
    server, url = start(handler)
    try:
        findings = audit(fetch(url))
    finally:
        server.shutdown()
    print(f"\n=== {label}  ({url}) ===")
    for f in findings:
        evidence = f"  [{f.evidence}]" if f.evidence else ""
        print(f"{f.severity:<8} {f.category:<10} {f.title}{evidence}")
    counts = summarize(findings)
    print("Summary:", "  ".join(f"{k}:{v}" for k, v in counts.items()))
    return counts


if __name__ == "__main__":
    print("WebGuard Audit - Module 1 demo (127.0.0.1 only, nothing leaves this computer)")
    before = show("BEFORE: weak server", WeakHandler)
    after = show("AFTER:  hardened server", HardenedHandler)
    drop = sum(before.values()) - sum(after.values())
    print(f"\nFindings reduced by {drop} after hardening.")
