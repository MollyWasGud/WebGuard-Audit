"""Run and verify the entire Windows regression inventory under the CI guard."""
import json
import os
from pathlib import Path
import ssl
import sys

import pytest
import sitecustomize

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from verify_member2 import REQUIRED_LOOPBACK_NODEIDS  # noqa: E402

EXPECTED = 922
PHASES = {"setup", "call", "teardown"}


class Inventory:
    def __init__(self):
        self.collected = []
        self.reports = {}

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report):
        self.reports.setdefault(report.nodeid, []).append(
            (report.when, report.outcome, hasattr(report, "wasxfail"))
        )

    def passed(self, nodeid):
        reports = self.reports.get(nodeid, [])
        return (
            len(reports) == 3
            and {phase for phase, _, _ in reports} == PHASES
            and all(outcome == "passed" and not xfail for _, outcome, xfail in reports)
        )


def main():
    if sys.platform != "win32" or not (ssl.HAS_TLSv1_2 and ssl.HAS_TLSv1_3):
        raise RuntimeError("Windows with TLS 1.2 and TLS 1.3 is required")
    if not getattr(sitecustomize, "ACTIVE", False):
        raise RuntimeError("CI network guard is not active")
    evidence = Path(os.environ["WG_CI_EVIDENCE"])
    inventory = Inventory()
    code = int(pytest.main(
        ["--disable-plugin-autoload", "-p", "no:cacheprovider", "-o", "addopts=",
         "-q", "tests", "--junitxml", str(evidence / "pytest.xml")],
        plugins=[inventory],
    ))
    unique = set(inventory.collected)
    passed = {nodeid for nodeid in unique if inventory.passed(nodeid)}
    required = set(REQUIRED_LOOPBACK_NODEIDS)
    blocked = evidence / "blocked-network.txt"
    summary = {
        "pytest_exit": code,
        "expected_tests": EXPECTED,
        "collected": len(inventory.collected),
        "unique_collected": len(unique),
        "passed_all_phases": len(passed),
        "required_loopback_total": len(required),
        "required_loopback_passed": len(required & passed),
        "blocked_network_attempts": len(blocked.read_text().splitlines()) if blocked.exists() else 0,
        "not_passed": sorted(unique - passed),
        "missing_required": sorted(required - passed),
        "guard": "Python audit hook; not OS-level network isolation",
    }
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (evidence / "collected-nodeids.txt").write_text("\n".join(sorted(unique)) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    complete = (
        code == 0 and len(inventory.collected) == len(unique) == len(passed) == EXPECTED
        and len(required) == 40 and required <= passed
        and not blocked.exists()
    )
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
