"""Module 1 - HTTP Security Auditor (headers, CSP, information disclosure, cookies).

Pure analysis: it receives a ResponseData and returns Findings. It makes NO network requests, so scope
checks, dry-run and the kill switch (Member 4) stay in one place.

    from webguard.auditors.http_audit import audit
    findings = audit(ResponseData(url, status, headers, body))
"""

from __future__ import annotations

from ...core.models import SEVERITIES, Finding, ResponseData
from .cookies import audit_cookies
from .csp import audit_csp
from .disclosure import audit_disclosure
from .headers import audit_headers

__all__ = ["audit", "summarize"]


def audit(resp: ResponseData) -> list[Finding]:
    """Run every Module-1 check; de-duplicated and sorted most severe first."""
    findings: dict[str, Finding] = {}
    for check in (audit_headers, audit_csp, audit_disclosure, audit_cookies):
        for finding in check(resp):
            findings.setdefault(finding.key(), finding)
    return sorted(findings.values(), key=lambda f: (-SEVERITIES.index(f.severity), f.check_id))


def summarize(findings: list[Finding]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if f.severity == sev) for sev in reversed(SEVERITIES)}
