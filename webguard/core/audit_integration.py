"""Integrate audit findings, coverage and compliance."""

from webguard.core.coverage import evaluate_coverage
from webguard.core.models import Finding
from webguard.core.policy import generate_compliance_summary
from webguard.core.remediation import generate_remediation_plan
from webguard.core.risk_scoring import (
    generate_risk_summary,
    remove_duplicates,
)
from webguard.core.tls_findings import convert_tls_findings


def integrate_audit_results(
    http_findings: list[Finding],
    tls_reports: list[dict],
    checked_http_policies: set[str],
    require_https_upgrade: bool = False,
) -> dict:
    """Combine HTTP and validated TLS audit results."""
    findings = list(http_findings)
    coverage = []
    checked_policies = set(checked_http_policies)
    checked_policies.discard("POL-009")

    for report in tls_reports:
        findings.extend(
            convert_tls_findings(report, require_https_upgrade)
        )
        coverage.append(evaluate_coverage(report))

    unique_findings = remove_duplicates(findings)

    return {
        "findings": unique_findings,
        "risk_summary": generate_risk_summary(findings),
        "compliance_summary": generate_compliance_summary(
            unique_findings, checked_policies
        ),
        "audit_coverage": coverage,
        "remediation_plan": generate_remediation_plan(
            unique_findings
        ),
    }