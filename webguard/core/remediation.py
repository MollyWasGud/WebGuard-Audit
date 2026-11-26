"""Prioritise security remediation recommendations."""

from webguard.core.models import Finding
from webguard.core.risk_scoring import (
    get_risk_score,
    remove_duplicates,
)


def generate_remediation_plan(findings: list[Finding]) -> list[dict]:
    """Generate prioritised remediation recommendations."""
    unique_findings = remove_duplicates(findings)

    sorted_findings = sorted(
        unique_findings,
        key=lambda finding: get_risk_score(finding.severity),
        reverse=True,
    )

    return [
        {
            "priority": index,
            "check_id": finding.check_id,
            "severity": finding.severity.upper(),
            "title": finding.title,
            "recommendation": finding.remediation,
            "risk_score": get_risk_score(finding.severity),
        }
        for index, finding in enumerate(sorted_findings, start=1)
    ]