"""Weighted risk scoring for WebGuard Audit."""

from webguard.core.models import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


def get_risk_score(severity: str) -> int:
    """Return the risk score for a severity level."""
    severity = severity.strip().upper()

    if severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Invalid severity: {severity}")

    return SEVERITY_WEIGHTS[severity]


def remove_duplicates(findings: list[Finding]) -> list[Finding]:
    """Remove repeated security findings."""
    unique = {}

    for finding in findings:
        key = finding.key()

        if key not in unique or get_risk_score(finding.severity) > get_risk_score(unique[key].severity):
            unique[key] = finding

    return list(unique.values())


def calculate_total_risk(findings: list[Finding]) -> int:
    """Calculate the total weighted risk score."""
    unique_findings = remove_duplicates(findings)

    total_score = 0

    for finding in unique_findings:
        total_score += get_risk_score(finding.severity)

    return total_score


def classify_risk(findings: list[Finding]) -> str:
    """Determine the overall risk classification."""
    total_score = calculate_total_risk(findings)

    if any(f.severity.strip().upper() == "CRITICAL" for f in findings):
        return "CRITICAL"

    if total_score >= 20:
        return "CRITICAL"
    elif total_score >= 7:
        return "HIGH"
    elif total_score >= 4:
        return "MEDIUM"
    elif total_score >= 1:
        return "LOW"

    return "INFO"

def count_severities(findings: list[Finding]) -> dict[str, int]:
    """Count unique findings by severity level."""
    counts = {severity: 0 for severity in SEVERITY_WEIGHTS}

    for finding in remove_duplicates(findings):
        severity = finding.severity.strip().upper()
        get_risk_score(severity)
        counts[severity] += 1

    return counts

def generate_risk_summary(findings: list[Finding]) -> dict:
    """Generate a combined security risk summary."""
    unique_findings = remove_duplicates(findings)

    return {
        "total_findings": len(unique_findings),
        "duplicates_removed": len(findings) - len(unique_findings),
        "total_risk_score": calculate_total_risk(unique_findings),
        "overall_risk_level": classify_risk(unique_findings),
        "severity_counts": count_severities(unique_findings),
    }