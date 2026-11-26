"""Compliance policy engine for WebGuard Audit."""

from webguard.core.models import Finding

POLICY_STATUS = {
    "PASS": "Security requirement satisfied",
    "FAIL": "Security requirement not satisfied",
    "NOT_CHECKED": "Security requirement not evaluated",
}

POLICIES = {
    "POL-001": "HSTS Protection",
    "POL-002": "Content Type Protection",
    "POL-003": "Clickjacking Protection",
    "POL-004": "Referrer Protection",
    "POL-005": "CORS Configuration",
    "POL-006": "Content Security Policy",
    "POL-007": "Information Disclosure",
    "POL-008": "Cookie Security",
    "POL-009": "TLS and HTTPS Security",
}

POLICY_MAPPING = {
    "POL-001": ("HDR:hsts",),
    "POL-002": ("HDR:nosniff",),
    "POL-003": (
        "HDR:clickjacking",
        "HDR:xfo-invalid",
        "HDR:frame-ancestors-wildcard",
    ),
    "POL-004": ("HDR:referrer",),
    "POL-005": ("HDR:cors",),
    "POL-006": ("CSP:",),
    "POL-007": ("DISC:",),
    "POL-008": ("COOKIE:",),
    "POL-009": (
        "TLS:certificate-verification",
        "TLS:expired",
        "TLS:legacy-version",
        "HTTPS:downgrade",
        "HTTPS:no-upgrade",
    ),
}


def match_policy(finding: Finding, policy_id: str) -> bool:
    """Check whether a finding belongs to a policy."""
    return finding.check_id.startswith(POLICY_MAPPING[policy_id])


def evaluate_policy(
    policy_id: str,
    findings: list[Finding],
    checked_policies: set[str],
) -> str:
    """Evaluate the status of a security policy."""
    if any(match_policy(f, policy_id) for f in findings):
        return "FAIL"

    if policy_id in checked_policies and POLICY_MAPPING[policy_id]:
        return "PASS"

    return "NOT_CHECKED"


def generate_compliance_summary(
    findings: list[Finding],
    checked_policies: set[str],
) -> dict:
    """Generate a summary of all security policies."""
    results = []
    counts = {status: 0 for status in POLICY_STATUS}

    for policy_id, name in POLICIES.items():
        status = evaluate_policy(
            policy_id, findings, checked_policies
        )

        counts[status] += 1

        results.append({
            "policy_id": policy_id,
            "policy_name": name,
            "status": status,
        })

    return {
        "total_policies": len(POLICIES),
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "not_checked": counts["NOT_CHECKED"],
        "policy_results": results,
    }