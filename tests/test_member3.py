"""Automated tests for Member 3's compliance and reporting engine."""

from webguard.core.audit_integration import integrate_audit_results
from webguard.core.coverage import evaluate_coverage
from webguard.core.models import Finding
from webguard.core.policy import evaluate_policy
from webguard.core.remediation import generate_remediation_plan
from webguard.core.risk_scoring import (
    generate_risk_summary,
    get_risk_score,
)
from webguard.core.tls_findings import convert_tls_findings


def test_severity_weights():
    assert get_risk_score("CRITICAL") == 10
    assert get_risk_score("HIGH") == 7
    assert get_risk_score("MEDIUM") == 4
    assert get_risk_score("LOW") == 1
    assert get_risk_score("INFO") == 0


def test_duplicate_findings():
    finding = Finding(
        "TLS:legacy-version",
        "tls",
        "HIGH",
        "Legacy TLS",
        "Outdated protocol detected",
        "Disable legacy TLS",
    )

    result = generate_risk_summary([finding, finding])

    assert result["total_findings"] == 1
    assert result["duplicates_removed"] == 1
    assert result["total_risk_score"] == 7
    assert result["overall_risk_level"] == "HIGH"


def test_empty_findings():
    result = generate_risk_summary([])

    assert result["total_findings"] == 0
    assert result["total_risk_score"] == 0
    assert result["overall_risk_level"] == "INFO"


def test_compliance_pass():
    assert evaluate_policy(
        "POL-006", [], {"POL-006"}
    ) == "PASS"


def test_compliance_fail():
    finding = Finding(
        "CSP:missing",
        "csp",
        "MEDIUM",
        "Missing CSP",
        "Content Security Policy is missing",
        "Configure CSP",
    )

    assert evaluate_policy(
        "POL-006", [finding], {"POL-006"}
    ) == "FAIL"


def test_compliance_not_checked():
    assert evaluate_policy(
        "POL-006", [], set()
    ) == "NOT_CHECKED"


def make_tls_report(status):
    return {
        "schema_version": 1,
        "kind": "tls_connectivity",
        "data": {
            "hostname": "localhost",
            "port": 443,
            "status": status,
            "verify_code": (
                62 if status == "certificate_verification_failed"
                else None
            ),
        },
        "issues": [],
    }


def test_tls_certificate_failure():
    report = make_tls_report("certificate_verification_failed")
    findings = convert_tls_findings(report)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].check_id == "TLS:certificate-verification"


def test_tls_timeout():
    report = make_tls_report("timeout")

    assert convert_tls_findings(report) == []


def test_coverage_completed():
    report = make_tls_report("ok")
    result = evaluate_coverage(report)

    assert result["coverage_status"] == "COMPLETED"


def test_coverage_incomplete():
    report = make_tls_report("timeout")
    result = evaluate_coverage(report)

    assert result["coverage_status"] == "INCOMPLETE"


def test_remediation_priority():
    low = Finding("TEST:low", "test", "LOW", "Low", "Test", "Fix low")
    high = Finding("TEST:high", "test", "HIGH", "High", "Test", "Fix high")
    plan = generate_remediation_plan([low, high, high])

    assert len(plan) == 2
    assert plan[0]["severity"] == "HIGH"
    assert plan[0]["priority"] == 1
    assert plan[1]["severity"] == "LOW"


def test_audit_integration():
    report = make_tls_report("certificate_verification_failed")
    result = integrate_audit_results([], [report, report], set())

    assert len(result["findings"]) == 1
    assert result["risk_summary"]["total_risk_score"] == 7
    assert result["risk_summary"]["duplicates_removed"] == 1
    assert len(result["remediation_plan"]) == 1


def test_incomplete_tls_compliance():
    report = make_tls_report("ok")
    result = integrate_audit_results([], [report], {"POL-009"})

    assert result["compliance_summary"]["policy_results"][-1]["status"] == "NOT_CHECKED"