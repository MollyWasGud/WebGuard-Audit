"""Integrate audit findings, coverage and compliance."""

from webguard.auditors import report_adapter
from webguard.core.coverage import evaluate_coverage
from webguard.core.models import Finding
from webguard.core.policy import generate_compliance_summary
from webguard.core.remediation import generate_remediation_plan
from webguard.core.risk_scoring import (
    generate_risk_summary,
    remove_duplicates,
)
from webguard.core.tls_findings import (
    _CertificateVerificationFinding,
    convert_tls_findings,
)


def integrate_audit_results(
    http_findings: list[Finding],
    tls_inputs: list[tuple[report_adapter.AuditKind, report_adapter.RawAuditResult]],
    checked_http_policies: set[str],
    require_https_upgrade: bool = False,
) -> dict:
    """Adapt typed TLS auditor results and combine them with HTTP findings."""
    findings = list(http_findings)
    coverage = []
    verification_codes: dict[str, set[int]] = {}
    checked_policies = set(checked_http_policies)
    checked_policies.discard("POL-009")

    for entry in tls_inputs:
        try:
            if type(entry) is not tuple or len(entry) != 2:
                raise report_adapter.ReportInputError
            kind, raw = entry
            report = report_adapter.to_safe_audit_report(kind, raw)
            if "schema_version" in raw:
                raise report_adapter.ReportInputError
        except report_adapter.ReportInputError:
            coverage.append(
                {
                    "audit_kind": "Rejected TLS input",
                    "coverage_status": "INCOMPLETE",
                    "data_quality_issues": 1,
                }
            )
            continue

        tls_findings = convert_tls_findings(report, require_https_upgrade)
        for finding in tls_findings:
            if (
                isinstance(finding, _CertificateVerificationFinding)
                and finding.endpoint
            ):
                code = finding.evidence.removeprefix(f"{finding.endpoint} verify_code=")
                if code.isdecimal():
                    verification_codes.setdefault(finding.key(), set()).add(int(code))
        findings.extend(tls_findings)
        coverage.append(evaluate_coverage(report))

    unique_findings = remove_duplicates(findings)
    for finding in unique_findings:
        if isinstance(finding, _CertificateVerificationFinding) and finding.endpoint:
            codes = verification_codes.get(finding.key())
            if codes:
                code_list = ", ".join(str(code) for code in sorted(codes))
                finding.evidence = f"{finding.endpoint} verify_code={code_list}"

    return {
        "findings": unique_findings,
        "risk_summary": generate_risk_summary(findings),
        "compliance_summary": generate_compliance_summary(
            unique_findings, checked_policies
        ),
        "audit_coverage": coverage,
        "remediation_plan": generate_remediation_plan(unique_findings),
    }
