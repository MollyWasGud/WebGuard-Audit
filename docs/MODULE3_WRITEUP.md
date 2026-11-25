# Module 3: Compliance and Reporting Engine

## 1. Overview

Module 3 is responsible for processing security audit results,
calculating weighted risk scores, evaluating security compliance
and generating structured security reports.

The module is designed to process HTTP findings from Member 1
and validated TLS and HTTPS audit results from Member 2.

## 2. Module Objectives

- Calculate weighted security risk scores.
- Classify findings according to their severity.
- Evaluate security compliance policies.
- Prevent duplicate findings from increasing risk scores.
- Identify incomplete audit coverage.
- Generate prioritised remediation recommendations.
- Generate local JSON and HTML security reports.
- Reduce sensitive information exposure in generated reports.

## 3. Module Components

| File | Function |
|---|---|
| risk_scoring.py | Calculates weighted risk scores. |
| policy.py | Evaluates security compliance policies. |
| tls_findings.py | Converts validated TLS results into findings. |
| coverage.py | Evaluates audit completeness. |
| audit_integration.py | Combines audit processing functions. |
| remediation.py | Prioritises security recommendations. |
| json_report.py | Generates structured JSON reports. |
| html_report.py | Generates readable HTML reports. |
| sanitizer.py | Redacts recognised credential patterns. |
| audit_report.html | Defines the HTML report layout. |

## 4. Weighted Risk Scoring

The system assigns a numerical weight to each severity level.

| Severity | Weight |
|---|---:|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

The total risk score is calculated by adding the weights of
unique security findings.

### Overall Risk Classification

| Total Risk Score | Classification |
|---|---|
| 20 and above | CRITICAL |
| 7–19 | HIGH |
| 4–6 | MEDIUM |
| 1–3 | LOW |
| 0 | INFO |

A confirmed CRITICAL finding automatically produces an overall
CRITICAL classification.

The scoring method is a custom weighted model developed for
WebGuard Audit and is not an official CVSS calculation.

## 5. Compliance Policy Evaluation

The module evaluates nine internal security policies.

| Policy ID | Security Policy |
|---|---|
| POL-001 | HSTS Protection |
| POL-002 | Content Type Protection |
| POL-003 | Clickjacking Protection |
| POL-004 | Referrer Protection |
| POL-005 | CORS Configuration |
| POL-006 | Content Security Policy |
| POL-007 | Information Disclosure |
| POL-008 | Cookie Security |
| POL-009 | TLS and HTTPS Security |

### Compliance Status

- PASS: The security requirement was explicitly checked
  and satisfied.
- FAIL: A matching policy violation was detected.
- NOT_CHECKED: The requirement was not evaluated or
  sufficient evidence was unavailable.

These policies represent internal project security requirements
and do not constitute formal regulatory certification.

## 6. Audit Coverage

Audit coverage distinguishes usable audit evidence from
incomplete or unsuccessful audit observations.

The supported coverage statuses are:

- COMPLETED
- INCOMPLETE

Connection timeouts, client restrictions and inconclusive
observations are not automatically classified as vulnerabilities.

Completed coverage does not automatically establish compliance.

## 7. Duplicate Handling

Duplicate findings are identified using their check ID and
evidence.

When matching findings contain different severity levels,
the finding with the highest severity is retained.

Certificate verification failures with matching endpoints
and verification codes can be consolidated to avoid repeated
risk scoring.

## 8. Remediation Plan

The remediation engine arranges recommendations from the
highest to the lowest severity.

Each recommendation includes:

- Priority number
- Security check ID
- Severity
- Finding title
- Recommended action
- Risk score

Existing recommendations supplied by the auditors are reused.

## 9. Report Generation

### JSON Report

The JSON report provides structured audit information suitable
for further processing and analysis.

### HTML Report

The HTML report provides a browser-based security dashboard
containing:

- Risk overview
- Severity distribution
- Compliance assessment
- Security findings
- Audit coverage
- Prioritised remediation plan

Reports are generated locally inside the reports directory.
The HTML report can be viewed offline using a web browser.

## 10. Security Controls

### Data Minimisation

Unnecessary evidence and reference fields are excluded
from the generated reports.

### Sensitive Data Sanitisation

Recognisable passwords, API keys, access tokens and Bearer
tokens are redacted using pattern-based filtering.

### HTML Injection Protection

Jinja2 automatic HTML escaping is enabled to reduce the
risk of malicious content executing in HTML reports.

### Local Report Storage

Generated reports are saved locally and are not automatically
transmitted to external services.

### Git Privacy Protection

The reports directory is excluded using .gitignore to reduce
the risk of accidental report uploads.

## 11. Testing and Verification

Testing was performed using:

- Operating System: Windows
- Python: 3.15.2
- Pytest: 9.2.0
- Ruff: Code quality verification

### Automated Test Results

| Testing Category | Passed |
|---|---:|
| Risk scoring | 3 |
| Compliance evaluation | 3 |
| TLS findings converter | 2 |
| Audit coverage | 2 |
| Remediation engine | 1 |
| Audit integration | 2 |
| JSON reporting | 1 |
| HTML reporting | 1 |
| Security protection | 3 |
| Total | 18 |

Total tests: 18
Passed: 18
Failed: 0
Execution time: 0.55 seconds

All scoped Python files passed Ruff verification.

### Testing Commands

python -m pytest tests/test_member3.py tests/test_member3_reporting.py -v

python -m ruff check webguard/core webguard/reporting tests/test_member3.py tests/test_member3_reporting.py

## 12. Team Integration

The main integration function is:

integrate_audit_results(
    http_findings,
    tls_reports,
    checked_http_policies,
    require_https_upgrade=False
)

HTTP findings must use the shared Finding model.

TLS results must first be processed through Member 2's
to_safe_audit_report() adapter.

The integration function returns:

- Combined unique findings
- Risk summary
- Compliance summary
- Audit coverage
- Remediation plan

The processed result can then be supplied to:

- generate_json_report()
- generate_html_report()

Member 4 is responsible for connecting the modules through
the CLI and enforcing authorised target restrictions.

## 13. Current Limitations

- Automatic TLS compliance PASS evaluation remains pending.
- Actual compatibility with the integrated auditors requires
  further team testing.
- Target authorisation and endpoint verification must be
  enforced during final CLI integration.
- Credential sanitisation cannot detect every possible
  type of sensitive information.
- Severity assignments and TLS policy requirements require
  final team agreement.
- Authorised target metadata is not yet included in reports.
- Automated tests use simulated audit results and do not
  establish complete end-to-end system security.

## 14. Conclusion

Module 3 provides the core compliance evaluation, weighted
risk scoring, remediation prioritisation and reporting
functions for WebGuard Audit.

The implemented functions successfully passed all 18
individual automated tests. Final team integration and
end-to-end verification are required before the complete
system is considered ready for release.