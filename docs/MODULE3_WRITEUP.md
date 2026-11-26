# Module 3: Compliance and Reporting Engine

## 1. Overview

Module 3 is responsible for processing security audit results,
calculating weighted risk scores, evaluating security compliance
and generating structured security reports.

The module is designed to process HTTP findings from Member 1
and typed TLS and HTTPS auditor results from Member 2.

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

Coverage is recorded as `COMPLETED` or `INCOMPLETE`. A timeout, client
restriction, unprobed protocol, inconclusive result, or rejected input can
leave coverage incomplete without establishing a vulnerability. Redirect
coverage records the source response and first-hop outcome. A parsed
destination remains `not_attempted` for verification.

The integration does not mark POL-009 as checked for a PASS. It can report a
FAIL from a mapped finding. Otherwise POL-009 remains `NOT_CHECKED`, including
for an HTTP-only report with a completed first-hop observation. A low risk
score measures the findings observed and can coexist with incomplete coverage.

## 7. Duplicate Handling

General findings use the check ID and evidence as the duplicate key. The
highest severity is retained when keys match. Certificate verification
failures use the check ID and validated hostname/IP and port. Observations
without an attributable endpoint remain separate. For a matching endpoint,
known verification codes are retained once each in numeric order in the
internal finding evidence. The risk score counts the finding once. JSON and
HTML omit the internal evidence field.

## 8. Remediation Plan

The engine builds recommendations from the mapped findings' remediation
text. It deduplicates findings, orders them by severity weight, and records
priority, check ID, severity, title, action, and risk score.

## 9. Report Generation

The JSON report uses strict serialization (`allow_nan=False`) and document
schema version 1. That document schema is separate from the Member 2 adapter
envelope. The HTML report uses Jinja2 automatic escaping. Both display
findings, severity, risk, policy status, coverage, and prioritised remediation.
Both use local timestamped files in the ignored `reports/` directory.

The writers omit finding evidence and references and redact recognised
credential patterns in finding and remediation text. Pattern matching has
limited coverage. Review reports before sharing.

## 10. Integration Contract

`integrate_audit_results(http_findings, tls_inputs, checked_http_policies,
require_https_upgrade=False)` processes observations for one target. Member 1
provides shared `Finding` objects. Member 2 provides typed auditor results as
`(kind, result)` pairs. The integration boundary invokes
`to_safe_audit_report` before mapping or scoring and rejects caller-supplied
report envelopes. An adapter rejection creates an incomplete coverage entry
without a finding or a raw-result fallback. Valid results from other
operations remain usable.

The CLI supplies authorised observations and adds the approved source origin
and its coverage status. The function returns findings, risk and compliance
summaries, coverage, and remediation for the two report writers. The shared
finding key and report contract are single-target. Do not combine observations
from unrelated targets in one call.

## 11. Verification

Step 41D.1 passed 63 focused Member 3 tests. Step 42C.1 separately verified the
HTTP-only CLI reporting contract with offline doubles. The historical Step
44.1 baseline passed 900 tests (680 Member 2 and 220 remaining integration).
Final Step 46C verification of `b47bca5b965ac80fd6a629489075e6638b009a42`
passed **919 unique tests** across two non-overlapping guarded partitions
(680 designated Member 2 and 239 remaining integration). Both exited 0
with zero failures, skips, xfails, or xpasses. All 40 required Member 2
loopback identities passed setup, call, and teardown. All 900 previous
identities were preserved, with 19 additions.

The live loopback CLI reconfirmed mandatory adaptation, first-hop reporting,
and certificate failure deduplication. The HTTP audit left
`POL-009=NOT_CHECKED`. With a temporary test-scoped CA, the trusted HTTPS
audit verified TLS 1.2 and 1.3 and wrote partial JSON and HTML reports.
Legacy protocols remained unprobed, so the intended exit code was 1 and
`POL-009` remained `NOT_CHECKED`. The default-trust run wrote partial reports
with one deduplicated certificate failure and `POL-009=FAIL`.
[Final demonstration results](../README.md#local-demonstration)

```powershell
python -B -m pytest --disable-plugin-autoload -p no:cacheprovider -o addopts= -q tests/test_member3.py tests/test_member3_reporting.py
python -B -m ruff check --no-cache webguard/core webguard/reporting tests/test_member3.py tests/test_member3_reporting.py
```
