"""Automated tests for Member 3's compliance and reporting engine."""

from unittest.mock import Mock

import pytest
from test_report_adapter import (
    availability,
    certificate,
    confirmed_protocol,
    connectivity,
    first_hop,
    http_probe,
    protocol_result,
)

from webguard.auditors import https, report_adapter
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

REJECTED_COVERAGE = {
    "audit_kind": "Rejected TLS input",
    "coverage_status": "INCOMPLETE",
    "data_quality_issues": 1,
}


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
    raw = connectivity() | {
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "tls_version": None,
        "cipher_suite": None,
        "verify_code": 62,
    }
    entry = ("tls_connectivity", raw)
    result = integrate_audit_results([], [entry, entry], set())

    assert len(result["findings"]) == 1
    assert result["risk_summary"]["total_risk_score"] == 7
    assert result["risk_summary"]["duplicates_removed"] == 1
    assert len(result["remediation_plan"]) == 1


def test_incomplete_tls_compliance():
    entry = ("tls_connectivity", connectivity())
    result = integrate_audit_results([], [entry], {"POL-009"})

    assert result["compliance_summary"]["policy_results"][-1]["status"] == "NOT_CHECKED"


@pytest.mark.parametrize(
    "envelope",
    [
        pytest.param(make_tls_report("certificate_verification_failed"), id="envelope"),
        pytest.param(
            {
                "schema_version": 1,
                "kind": "tls_connectivity",
                "data": connectivity() | {"failed_stage": "connect"},
                "issues": [],
            },
            id="contradictory-envelope",
        ),
        pytest.param(
            make_tls_report("certificate_verification_failed")
            | {"schema_version": True},
            id="boolean-schema",
        ),
        pytest.param(
            {"schema_version": 1, "kind": "tls_connectivity", "issues": []},
            id="missing-data",
        ),
        pytest.param(
            make_tls_report("ok") | {"kind": "unknown-kind"}, id="unsupported-kind"
        ),
    ],
)
def test_integration_rejects_caller_envelopes(envelope):
    result = integrate_audit_results([], [envelope], {"POL-009"})

    assert result["findings"] == []
    assert result["risk_summary"]["total_risk_score"] == 0
    assert result["audit_coverage"] == [REJECTED_COVERAGE]
    assert result["compliance_summary"]["policy_results"][-1]["status"] == "NOT_CHECKED"


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(
            ("tls_connectivity", connectivity() | {"failed_stage": "connect"}),
            id="contradictory-ok-connect",
        ),
        pytest.param(("tls_connectivity", {}), id="missing-raw-fields"),
        pytest.param(("tls_connectivity", []), id="invalid-raw-type"),
        pytest.param(("unknown-kind", connectivity()), id="invalid-kind"),
        pytest.param(("tls_connectivity",), id="malformed-record"),
        pytest.param(
            ("tls_connectivity", connectivity() | {"schema_version": True}),
            id="versioned-raw-input",
        ),
    ],
)
def test_integration_records_rejected_inputs(entry):
    result = integrate_audit_results([], [entry], {"POL-009"})

    assert result["audit_coverage"] == [REJECTED_COVERAGE]
    assert result["findings"] == []
    assert result["risk_summary"]["total_risk_score"] == 0
    assert result["compliance_summary"]["policy_results"][-1]["status"] == "NOT_CHECKED"


def test_integration_scores_only_valid_siblings():
    valid = ("tls_certificate", certificate())
    rejected = (
        "tls_connectivity",
        connectivity()
        | {
            "status": "certificate_verification_failed",
            "failed_stage": "handshake",
            "verify_code": 62,
        },
    )
    partial = (
        "https_availability",
        availability(200, False) | {"elapsed_ms": float("inf")},
    )
    result = integrate_audit_results([], [valid, rejected, partial], set())
    valid_only = integrate_audit_results([], [valid, partial], set())

    assert result["findings"] == valid_only["findings"]
    assert [f.check_id for f in result["findings"]] == ["TLS:expired"]
    assert result["risk_summary"] == valid_only["risk_summary"]
    assert result["risk_summary"]["total_risk_score"] == 7
    complete, rejected_coverage, incomplete = result["audit_coverage"]
    assert complete["coverage_status"] == "COMPLETED"
    assert rejected_coverage == REJECTED_COVERAGE
    assert incomplete == {
        "audit_kind": "https_availability",
        "coverage_status": "INCOMPLETE",
        "data_quality_issues": 1,
    }


@pytest.mark.parametrize(
    ("kind", "raw", "finding", "status"),
    [
        pytest.param(
            "tls_connectivity",
            connectivity(),
            None,
            "COMPLETED",
            id="connectivity",
        ),
        pytest.param(
            "tls_certificate",
            certificate(),
            "TLS:expired",
            "COMPLETED",
            id="certificate",
        ),
        pytest.param(
            "tls_protocols",
            protocol_result(
                confirmed_protocol("TLSv1.2"),
                confirmed_protocol("TLSv1.3"),
                confirmed_protocol("TLSv1"),
                not_probed=("TLSv1.1",),
            ),
            "TLS:legacy-version",
            "INCOMPLETE",
            id="protocols",
        ),
        pytest.param(
            "https_availability",
            availability(503, False),
            None,
            "COMPLETED",
            id="availability",
        ),
        pytest.param(
            "http_redirect",
            first_hop("https", "downgrade", "http", 302, ("https_to_http_downgrade",)),
            "HTTPS:downgrade",
            "COMPLETED",
            id="redirect",
        ),
    ],
)
def test_integration_adapts_each_result_kind(monkeypatch, kind, raw, finding, status):
    adapter = Mock(wraps=report_adapter.to_safe_audit_report)
    monkeypatch.setattr(report_adapter, "to_safe_audit_report", adapter)

    result = integrate_audit_results([], [(kind, raw)], set())

    adapter.assert_called_once_with(kind, raw)
    assert [f.check_id for f in result["findings"]] == ([finding] if finding else [])
    expected = {"audit_kind": kind, "coverage_status": status, "data_quality_issues": 0}
    if kind == "http_redirect":
        expected.update(
            redirect_outcome="downgrade",
            probe_outcome="available",
            destination_verification="not_attempted",
        )
    assert result["audit_coverage"] == [expected]


def test_integration_propagates_unexpected_adapter_errors(monkeypatch):
    adapter = Mock(side_effect=RuntimeError("Unexpected adapter failure"))
    monkeypatch.setattr(report_adapter, "to_safe_audit_report", adapter)

    with pytest.raises(RuntimeError, match="^Unexpected adapter failure$"):
        integrate_audit_results([], [("tls_connectivity", connectivity())], set())


def certificate_verification_input(hostname, port, code):
    raw = connectivity() | {
        "hostname": hostname,
        "port": port,
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "tls_version": None,
        "cipher_suite": None,
    }
    if code is None:
        del raw["verify_code"]
    else:
        raw["verify_code"] = code
    return "tls_connectivity", raw


@pytest.mark.parametrize(
    ("first_code", "second_code", "retained"),
    [
        pytest.param(62, 62, 62, id="same-code"),
        pytest.param(62, None, 62, id="second-code-omitted"),
        pytest.param(None, 62, 62, id="first-code-omitted"),
        pytest.param(62, 10, 10, id="different-codes"),
        pytest.param(10, 62, 10, id="different-codes-reversed"),
    ],
)
def test_certificate_verification_deduplicates_by_canonical_endpoint(
    first_code, second_code, retained
):
    first = certificate_verification_input("Example.test.", 443, first_code)
    second = certificate_verification_input("example.test", 443, second_code)

    result = integrate_audit_results([], [first, second], set())

    assert len(result["findings"]) == 1
    assert result["findings"][0].severity == "HIGH"
    assert f"verify_code={retained}" in result["findings"][0].evidence
    assert result["risk_summary"]["total_risk_score"] == 7
    assert result["risk_summary"]["duplicates_removed"] == 1


@pytest.mark.parametrize(
    ("first_endpoint", "second_endpoint", "count"),
    [
        pytest.param(("one.test", 443), ("two.test", 443), 2, id="different-hosts"),
        pytest.param(
            ("example.test", 443), ("example.test", 8443), 2, id="different-ports"
        ),
        pytest.param(
            ("2001:db8:0:0:0:0:0:1", 443), ("2001:db8::1", 443), 1, id="same-ipv6"
        ),
        pytest.param(
            ("2001:db8::1", 443), ("2001:db8::2", 443), 2, id="different-ipv6"
        ),
        pytest.param(("192.0.2.1", 443), ("::ffff:192.0.2.1", 443), 2, id="ipv4-ipv6"),
        pytest.param(
            ("bad host", 443), ("other bad host", 443), 2, id="redacted-hosts"
        ),
        pytest.param(
            ("example.test", 0), ("example.test", 65536), 2, id="redacted-ports"
        ),
    ],
)
def test_certificate_verification_preserves_endpoint_boundaries(
    first_endpoint, second_endpoint, count
):
    inputs = [
        certificate_verification_input(*first_endpoint, 62),
        certificate_verification_input(*second_endpoint, 62),
    ]

    result = integrate_audit_results([], inputs, set())

    assert len(result["findings"]) == count
    assert result["risk_summary"]["total_risk_score"] == count * 7


def test_certificate_verification_preserves_other_checks_and_rejects_bad_input():
    verification = certificate_verification_input("example.test", 443, 62)
    rejected = ("tls_connectivity", verification[1] | {"tls_version": "TLSv1.3"})
    expiry = ("tls_certificate", certificate())

    result = integrate_audit_results([], [verification, rejected, expiry], set())

    assert [f.check_id for f in result["findings"]] == [
        "TLS:certificate-verification",
        "TLS:expired",
    ]
    assert result["risk_summary"]["total_risk_score"] == 14
    assert result["risk_summary"]["duplicates_removed"] == 0
    assert result["audit_coverage"][1] == REJECTED_COVERAGE


@pytest.mark.parametrize(
    ("scheme", "status", "locations", "outcome", "finding", "completed"),
    [
        pytest.param(
            "http", 302, ["https://example.test/"], "upgrade", None, True, id="upgrade"
        ),
        pytest.param(
            "https",
            302,
            ["http://example.test/"],
            "downgrade",
            "HTTPS:downgrade",
            True,
            id="downgrade",
        ),
        pytest.param(
            "http", 200, [], "no_redirect", "HTTPS:no-upgrade", True, id="no-upgrade"
        ),
        pytest.param(
            "https",
            307,
            ["/other"],
            "same_scheme_redirect",
            None,
            True,
            id="same-scheme",
        ),
        pytest.param("http", 302, [], "missing_location", None, False, id="missing"),
        pytest.param("http", 302, [" "], "empty_location", None, False, id="empty"),
        pytest.param(
            "http", 302, ["/a", "/b"], "ambiguous_location", None, False, id="ambiguous"
        ),
        pytest.param(
            "http", 302, ["/%XX"], "invalid_location", None, False, id="malformed"
        ),
        pytest.param(
            "http",
            302,
            ["ftp://example.test/"],
            "unsupported_scheme",
            None,
            False,
            id="unsupported-scheme",
        ),
        pytest.param(
            "http",
            305,
            [],
            "unsupported_redirect_status",
            None,
            False,
            id="unsupported-status",
        ),
    ],
)
def test_redirect_coverage_distinguishes_first_hop_outcomes(
    monkeypatch, scheme, status, locations, outcome, finding, completed
):
    response = http_probe() | {"http_status": status}
    head = Mock(return_value=(response, locations))
    monkeypatch.setattr(https, "_probe_response_head", head)
    raw = https.audit_http_redirect("example.test", source_scheme=scheme)
    head.assert_called_once()

    result = integrate_audit_results(
        [], [("http_redirect", raw)], set(), require_https_upgrade=True
    )

    assert result["audit_coverage"] == [
        {
            "audit_kind": "http_redirect",
            "coverage_status": "COMPLETED" if completed else "INCOMPLETE",
            "data_quality_issues": 0,
            "redirect_outcome": outcome,
            "probe_outcome": "available",
            "destination_verification": (
                "not_attempted"
                if outcome in {"upgrade", "downgrade", "same_scheme_redirect"}
                else None
            ),
        }
    ]
    assert [f.check_id for f in result["findings"]] == ([finding] if finding else [])
    if not completed:
        assert (
            result["compliance_summary"]["policy_results"][-1]["status"]
            == "NOT_CHECKED"
        )


def test_redirect_coverage_distinguishes_failure_rejection_and_redaction(monkeypatch):
    response = http_probe() | {
        "outcome": "timeout",
        "http_status": None,
        "failed_stage": "response",
    }
    monkeypatch.setattr(
        https, "_probe_response_head", Mock(return_value=(response, []))
    )
    failed = https.audit_http_redirect("example.test")
    rejected = first_hop("https", "downgrade", None, 302)
    redacted = first_hop("http", "upgrade", "https", 302)
    redacted["redirect"]["destination"]["hostname"] = "redacted host"

    result = integrate_audit_results(
        [], [("http_redirect", raw) for raw in [failed, rejected, redacted]], set()
    )

    failed_coverage, rejected_coverage, redacted_coverage = result["audit_coverage"]
    assert failed_coverage == {
        "audit_kind": "http_redirect",
        "coverage_status": "INCOMPLETE",
        "data_quality_issues": 0,
        "redirect_outcome": "not_evaluated",
        "probe_outcome": "timeout",
        "destination_verification": None,
    }
    assert rejected_coverage == REJECTED_COVERAGE
    assert redacted_coverage == {
        "audit_kind": "http_redirect",
        "coverage_status": "INCOMPLETE",
        "data_quality_issues": 1,
        "redirect_outcome": "upgrade",
        "probe_outcome": "available",
        "destination_verification": "not_attempted",
    }
    assert result["findings"] == []
    assert result["risk_summary"]["total_risk_score"] == 0
    assert result["compliance_summary"]["policy_results"][-1]["status"] == "NOT_CHECKED"
