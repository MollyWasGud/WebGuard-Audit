import json
from copy import deepcopy

import pytest

from webguard.auditors import https, tls
from webguard.auditors.report_adapter import ReportInputError


class OpaqueInput:
    def __str__(self):
        raise AssertionError("reporting called str() on an arbitrary object")

    def __repr__(self):
        raise AssertionError("reporting called repr() on an arbitrary object")


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("reporting test attempted network or TLS activity")

    for target in (
        "socket.getaddrinfo",
        "socket.create_connection",
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "ssl.create_default_context",
        "ssl.SSLContext.wrap_socket",
        "ssl.SSLSocket.do_handshake",
        "http.client.HTTPConnection.request",
    ):
        monkeypatch.setattr(target, blocked)


@pytest.fixture
def adapter():
    def adapt(kind, raw):
        from webguard.auditors.report_adapter import to_safe_audit_report

        return to_safe_audit_report(kind, raw)

    return adapt


_AUDITORS = [
    ("tls_connectivity", tls.audit_tls_connectivity),
    ("tls_certificate", tls.audit_tls_certificate),
    ("tls_protocols", tls.audit_tls_protocols),
    ("https_availability", https.audit_https_availability),
    ("http_redirect", https.audit_http_redirect),
]


@pytest.mark.parametrize(("kind", "audit"), _AUDITORS)
@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param(
            "hostname", "https://user:private-marker@example.test/", id="creds"
        ),
        pytest.param("hostname", "private-marker\x00.example.test", id="control"),
        pytest.param("hostname", OpaqueInput(), id="object"),
        pytest.param("port", 1 << 15000, id="huge-port"),
        pytest.param("port", True, id="boolean-port"),
        pytest.param("port", "443", id="string-port"),
        pytest.param("port", 65536, id="port-out-of-range"),
        pytest.param("port", float("nan"), id="nan-port"),
        pytest.param("port", float("inf"), id="positive-infinite-port"),
        pytest.param("port", -float("inf"), id="negative-infinite-port"),
    ],
)
def test_reports_from_all_auditors_serialize_rejected_inputs(
    adapter, kind, audit, field, value
):
    raw = audit(**({"hostname": "Example.test.", "port": 443} | {field: value}))
    report = adapter(kind, raw)

    assert report["schema_version"] == 1
    assert report["kind"] == kind
    data = report["data"]
    if kind == "tls_certificate":
        assert data["certificate_status"] == "not_collected"
        data = data["connectivity"]
    if kind == "http_redirect":
        assert data["probe"]["outcome"] == "invalid_input"
        assert data["redirect"]["outcome"] == "not_evaluated"
        target = data["source"]
    elif kind == "https_availability":
        assert data["outcome"] == "invalid_input"
        target = data["target"]
    else:
        assert data["status"] == "invalid_input"
        target = data["target"] if kind == "tls_protocols" else data

    assert target[field] is None
    if field == "hostname":
        assert target["port"] == 443
    else:
        assert target["hostname"] == "example.test"
    assert "private-marker" not in json.dumps(report, allow_nan=False)


def test_raw_tls_targets_are_redacted_with_stable_issues(adapter):
    hostname = OpaqueInput()
    port = 1 << 15000
    raw = tls.audit_tls_connectivity(hostname, port)

    report = adapter("tls_connectivity", raw)

    assert report["data"]["hostname"] is report["data"]["port"] is None
    assert {"field": "hostname", "code": "invalid_value"} in report["issues"]
    assert {"field": "port", "code": "invalid_value"} in report["issues"]
    assert raw["hostname"] is hostname and raw["port"] is port
    json.dumps(report, allow_nan=False)


def connectivity():
    return {
        "hostname": "Example.test.",
        "port": 443,
        "status": "ok",
        "failed_stage": None,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "error_message": None,
        "verify_code": None,
    }


def certificate():
    return {
        "connectivity": connectivity(),
        "certificate_status": "ok",
        "certificate_error": None,
        "certificate": {
            "subject": "CN=example.test",
            "issuer": "CN=Test CA",
            "serial_number": "1a2b",
            "sans": [
                {"type": "dns", "value": "*.example.test"},
                {"type": "ip", "value": "192.0.2.1"},
            ],
            "not_valid_before": "2024-01-01T00:00:00+00:00",
            "not_valid_after": "2025-01-01T00:00:00+00:00",
            "remaining_seconds": -0.5,
            "expiration_status": "expired",
            "sha256_fingerprint": "ab" * 32,
        },
    }


def http_probe():
    return {
        "outcome": "available",
        "http_status": 503,
        "failed_stage": None,
        "verify_code": None,
        "elapsed_ms": 3.25,
    }


def test_connectivity_preserves_failure_and_generates_safe_diagnostic(adapter):
    raw = connectivity() | {
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "tls_version": None,
        "cipher_suite": None,
        "verify_code": 62,
        "error_message": "private-marker https://user:secret@example.test/\x1b",
    }

    report = adapter("tls_connectivity", raw)

    assert report["data"] == raw | {
        "hostname": "example.test",
        "error_message": "Certificate verification failed.",
    }
    assert "private-marker" not in json.dumps(report, allow_nan=False)


def test_certificate_preserves_verified_metadata_and_copies_nested_data(adapter):
    raw = certificate()
    original = deepcopy(raw)

    report = adapter("tls_certificate", raw)

    assert report["data"]["certificate_status"] == "ok"
    assert report["data"]["connectivity"] == connectivity() | {
        "hostname": "example.test"
    }
    assert report["data"]["certificate"] == original["certificate"]
    assert json.loads(json.dumps(report, allow_nan=False)) == report
    report["data"]["certificate"]["sans"][0]["value"] = "other.test"
    assert raw == original


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        pytest.param(
            "subject", "CN=private-marker\x1b", "unsafe_text", id="subject-control"
        ),
        pytest.param(
            "issuer",
            "CN=https://user:private-marker@example.test/",
            "unsafe_text",
            id="issuer-credentials",
        ),
        pytest.param("issuer", "x" * 20000, "value_too_long", id="oversized-issuer"),
        pytest.param(
            "serial_number", OpaqueInput(), "invalid_value", id="serial-object"
        ),
        pytest.param(
            "remaining_seconds", float("nan"), "invalid_value", id="nan-validity"
        ),
        pytest.param(
            "sha256_fingerprint", "private-marker", "invalid_value", id="fingerprint"
        ),
    ],
)
def test_certificate_issues_are_field_specific(adapter, field, value, code):
    raw = certificate()
    raw["certificate"][field] = value

    report = adapter("tls_certificate", raw)

    assert report["data"]["certificate_status"] == "ok"
    assert report["data"]["certificate"] == certificate()["certificate"] | {field: None}
    assert {"field": f"certificate.{field}", "code": code} in report["issues"]
    assert "private-marker" not in json.dumps(report, allow_nan=False)


def test_protocol_preserves_negotiated_evidence_and_recommendation(adapter):
    probe = {
        "requested_version": "TLSv1.2",
        "outcome": "confirmed_supported",
        "evidence_code": "verified_handshake",
        "negotiated_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "secret_bits": 128,
        "failed_stage": None,
        "error_message": None,
        "verify_code": None,
    }
    rejection = {
        "requested_version": "TLSv1.3",
        "outcome": "server_rejected",
        "evidence_code": "TLSV1_ALERT_PROTOCOL_VERSION",
        "negotiated_version": None,
        "cipher_suite": None,
        "secret_bits": None,
        "failed_stage": "handshake",
        "error_message": "private-marker",
        "verify_code": None,
    }
    raw = {
        "target": {"hostname": "example.test", "port": 443},
        "status": "ok",
        "error_message": None,
        "probes": [probe, rejection],
        "not_probed": ["TLSv1", "TLSv1.1"],
        "recommendations": [{"code": "review_tls_1_3", "message": "private-marker"}],
    }

    report = adapter("tls_protocols", raw)

    data = report["data"]
    assert data["probes"][0] == probe
    assert data["probes"][1]["outcome"] == "server_rejected"
    assert data["probes"][1]["evidence_code"] == "TLSV1_ALERT_PROTOCOL_VERSION"
    assert data["probes"][1]["error_message"]
    assert data["not_probed"] == raw["not_probed"]
    assert [advice["code"] for advice in data["recommendations"]] == ["review_tls_1_3"]
    assert "private-marker" not in json.dumps(report, allow_nan=False)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("elapsed_ms", -float("inf"), id="infinite-elapsed"),
        pytest.param("http_status", True, id="boolean-status"),
        pytest.param("http_status", 600, id="status-out-of-range"),
        pytest.param("verify_code", 1 << 15000, id="oversized-verify-code"),
        pytest.param("verify_code", OpaqueInput(), id="object-verify-code"),
    ],
)
def test_https_reports_invalid_optional_evidence(adapter, field, value):
    raw = http_probe() | {
        "target": {"hostname": "example.test", "port": 443},
        "is_redirect": False,
    }
    raw[field] = value

    report = adapter("https_availability", raw)

    assert report["data"] == (raw | {field: None})
    assert {"field": field, "code": "invalid_value"} in report["issues"]
    json.dumps(report, allow_nan=False)


def test_redirect_preserves_unverified_destination_origin_and_advice(adapter):
    raw = {
        "source": {"scheme": "https", "hostname": "example.test", "port": 443},
        "probe": http_probe() | {"http_status": 302},
        "redirect": {
            "outcome": "downgrade",
            "same_host": False,
            "port_changed": True,
            "destination": {
                "scheme": "http",
                "hostname": "xn--bcher-kva.test",
                "port": 80,
                "verification": "not_attempted",
                "location": "http://user:private-marker@example.test/?token=secret",
            },
        },
        "recommendations": ["https_to_http_downgrade", "review_cross_host_redirect"],
    }

    report = adapter("http_redirect", raw)

    data = report["data"]
    assert data["probe"]["http_status"] == 302
    assert data["redirect"]["outcome"] == "downgrade"
    assert data["redirect"]["destination"] == {
        "scheme": "http",
        "hostname": "xn--bcher-kva.test",
        "port": 80,
        "verification": "not_attempted",
    }
    assert data["recommendations"] == raw["recommendations"]
    assert "private-marker" not in json.dumps(report, allow_nan=False)


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        pytest.param("private-marker", connectivity(), id="unknown-kind"),
        pytest.param(OpaqueInput(), connectivity(), id="object-kind"),
        pytest.param("https_availability", connectivity(), id="mismatched-kind"),
        pytest.param(
            "tls_connectivity",
            connectivity() | {"status": "private-marker"},
            id="unknown-status",
        ),
        pytest.param(
            "tls_connectivity",
            connectivity() | {"status": OpaqueInput()},
            id="object-status",
        ),
    ],
)
def test_invalid_required_report_input_has_fixed_error(adapter, kind, raw):
    with pytest.raises(ValueError, match=r"^Invalid audit report input$"):
        adapter(kind, raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [("verify_code", 62), ("failed_stage", "handshake")],
)
def test_semantic_connectivity_success_conflicts_with_failure(adapter, field, value):
    raw = connectivity() | {field: value}
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_connectivity", raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [("tls_version", "TLSv1.3"), ("cipher_suite", "TLS_AES_256_GCM_SHA384")],
)
def test_semantic_connectivity_failure_conflicts_with_negotiation(
    adapter, field, value
):
    raw = connectivity() | {
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "verify_code": 62,
        "tls_version": None,
        "cipher_suite": None,
    }
    raw[field] = value
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_connectivity", raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("remaining_seconds", 60.0, id="expired-positive-remaining"),
        pytest.param(
            "not_valid_before", "2025-01-02T00:00:00+00:00", id="reversed-dates"
        ),
        pytest.param(
            "expiration_status", "expiring_soon", id="expiring-negative-remaining"
        ),
        pytest.param("expiration_status", "current", id="current-negative-remaining"),
    ],
)
def test_semantic_certificate_rejects_contradictions(adapter, field, value):
    raw = certificate()
    raw["certificate"][field] = value
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_certificate", raw)


@pytest.mark.parametrize("status", ["expiring_soon", "current"])
def test_semantic_certificate_zero_seconds_cannot_be_unexpired(adapter, status):
    raw = certificate()
    raw["certificate"]["remaining_seconds"] = 0.0
    raw["certificate"]["expiration_status"] = status
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_certificate", raw)


@pytest.mark.parametrize(
    ("status", "seconds"),
    [("expired", -0.5), ("expired", 0.0), ("expiring_soon", 60.0), ("current", 60.0)],
)
def test_semantic_certificate_preserves_consistent_expiry(adapter, status, seconds):
    raw = certificate()
    raw["certificate"]["expiration_status"] = status
    raw["certificate"]["remaining_seconds"] = seconds
    raw["certificate"]["subject"] = "CN=unsafe\x00.example.test"

    report = adapter("tls_certificate", raw)

    assert report["data"]["certificate"] == raw["certificate"] | {"subject": None}
    assert {"field": "certificate.subject", "code": "unsafe_text"} in report["issues"]
    json.dumps(report, allow_nan=False)


def test_semantic_certificate_reports_null_san_without_losing_valid_evidence(adapter):
    raw = certificate()
    neighbors = raw["certificate"]["sans"]
    raw["certificate"]["sans"] = [None, *neighbors]

    report = adapter("tls_certificate", raw)

    assert report["data"]["certificate_status"] == "ok"
    assert report["data"]["certificate"] == raw["certificate"]
    assert report["data"]["certificate"]["sans"][1:] == neighbors
    assert {"field": "certificate.sans[0]", "code": "invalid_value"} in report["issues"]
    json.dumps(report, allow_nan=False)


def confirmed_protocol(version):
    return {
        "requested_version": version,
        "outcome": "confirmed_supported",
        "evidence_code": "verified_handshake",
        "negotiated_version": version,
        "cipher_suite": (
            "TLS_AES_128_GCM_SHA256" if version == "TLSv1.3" else "ECDHE-RSA-AES128-SHA"
        ),
        "secret_bits": 128,
        "failed_stage": None,
        "error_message": None,
        "verify_code": None,
    }


def unconfirmed_protocol(version, outcome, code, stage):
    return confirmed_protocol(version) | {
        "outcome": outcome,
        "evidence_code": code,
        "failed_stage": stage,
        "negotiated_version": None,
        "cipher_suite": None,
        "secret_bits": None,
    }


def protocol_result(*probes, not_probed=("TLSv1", "TLSv1.1"), recommendations=()):
    messages = {
        "disable_legacy_tls": "Disable the legacy TLS versions confirmed by verified handshakes.",
        "review_tls_1_3": "Review TLS 1.3 availability for the audited endpoint.",
    }
    return {
        "target": {"hostname": "example.test", "port": 443},
        "status": "ok",
        "error_message": None,
        "probes": list(probes),
        "not_probed": list(not_probed),
        "recommendations": [
            {"code": code, "message": messages[code]} for code in recommendations
        ],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("failed_stage", "handshake"),
        ("verify_code", 62),
        ("negotiated_version", "TLSv1.3"),
    ],
)
def test_semantic_protocol_support_requires_consistent_evidence(adapter, field, value):
    raw = protocol_result(
        confirmed_protocol("TLSv1.2") | {field: value}, confirmed_protocol("TLSv1.3")
    )
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


@pytest.mark.parametrize(
    "code",
    ["disable_legacy_tls", "review_tls_1_3"],
)
def test_semantic_protocol_advice_requires_confirming_probes(adapter, code):
    raw = protocol_result(
        confirmed_protocol("TLSv1.2"),
        unconfirmed_protocol("TLSv1.3", "inconclusive", "timeout", "handshake"),
    )
    raw["recommendations"] = [{"code": code, "message": ""}]
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def test_semantic_protocol_preserves_unconfirmed_outcomes(adapter):
    raw = protocol_result(
        confirmed_protocol("TLSv1.2")
        | {
            "outcome": "inconclusive",
            "evidence_code": "unexpected_negotiated_version",
            "negotiated_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
        },
        unconfirmed_protocol(
            "TLSv1.3", "server_rejected", "TLSV1_ALERT_PROTOCOL_VERSION", "handshake"
        ),
        unconfirmed_protocol(
            "TLSv1", "client_restricted", "client_version_policy", None
        ),
        unconfirmed_protocol(
            "TLSv1.1", "client_restricted", "NO_PROTOCOLS_AVAILABLE", "handshake"
        ),
        not_probed=(),
    )

    data = adapter("tls_protocols", raw)["data"]

    assert [probe["outcome"] for probe in data["probes"]] == [
        "inconclusive",
        "server_rejected",
        "client_restricted",
        "client_restricted",
    ]
    assert data["probes"][0]["negotiated_version"] == "TLSv1.3"
    assert data["recommendations"] == []


def test_semantic_protocol_rejects_certificate_failure_as_client_restricted(adapter):
    probe = unconfirmed_protocol(
        "TLSv1.3", "inconclusive", "CERTIFICATE_VERIFY_FAILED", "handshake"
    )
    probe["verify_code"] = 62
    raw = protocol_result(confirmed_protocol("TLSv1.2"), probe)
    accepted = adapter("tls_protocols", raw)
    assert accepted["issues"] == []
    assert accepted["data"]["probes"][1]["verify_code"] == 62

    probe["outcome"] = "client_restricted"

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def test_semantic_protocol_preserves_supported_advice_and_not_probed_versions(adapter):
    tls12 = confirmed_protocol("TLSv1.2")
    tls13 = unconfirmed_protocol(
        "TLSv1.3", "server_rejected", "TLSV1_ALERT_PROTOCOL_VERSION", "handshake"
    )
    modern_only = protocol_result(tls12, tls13, recommendations=("review_tls_1_3",))
    legacy_confirmed = protocol_result(
        tls12,
        tls13,
        confirmed_protocol("TLSv1"),
        unconfirmed_protocol(
            "TLSv1.1", "client_restricted", "client_version_policy", None
        ),
        not_probed=(),
        recommendations=("disable_legacy_tls", "review_tls_1_3"),
    )

    for raw in (modern_only, legacy_confirmed):
        data = adapter("tls_protocols", raw)["data"]
        assert data["not_probed"] == raw["not_probed"]
        assert [item["code"] for item in data["recommendations"]] == [
            item["code"] for item in raw["recommendations"]
        ]


def availability(status, is_redirect):
    return http_probe() | {
        "target": {"hostname": "example.test", "port": 443},
        "http_status": status,
        "is_redirect": is_redirect,
    }


@pytest.mark.parametrize(
    ("status", "expected"), [(200, False), (302, True), (304, False)]
)
def test_semantic_https_rejects_wrong_redirect_flag(adapter, status, expected):
    raw = availability(status, expected)
    raw["is_redirect"] = not expected
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("https_availability", raw)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, False),
        (300, True),
        (301, True),
        (302, True),
        (303, True),
        (304, False),
        (305, False),
        (306, False),
        (307, True),
        (308, True),
        (503, False),
    ],
)
def test_semantic_https_preserves_producer_status_classification(
    adapter, status, expected
):
    raw = availability(status, expected)
    raw["elapsed_ms"] = float("inf")
    report = adapter("https_availability", raw)
    assert report["data"] == raw | {"elapsed_ms": None}
    assert {"field": "elapsed_ms", "code": "invalid_value"} in report["issues"]
    json.dumps(report, allow_nan=False)


def first_hop(source_scheme, outcome, destination_scheme, status, recommendations=()):
    default_ports = {"http": 80, "https": 443}
    destination = None
    if destination_scheme is not None:
        destination = {
            "scheme": destination_scheme,
            "hostname": "example.test",
            "port": default_ports[destination_scheme],
            "verification": "not_attempted",
        }
    return {
        "source": {
            "scheme": source_scheme,
            "hostname": "example.test",
            "port": default_ports[source_scheme],
        },
        "probe": http_probe() | {"http_status": status},
        "redirect": {
            "outcome": outcome,
            "destination": destination,
            "same_host": True if destination is not None else None,
            "port_changed": source_scheme != destination_scheme
            if destination is not None
            else None,
        },
        "recommendations": list(recommendations),
    }


@pytest.mark.parametrize(
    ("source", "outcome", "destination", "advice", "contradiction"),
    [
        pytest.param(
            "http", "upgrade", "https", (), "downgrade", id="upgrade-as-downgrade"
        ),
        pytest.param(
            "https",
            "downgrade",
            "http",
            ("https_to_http_downgrade",),
            "upgrade",
            id="downgrade-as-upgrade",
        ),
    ],
)
def test_semantic_redirect_rejects_wrong_scheme_classification(
    adapter, source, outcome, destination, advice, contradiction
):
    raw = first_hop(source, outcome, destination, 302, advice)
    raw["redirect"]["outcome"] = contradiction
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)


@pytest.mark.parametrize(
    "change", ["incompatible_http_status", "contradictory_destination_scheme"]
)
def test_semantic_redirect_rejects_conflicting_evidence(adapter, change):
    raw = first_hop("http", "upgrade", "https", 302)
    if change == "incompatible_http_status":
        raw["probe"]["http_status"] = 200
    else:
        raw["redirect"]["destination"]["scheme"] = "http"

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)


@pytest.mark.parametrize(
    "advice",
    [
        "https_to_http_downgrade",
        "review_https_upgrade",
        "review_cross_host_redirect",
        "review_unusual_redirect_port",
    ],
)
def test_semantic_redirect_rejects_unfounded_advice(adapter, advice):
    raw = first_hop("http", "upgrade", "https", 302)
    raw["recommendations"] = [advice]
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)


@pytest.mark.parametrize(
    ("source", "outcome", "destination", "status", "advice"),
    [
        ("http", "upgrade", "https", 300, ()),
        ("https", "downgrade", "http", 308, ("https_to_http_downgrade",)),
        ("http", "same_scheme_redirect", "http", 307, ("review_https_upgrade",)),
        ("http", "no_redirect", None, 304, ("review_https_upgrade",)),
        ("https", "unsupported_redirect_status", None, 305, ()),
        ("https", "unsupported_redirect_status", None, 306, ()),
        ("https", "missing_location", None, 302, ()),
    ],
)
def test_semantic_redirect_preserves_consistent_first_hop(
    adapter, source, outcome, destination, status, advice
):
    raw = first_hop(source, outcome, destination, status, advice)
    report = adapter("http_redirect", raw)
    assert report["data"] == raw
    if destination is not None:
        assert (
            report["data"]["redirect"]["destination"]["verification"] == "not_attempted"
        )
    json.dumps(report, allow_nan=False)


def test_semantic_redirect_rejects_downgrade_without_destination(adapter):
    raw = first_hop("https", "downgrade", "http", 302, ("https_to_http_downgrade",))
    accepted = adapter("http_redirect", raw)
    assert accepted["issues"] == []
    assert (
        accepted["data"]["redirect"]["destination"]["verification"] == "not_attempted"
    )

    raw["redirect"]["destination"] = None

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)


def test_semantic_redirect_preserves_cross_host_and_unusual_port_advice(adapter):
    raw = first_hop("http", "upgrade", "https", 302)
    raw["redirect"]["destination"].update(hostname="other.test", port=8443)
    raw["redirect"]["same_host"] = False
    raw["recommendations"] = [
        "review_cross_host_redirect",
        "review_unusual_redirect_port",
    ]

    assert adapter("http_redirect", raw)["data"] == raw


_SETUP_REPORT_MARKER = r"C:\synthetic\private-path password=setup-test-marker"
_SETUP_REPORT_DIAGNOSTIC = "Could not initialize the local TLS client context."


def setup_failure_raw(kind):
    if kind == "tls_connectivity":
        return connectivity() | {
            "status": "tls_setup_error",
            "failed_stage": "tls_setup",
            "error_message": _SETUP_REPORT_MARKER,
            "tls_version": None,
            "cipher_suite": None,
        }
    if kind == "tls_certificate":
        return {
            "connectivity": setup_failure_raw("tls_connectivity"),
            "certificate_status": "not_collected",
            "certificate_error": None,
            "certificate": None,
        }
    if kind == "tls_protocols":
        failed = unconfirmed_protocol(
            "TLSv1.3", "inconclusive", "tls_setup_error", "tls_setup"
        )
        failed["error_message"] = _SETUP_REPORT_MARKER
        return protocol_result(confirmed_protocol("TLSv1.2"), failed)

    failed = http_probe() | {
        "outcome": "tls_error",
        "http_status": None,
        "failed_stage": "tls_setup",
    }
    if kind == "https_availability":
        return availability(None, None) | failed
    raw = first_hop("https", "not_evaluated", None, None)
    raw["probe"] = failed
    return raw


@pytest.mark.parametrize(
    "kind",
    [
        "tls_connectivity",
        "tls_certificate",
        "tls_protocols",
        "https_availability",
        "http_redirect",
    ],
)
def test_context_setup_red_adapter_preserves_local_failure_and_raw_result(
    adapter, kind
):
    raw = setup_failure_raw(kind)
    original = deepcopy(raw)

    report = adapter(kind, raw)

    assert raw == original
    assert report["schema_version"] == 1
    assert report["kind"] == kind
    encoded = json.dumps(report, allow_nan=False)
    assert "setup-test-marker" not in encoded
    assert "private-path" not in encoded
    data = report["data"]
    if kind == "tls_certificate":
        assert data["certificate_status"] == "not_collected"
        assert data["certificate"] is None
        data = data["connectivity"]
    if kind in {"tls_connectivity", "tls_certificate"}:
        assert data["status"] == "tls_setup_error"
        assert data["failed_stage"] == "tls_setup"
        assert data["error_message"] == _SETUP_REPORT_DIAGNOSTIC
        assert (
            data["tls_version"] is data["cipher_suite"] is data["verify_code"] is None
        )
    elif kind == "tls_protocols":
        assert data["status"] == "ok"
        assert data["recommendations"] == []
        assert data["probes"][0] == raw["probes"][0]
        assert data["probes"][1] == raw["probes"][1] | {
            "error_message": _SETUP_REPORT_DIAGNOSTIC
        }
    else:
        if kind == "http_redirect":
            assert data["redirect"]["outcome"] == "not_evaluated"
            assert data["redirect"]["destination"] is None
            assert data["recommendations"] == []
            data = data["probe"]
        assert data["outcome"] == "tls_error"
        assert data["failed_stage"] == "tls_setup"
        assert data["http_status"] is data["verify_code"] is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "connection_error"),
        ("failed_stage", "handshake"),
        ("verify_code", 62),
        ("tls_version", "TLSv1.3"),
        ("cipher_suite", "TLS_AES_128_GCM_SHA256"),
    ],
)
def test_context_setup_red_adapter_rejects_contradictory_tls_failure(
    adapter, field, value
):
    raw = setup_failure_raw("tls_connectivity")
    raw[field] = value
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_connectivity", raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_code", "timeout"),
        ("failed_stage", "handshake"),
        ("outcome", "client_restricted"),
        ("verify_code", 62),
        ("negotiated_version", "TLSv1.3"),
        ("cipher_suite", "TLS_AES_128_GCM_SHA256"),
        ("secret_bits", 128),
    ],
)
def test_context_setup_red_adapter_rejects_contradictory_protocol_failure(
    adapter, field, value
):
    raw = setup_failure_raw("tls_protocols")
    raw["probes"][1][field] = value
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


@pytest.mark.parametrize("kind", ["https_availability", "http_redirect"])
@pytest.mark.parametrize(
    "change",
    [
        {"http_status": 200},
        {"verify_code": 62},
        {"outcome": "certificate_verification_failed"},
    ],
    ids=["http-response", "verify-code", "peer-verification-outcome"],
)
def test_context_setup_red_adapter_rejects_peer_evidence_at_https_setup(
    adapter, kind, change
):
    raw = setup_failure_raw(kind)
    probe = raw["probe"] if kind == "http_redirect" else raw
    probe.update(change)
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter(kind, raw)


@pytest.mark.parametrize("flag", [True, False], ids=["redirect", "not-redirect"])
def test_setup_redirect_consistency_rejects_https_redirect_flag(adapter, flag):
    raw = setup_failure_raw("https_availability") | {"is_redirect": flag}

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("https_availability", raw)


@pytest.mark.parametrize("flag", [None, "setup-marker"], ids=["unavailable", "invalid"])
def test_setup_redirect_consistency_accepts_unavailable_https_flag(adapter, flag):
    raw = setup_failure_raw("https_availability") | {"is_redirect": flag}
    original = deepcopy(raw)

    report = adapter("https_availability", raw)

    assert raw == original
    assert report["data"] == raw | {"is_redirect": None}
    assert report["issues"] == (
        [] if flag is None else [{"field": "is_redirect", "code": "invalid_value"}]
    )
    assert "setup-marker" not in json.dumps(report, allow_nan=False)


def test_setup_redirect_consistency_rejects_plaintext_source(adapter):
    raw = setup_failure_raw("http_redirect")
    raw["source"].update(scheme="http", port=80)

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)


@pytest.mark.parametrize(
    ("scheme_field", "expected_scheme", "redacted"),
    [
        pytest.param({"scheme": "https"}, "https", False, id="https"),
        pytest.param({"scheme": None}, None, False, id="unavailable"),
        pytest.param({}, None, True, id="absent"),
        pytest.param({"scheme": "setup-marker"}, None, True, id="invalid"),
    ],
)
def test_setup_redirect_consistency_preserves_https_or_unavailable_scheme(
    adapter, scheme_field, expected_scheme, redacted
):
    raw = setup_failure_raw("http_redirect")
    raw["source"].pop("scheme")
    raw["source"].update(scheme_field)
    original = deepcopy(raw)

    report = adapter("http_redirect", raw)

    assert raw == original
    assert report["data"] == raw | {
        "source": raw["source"] | {"scheme": expected_scheme}
    }
    assert report["issues"] == (
        [{"field": "source.scheme", "code": "invalid_value"}] if redacted else []
    )
    assert "setup-marker" not in json.dumps(report, allow_nan=False)


def test_setup_redirect_consistency_preserves_plaintext_upgrade(adapter):
    raw = first_hop("http", "upgrade", "https", 302)
    original = deepcopy(raw)

    report = adapter("http_redirect", raw)

    assert raw == original
    assert report["data"] == original
    assert report["issues"] == []
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize(
    "kind",
    [
        "tls_connectivity",
        "tls_certificate",
        "tls_protocols",
        "https_availability",
        "http_redirect",
    ],
)
def test_secondary_failure_red_adapter_preserves_fixed_diagnostics(adapter, kind):
    if kind == "tls_connectivity":
        raw = connectivity() | {"tls_version": None}
        path = ()
        diagnostics = ["tls_version_unavailable", "tcp_close_failed"]
    elif kind == "tls_certificate":
        raw = certificate()
        path = ("connectivity",)
        raw["connectivity"]["cipher_suite"] = None
        diagnostics = ["cipher_metadata_unavailable", "tls_close_failed"]
    elif kind == "tls_protocols":
        raw = protocol_result(confirmed_protocol("TLSv1.2"))
        path = ("probes", 0)
        raw["probes"][0].update(cipher_suite=None, secret_bits=None)
        diagnostics = ["cipher_metadata_unavailable"]
    elif kind == "https_availability":
        raw = availability(200, False)
        path = ()
        diagnostics = ["http_response_close_failed", "http_connection_close_failed"]
    else:
        raw = first_hop("http", "upgrade", "https", 302)
        path = ("probe",)
        diagnostics = ["http_connection_close_failed"]

    baseline = adapter(kind, raw)
    raw_leaf = raw
    for part in path:
        raw_leaf = raw_leaf[part]
    raw_leaf["diagnostics"] = diagnostics
    expected_leaf = baseline["data"]
    for part in path:
        expected_leaf = expected_leaf[part]
    expected_leaf["diagnostics"] = diagnostics
    original = deepcopy(raw)

    report = adapter(kind, raw)

    assert report == baseline
    assert raw == original
    assert report["schema_version"] == 1
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize(
    ("diagnostics", "retained", "issues"),
    [
        pytest.param([], None, [], id="empty"),
        pytest.param(
            "synthetic private diagnostic",
            None,
            [{"field": "diagnostics", "code": "invalid_value"}],
            id="invalid-container",
        ),
        pytest.param(
            [
                "tls_close_failed",
                {"secret": "synthetic private diagnostic"},
                "unknown-diagnostic",
            ],
            ["tls_close_failed"],
            [
                {"field": "diagnostics[1]", "code": "invalid_value"},
                {"field": "diagnostics[2]", "code": "invalid_value"},
            ],
            id="invalid-items",
        ),
        pytest.param(
            ["tls_close_failed"] * 64,
            None,
            [{"field": "diagnostics", "code": "value_too_long"}],
            id="over-limit",
        ),
    ],
)
def test_secondary_failure_red_adapter_sanitizes_optional_diagnostics(
    adapter, diagnostics, retained, issues
):
    raw = connectivity() | {"diagnostics": diagnostics}
    original = deepcopy(raw)

    report = adapter("tls_connectivity", raw)

    assert raw == original
    assert report["data"]["status"] == "ok"
    if retained is None:
        assert "diagnostics" not in report["data"]
    else:
        assert report["data"]["diagnostics"] == retained
    assert report["issues"] == issues
    encoded = json.dumps(report, allow_nan=False)
    assert "synthetic private diagnostic" not in encoded
    assert "unknown-diagnostic" not in encoded


def test_secondary_failure_red_adapter_keeps_unreadable_version_inconclusive(adapter):
    probe = confirmed_protocol("TLSv1.2") | {
        "outcome": "inconclusive",
        "evidence_code": "tls_version_unavailable",
        "negotiated_version": None,
        "error_message": "synthetic private version message",
        "diagnostics": ["tls_version_unavailable"],
    }
    raw = protocol_result(probe, confirmed_protocol("TLSv1.3"))
    original = deepcopy(raw)

    report = adapter("tls_protocols", raw)

    assert raw == original
    first, second = report["data"]["probes"]
    assert first == probe | {
        "error_message": "Could not read the negotiated TLS version."
    }
    assert second == raw["probes"][1]
    assert report["data"]["recommendations"] == []
    assert "synthetic private" not in json.dumps(report, allow_nan=False)


def test_secondary_failure_red_adapter_rejects_confirmed_unreadable_version(adapter):
    probe = confirmed_protocol("TLSv1.2") | {"diagnostics": ["tls_version_unavailable"]}
    raw = protocol_result(probe)

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def _tls_diagnostic_result(kind, observed):
    if kind == "tls_connectivity":
        return observed
    raw = certificate() if observed["status"] == "ok" else setup_failure_raw(kind)
    raw["connectivity"] = observed
    return raw


@pytest.mark.parametrize("kind", ["tls_connectivity", "tls_certificate"])
@pytest.mark.parametrize(
    ("stage", "diagnostic"),
    [
        pytest.param(None, "tls_version_unavailable", id="observed-version"),
        pytest.param(None, "cipher_metadata_unavailable", id="observed-cipher"),
        pytest.param(
            "handshake", "cipher_metadata_unavailable", id="failed-verification"
        ),
        pytest.param("tls_setup", "tcp_close_failed", id="setup-before-tcp"),
        pytest.param("tls_setup", "tls_close_failed", id="setup-before-tls"),
    ],
)
def test_cycle5_diagnostics_rejects_tls_contradictions(
    adapter, kind, stage, diagnostic
):
    observed = (
        connectivity() if stage is None else setup_failure_raw("tls_connectivity")
    )
    if stage == "handshake":
        observed.update(
            status="certificate_verification_failed",
            failed_stage="handshake",
            verify_code=62,
        )
    raw = _tls_diagnostic_result(kind, observed)
    adapter(kind, raw)
    observed["diagnostics"] = [diagnostic]
    original = deepcopy(raw)

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter(kind, raw)

    assert raw == original


@pytest.mark.parametrize("kind", ["tls_connectivity", "tls_certificate"])
def test_cycle5_diagnostics_keeps_cleanup_after_certificate_failure(adapter, kind):
    observed = setup_failure_raw("tls_connectivity") | {
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "verify_code": 62,
        "diagnostics": ["tls_close_failed", "tcp_close_failed"],
    }
    raw = _tls_diagnostic_result(kind, observed)
    original = deepcopy(raw)

    report = adapter(kind, raw)
    data = report["data"]
    evidence = data if kind == "tls_connectivity" else data["connectivity"]
    assert evidence["status"] == "certificate_verification_failed"
    assert evidence["failed_stage"] == "handshake"
    assert evidence["verify_code"] == 62
    assert evidence["diagnostics"] == observed["diagnostics"]
    assert evidence["diagnostics"] is not observed["diagnostics"]
    assert report["issues"] == []
    assert raw == original
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize(
    ("version", "issues"),
    [
        pytest.param(None, [], id="unavailable"),
        pytest.param(
            "invalid-version",
            [{"field": "tls_version", "code": "invalid_value"}],
            id="redacted",
        ),
    ],
)
def test_cycle5_diagnostics_keeps_cipher_when_version_unavailable(
    adapter, version, issues
):
    raw = connectivity() | {
        "tls_version": version,
        "diagnostics": ["tls_version_unavailable"],
    }
    original = deepcopy(raw)

    report = adapter("tls_connectivity", raw)
    data = report["data"]
    assert data["status"] == "ok"
    assert data["tls_version"] is None
    assert data["cipher_suite"] == raw["cipher_suite"]
    assert data["diagnostics"] == raw["diagnostics"]
    assert report["issues"] == issues
    assert raw == original
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize(
    ("probe", "diagnostic"),
    [
        pytest.param(
            confirmed_protocol("TLSv1.3"),
            "tls_version_unavailable",
            id="confirmed-version-unreadable",
        ),
        pytest.param(
            confirmed_protocol("TLSv1.3") | {"secret_bits": None},
            "cipher_metadata_unavailable",
            id="observed-cipher-suite",
        ),
        pytest.param(
            confirmed_protocol("TLSv1.3") | {"cipher_suite": None},
            "cipher_metadata_unavailable",
            id="observed-secret-bits",
        ),
        pytest.param(
            unconfirmed_protocol("TLSv1.3", "inconclusive", "timeout", "handshake"),
            "cipher_metadata_unavailable",
            id="metadata-after-handshake-timeout",
        ),
        pytest.param(
            unconfirmed_protocol(
                "TLSv1.3", "inconclusive", "tls_setup_error", "tls_setup"
            ),
            "tls_close_failed",
            id="setup-before-tls",
        ),
        pytest.param(
            unconfirmed_protocol(
                "TLSv1.3", "client_restricted", "client_version_policy", None
            ),
            "tcp_close_failed",
            id="policy-before-tcp",
        ),
    ],
)
def test_cycle5_diagnostics_rejects_protocol_contradictions(adapter, probe, diagnostic):
    earlier_probe = confirmed_protocol("TLSv1.2")
    adapter("tls_protocols", protocol_result(earlier_probe, probe))
    raw = protocol_result(earlier_probe, probe | {"diagnostics": [diagnostic]})
    original = deepcopy(raw)

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)

    assert raw == original


def test_cycle5_diagnostics_keeps_confirmed_protocol_when_cipher_redacted(adapter):
    probe = confirmed_protocol("TLSv1.3") | {
        "cipher_suite": "invalid\x00cipher",
        "secret_bits": True,
        "diagnostics": ["cipher_metadata_unavailable"],
    }
    raw = protocol_result(probe)
    original = deepcopy(raw)

    report = adapter("tls_protocols", raw)
    assert report["data"]["probes"] == [
        probe | {"cipher_suite": None, "secret_bits": None}
    ]
    assert report["issues"] == [
        {"field": "probes[0].cipher_suite", "code": "invalid_value"},
        {"field": "probes[0].secret_bits", "code": "invalid_value"},
    ]
    assert raw == original
    assert json.loads(json.dumps(report, allow_nan=False)) == report


def test_cycle5_diagnostics_keeps_protocol_cleanup_after_handshake_failure(adapter):
    failed = unconfirmed_protocol(
        "TLSv1.3", "client_restricted", "NO_CIPHERS_AVAILABLE", "handshake"
    ) | {"diagnostics": ["tls_close_failed", "tcp_close_failed"]}
    earlier = confirmed_protocol("TLSv1.2")
    raw = protocol_result(earlier, failed)
    original = deepcopy(raw)

    report = adapter("tls_protocols", raw)
    assert report["data"]["probes"][0] == earlier
    evidence = report["data"]["probes"][1]
    assert evidence["outcome"] == failed["outcome"]
    assert evidence["evidence_code"] == failed["evidence_code"]
    assert evidence["failed_stage"] == "handshake"
    assert evidence["diagnostics"] == failed["diagnostics"]
    assert report["data"]["recommendations"] == []
    assert report["issues"] == []
    assert raw == original
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize("kind", ["https_availability", "http_redirect"])
@pytest.mark.parametrize(
    "diagnostic", ["http_response_close_failed", "http_connection_close_failed"]
)
def test_cycle5_diagnostics_rejects_http_cleanup_before_acquisition(
    adapter, kind, diagnostic
):
    raw = setup_failure_raw(kind)
    adapter(kind, raw)
    probe = raw if kind == "https_availability" else raw["probe"]
    probe["diagnostics"] = [diagnostic]
    original = deepcopy(raw)

    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter(kind, raw)

    assert raw == original


@pytest.mark.parametrize("kind", ["https_availability", "http_redirect"])
@pytest.mark.parametrize(
    ("outcome", "stage", "diagnostics"),
    [
        pytest.param(
            "invalid_http_response",
            "response",
            ["http_response_close_failed", "http_connection_close_failed"],
            id="response-failure",
        ),
        pytest.param(
            "transport_error",
            "request",
            ["http_connection_close_failed"],
            id="request-failure",
        ),
    ],
)
def test_cycle5_diagnostics_keeps_http_cleanup_after_acquisition(
    adapter, kind, outcome, stage, diagnostics
):
    raw = setup_failure_raw(kind)
    probe = raw if kind == "https_availability" else raw["probe"]
    probe.update(
        outcome=outcome,
        failed_stage=stage,
        diagnostics=diagnostics,
    )
    original = deepcopy(raw)

    report = adapter(kind, raw)
    data = report["data"]
    evidence = data if kind == "https_availability" else data["probe"]
    assert evidence == probe
    assert evidence["diagnostics"] is not probe["diagnostics"]
    assert report["issues"] == []
    assert raw == original
    assert json.loads(json.dumps(report, allow_nan=False)) == report


def test_report_integrity_rejects_opposing_probes_for_same_version(adapter):
    rejected = unconfirmed_protocol(
        "TLSv1.3", "server_rejected", "TLSV1_ALERT_PROTOCOL_VERSION", "handshake"
    )
    raw = protocol_result(confirmed_protocol("TLSv1.2"), rejected)
    report = adapter("tls_protocols", raw)
    assert [probe["outcome"] for probe in report["data"]["probes"]] == [
        "confirmed_supported",
        "server_rejected",
    ]

    rejected["requested_version"] = "TLSv1.2"
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def test_report_integrity_rejects_probed_version_listed_as_not_probed(adapter):
    raw = protocol_result(
        confirmed_protocol("TLSv1.2"),
        unconfirmed_protocol("TLSv1.3", "inconclusive", "timeout", "handshake"),
    )
    report = adapter("tls_protocols", raw)
    assert report["data"]["not_probed"] == ["TLSv1", "TLSv1.1"]
    assert report["data"]["probes"][1]["outcome"] == "inconclusive"

    raw["not_probed"].append("TLSv1.2")
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def test_report_integrity_rejects_negotiated_evidence_on_server_rejection(adapter):
    rejected = unconfirmed_protocol(
        "TLSv1.3", "server_rejected", "TLSV1_ALERT_PROTOCOL_VERSION", "handshake"
    ) | {"diagnostics": ["tls_close_failed", "tcp_close_failed"]}
    raw = protocol_result(confirmed_protocol("TLSv1.2"), rejected)
    report = adapter("tls_protocols", raw)
    evidence = report["data"]["probes"][1]
    assert evidence["outcome"] == "server_rejected"
    assert evidence["diagnostics"] == ["tls_close_failed", "tcp_close_failed"]

    rejected.update(
        negotiated_version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        secret_bits=128,
        verify_code=62,
    )
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("tls_protocols", raw)


def test_report_integrity_rejects_certificate_failure_on_plaintext_redirect(adapter):
    raw = first_hop("https", "not_evaluated", None, None)
    raw["probe"].update(
        outcome="certificate_verification_failed",
        failed_stage="handshake",
        verify_code=62,
    )
    report = adapter("http_redirect", raw)
    assert report["data"]["probe"] == raw["probe"]

    raw["source"].update(scheme="http", port=80)
    with pytest.raises(ReportInputError, match=r"^Invalid audit report input$"):
        adapter("http_redirect", raw)
