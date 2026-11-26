"""Automated reporting tests for Member 3."""

import json
from unittest.mock import Mock

from test_report_adapter import http_probe

from webguard import cli
from webguard.auditors import https
from webguard.core.audit_integration import integrate_audit_results
from webguard.core.models import Finding, ResponseData
from webguard.reporting.html_report import generate_html_report
from webguard.reporting.json_report import generate_json_report
from webguard.reporting.sanitizer import sanitize_text


def make_audit_result():
    finding = Finding(
        "CSP:missing",
        "csp",
        "MEDIUM",
        "Missing CSP",
        "Content Security Policy is missing",
        "Configure CSP",
    )

    return integrate_audit_results([finding], [], set())


def test_json_report_generation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = make_audit_result()
    path = generate_json_report(result)

    assert path.exists()
    assert path.suffix == ".json"

    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["report_name"] == "WebGuard Audit"
    assert report["risk_summary"]["total_risk_score"] == 4
    assert len(report["findings"]) == 1


def test_html_report_generation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = make_audit_result()
    path = generate_html_report(result)

    assert path.exists()
    assert path.suffix == ".html"

    content = path.read_text(encoding="utf-8")

    assert "WebGuard Audit" in content
    assert "Missing CSP" in content
    assert "Compliance Assessment" in content
    assert "Prioritised Remediation Plan" in content


def test_sensitive_text_sanitization():
    assert sanitize_text("password=DEMO_SECRET") == "password=[REDACTED]"
    assert sanitize_text("api_key=ABC123") == "api_key=[REDACTED]"
    assert sanitize_text("Bearer ABC123") == "Bearer [REDACTED]"
    assert sanitize_text("Missing CSP") == "Missing CSP"


def test_html_injection_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    finding = Finding(
        "TEST:xss",
        "security",
        "INFO",
        "<script>alert(1)</script>",
        "HTML escaping test",
        "Escape untrusted content",
    )

    result = integrate_audit_results([finding], [], set())
    content = generate_html_report(result).read_text(encoding="utf-8")

    assert "&lt;script&gt;" in content
    assert "<script>alert(1)</script>" not in content


def test_report_sensitive_data_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    finding = Finding(
        "TEST:privacy",
        "security",
        "INFO",
        "Privacy test",
        "password=DEMO_SECRET_123",
        "Protect sensitive data",
        evidence="password=RAW_SECRET_456",
    )

    result = integrate_audit_results([finding], [], set())

    json_content = generate_json_report(result).read_text(
        encoding="utf-8"
    )
    html_content = generate_html_report(result).read_text(
        encoding="utf-8"
    )

    for content in (json_content, html_content):
        assert "DEMO_SECRET_123" not in content
        assert "RAW_SECRET_456" not in content
        assert "[REDACTED]" in content


def test_rejected_tls_input_is_visible_in_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    marker = "SYNTHETIC_TLS_PRIVATE_41C"
    malformed = {
        "hostname": marker,
        "port": 443,
        "status": "certificate_verification_failed",
        "verify_code": 62,
        "error_message": f"password={marker}",
    }
    finding = Finding("TEST:inert", "test", "INFO", "<script>inert</script>", "", "")
    result = integrate_audit_results(
        [finding], [("tls_connectivity", malformed)], {"POL-009"}
    )

    json_text = generate_json_report(result).read_text(encoding="utf-8")
    html_text = generate_html_report(result).read_text(encoding="utf-8")
    report = json.loads(json_text)
    json.dumps(report, allow_nan=False)

    assert report["schema_version"] == 1
    assert report["audit_coverage"] == [
        {
            "audit_kind": "Rejected TLS input",
            "coverage_status": "INCOMPLETE",
            "data_quality_issues": 1,
        }
    ]
    assert report["risk_summary"]["total_risk_score"] == 0
    assert [item["check_id"] for item in report["findings"]] == ["TEST:inert"]
    assert "Rejected TLS input" in html_text
    assert "INCOMPLETE" in html_text
    assert marker not in json_text + html_text
    assert "&lt;script&gt;inert&lt;/script&gt;" in html_text
    assert "<script>inert</script>" not in html_text


def test_http_only_cli_reports_tls_unassessed(tmp_path, monkeypatch):
    import io
    import re
    import socket

    from webguard.auditors import report_adapter, tls

    monkeypatch.chdir(tmp_path)
    target = "http://127.0.0.1:8000"
    destination = "https://127.0.0.1:8443/"
    fetch = Mock(return_value=ResponseData(target, 200, []))
    monkeypatch.setattr(cli, "fetch", fetch)

    peer = Mock()
    peer.makefile.return_value = io.BytesIO(
        f"HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\n\r\n".encode()
    )
    socket_factory = Mock(return_value=peer)
    resolve = Mock(side_effect=AssertionError("Unexpected DNS resolution"))
    monkeypatch.setattr(socket, "socket", socket_factory)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    tls_context = Mock(side_effect=AssertionError("Unexpected TLS context"))
    monkeypatch.setattr(tls, "_create_verified_client_context", tls_context)
    monkeypatch.setattr(https, "_create_verified_client_context", tls_context)

    redirect = Mock(wraps=https.audit_http_redirect)
    adapt = Mock(wraps=report_adapter.to_safe_audit_report)
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    monkeypatch.setattr(report_adapter, "to_safe_audit_report", adapt)

    assert cli.run_audit(target) == 0

    transport = fetch.call_args.kwargs["transport"]
    assert (transport.scheme, transport.hostname, transport.port, transport.peer) == (
        "http",
        "127.0.0.1",
        8000,
        "127.0.0.1",
    )
    fetch.assert_called_once_with(target, transport=transport)
    redirect.assert_called_once_with(
        "127.0.0.1", 8000, source_scheme="http", transport=transport
    )
    socket_factory.assert_called_once()
    peer.connect.assert_called_once_with(("127.0.0.1", 8000))
    peer.sendall.assert_called_once()
    wire = peer.sendall.call_args.args[0]
    assert wire.startswith(b"HEAD / HTTP/1.1\r\n")
    assert b"Host: 127.0.0.1:8000\r\n" in wire
    resolve.assert_not_called()
    tls_context.assert_not_called()
    adapt.assert_called_once()
    kind, raw = adapt.call_args.args
    assert kind == "http_redirect"
    assert raw["source"] == {"scheme": "http", "hostname": "127.0.0.1", "port": 8000}
    assert raw["redirect"]["destination"] == {
        "scheme": "https",
        "hostname": "127.0.0.1",
        "port": 8443,
        "verification": "not_attempted",
    }

    (report_path,) = (tmp_path / "reports").glob("*.json")
    (html_path,) = (tmp_path / "reports").glob("*.html")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    assert report["findings"]
    assert report["audit_coverage"] == [
        {
            "audit_kind": "http_redirect",
            "coverage_status": "COMPLETED",
            "data_quality_issues": 0,
            "redirect_outcome": "upgrade",
            "probe_outcome": "available",
            "destination_verification": "not_attempted",
        },
        {
            "audit_kind": f"Audit scope: {target}",
            "coverage_status": "COMPLETED",
            "data_quality_issues": 0,
        },
    ]
    policy = report["compliance_summary"]["policy_results"][-1]
    assert (policy["policy_id"], policy["status"]) == ("POL-009", "NOT_CHECKED")
    assert ">upgrade<" in html and ">not_attempted<" in html
    assert re.search(
        r"<td>POL-009</td>\s*<td>TLS and HTTPS Security</td>\s*<td class=\"NOT_CHECKED\">",
        html,
    )


def test_redirect_reports_use_first_hop_outcomes_without_location_data(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    redirect_inputs = []
    for scheme, location in (
        (
            "http",
            "https://destination.test/path?token=SYNTH_41D_QUERY#SYNTH_41D_FRAGMENT",
        ),
        (
            "https",
            "http://destination.test/path?token=SYNTH_41D_QUERY#SYNTH_41D_FRAGMENT",
        ),
        ("https", "https://name:SYNTH_41D_PASSWORD@destination.test/"),
    ):
        response = http_probe() | {"http_status": 302}
        monkeypatch.setattr(
            https, "_probe_response_head", Mock(return_value=(response, [location]))
        )
        redirect_inputs.append(
            (
                "http_redirect",
                https.audit_http_redirect("example.test", source_scheme=scheme),
            )
        )

    inert = Finding("TEST:inert", "test", "INFO", "<script>inert</script>", "", "")
    result = integrate_audit_results([inert], redirect_inputs, set())
    json_text = generate_json_report(result).read_text(encoding="utf-8")
    html_text = generate_html_report(result).read_text(encoding="utf-8")
    report = json.loads(json_text)
    json.dumps(report, allow_nan=False)

    assert report["schema_version"] == 1
    rows = report["audit_coverage"]
    assert [row["redirect_outcome"] for row in rows] == [
        "upgrade",
        "downgrade",
        "invalid_location",
    ]
    assert [row["coverage_status"] for row in rows] == [
        "COMPLETED",
        "COMPLETED",
        "INCOMPLETE",
    ]
    assert [row["destination_verification"] for row in rows] == [
        "not_attempted",
        "not_attempted",
        None,
    ]
    for outcome in ("upgrade", "downgrade", "invalid_location", "not_attempted"):
        assert f">{outcome}<" in html_text
    for marker in (
        "destination.test",
        "SYNTH_41D_QUERY",
        "SYNTH_41D_FRAGMENT",
        "SYNTH_41D_PASSWORD",
    ):
        assert marker not in json_text + html_text
    assert "&lt;script&gt;inert&lt;/script&gt;" in html_text
    assert "<script>inert</script>" not in html_text
