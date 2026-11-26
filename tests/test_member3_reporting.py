"""Automated reporting tests for Member 3."""

import json

from webguard.core.audit_integration import integrate_audit_results
from webguard.core.models import Finding
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