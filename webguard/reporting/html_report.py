"""Generate local HTML security audit reports."""

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from webguard.reporting.sanitizer import sanitize_text


def generate_html_report(audit_result: dict) -> Path:
    """Generate an HTML report from processed audit results."""
    timestamp = datetime.now(UTC)

    template_dir = Path(__file__).parent / "templates"

    environment = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )

    template = environment.get_template("audit_report.html")

    safe_findings = [
        {
            "check_id": sanitize_text(finding.check_id),
            "category": sanitize_text(finding.category),
            "severity": sanitize_text(finding.severity),
            "title": sanitize_text(finding.title),
            "detail": sanitize_text(finding.detail),
            "remediation": sanitize_text(finding.remediation),
        }
        for finding in audit_result["findings"]
    ]

    safe_remediation = [
        {
            key: sanitize_text(value)
            if isinstance(value, str)
            else value
            for key, value in action.items()
        }
        for action in audit_result["remediation_plan"]
    ]

    html_content = template.render(
        report_name="WebGuard Audit",
        generated_at=timestamp.isoformat(),
        risk_summary=audit_result["risk_summary"],
        compliance_summary=audit_result["compliance_summary"],
        audit_coverage=audit_result["audit_coverage"],
        findings=safe_findings,
        remediation_plan=safe_remediation,
    )

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    filename = timestamp.strftime("audit_%Y%m%d_%H%M%S_%f.html")
    report_path = output_dir / filename

    report_path.write_text(html_content, encoding="utf-8")

    return report_path