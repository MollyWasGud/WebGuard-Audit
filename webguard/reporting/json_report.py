"""Generate local JSON security audit reports."""

import json
from datetime import UTC, datetime
from pathlib import Path

from webguard.reporting.sanitizer import sanitize_text


def generate_json_report(audit_result: dict) -> Path:
    """Save processed security audit results as JSON."""
    timestamp = datetime.now(UTC)

    report = {
        "report_name": "WebGuard Audit",
        "schema_version": 1,
        "generated_at": timestamp.isoformat(),
        "risk_summary": audit_result["risk_summary"],
        "compliance_summary": audit_result["compliance_summary"],
        "audit_coverage": audit_result["audit_coverage"],
        "findings": [
            {
                "check_id": sanitize_text(finding.check_id),
                "category": sanitize_text(finding.category),
                "severity": sanitize_text(finding.severity),
                "title": sanitize_text(finding.title),
                "detail": sanitize_text(finding.detail),
                "remediation": sanitize_text(finding.remediation),
            }
            for finding in audit_result["findings"]
        ],
        "remediation_plan": [
            {
                key: sanitize_text(value)
                if isinstance(value, str)
                else value
                for key, value in action.items()
            }
            for action in audit_result["remediation_plan"]
        ],
    }

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    filename = timestamp.strftime("audit_%Y%m%d_%H%M%S_%f.json")
    report_path = output_dir / filename

    report_path.write_text(
        json.dumps(report, indent=4, allow_nan=False),
        encoding="utf-8",
    )

    return report_path