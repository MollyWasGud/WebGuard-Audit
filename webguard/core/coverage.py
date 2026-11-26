"""Track TLS and HTTPS audit coverage."""

from typing import get_args

from webguard.auditors.report_adapter import HTTPOutcome, RedirectOutcome

_REDIRECT_OUTCOMES = get_args(RedirectOutcome)
_HTTP_OUTCOMES = get_args(HTTPOutcome)


def evaluate_coverage(report: dict) -> dict:
    """Determine whether an audit produced usable evidence."""
    if report.get("schema_version") != 1:
        raise ValueError("Unsupported TLS report schema")

    kind = report["kind"]
    data = report["data"]
    redirect_coverage = {}

    if kind == "tls_connectivity":
        completed = data["status"] in {
            "ok", "certificate_verification_failed"
        }

    elif kind == "tls_certificate":
        completed = data["certificate_status"] == "ok"

    elif kind == "tls_protocols":
        probes = data["probes"]
        completed = (
            data["status"] == "ok"
            and {
                probe["requested_version"]
                for probe in probes
            } == {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
            and all(
                probe["outcome"] in {
                    "confirmed_supported", "server_rejected"
                }
                for probe in probes
            )
        )

    elif kind == "https_availability":
        completed = data["outcome"] in {
            "available", "certificate_verification_failed"
        }

    elif kind == "http_redirect":
        probe = data["probe"]
        redirect = data["redirect"]
        outcome = redirect["outcome"]
        probe_outcome = probe["outcome"]
        destination = redirect["destination"]
        verification = (
            "not_attempted"
            if destination is not None
            and destination["verification"] == "not_attempted"
            else None
        )
        completed = (
            probe_outcome == "available"
            and probe["http_status"] is not None
            and (
                outcome == "no_redirect"
                or (
                    outcome in ("upgrade", "downgrade", "same_scheme_redirect")
                    and destination is not None
                    and verification is not None
                    and all(
                        destination[field] is not None
                        for field in ("scheme", "hostname", "port")
                    )
                )
            )
        )
        redirect_coverage = {
            "redirect_outcome": outcome if outcome in _REDIRECT_OUTCOMES else None,
            "probe_outcome": probe_outcome if probe_outcome in _HTTP_OUTCOMES else None,
            "destination_verification": verification,
        }

    else:
        raise ValueError("Unsupported TLS audit kind")

    issues = report.get("issues", [])

    return {
        "audit_kind": kind,
        "coverage_status": (
            "COMPLETED" if completed and not issues
            else "INCOMPLETE"
        ),
        "data_quality_issues": len(issues),
        **redirect_coverage,
    }