"""Track TLS and HTTPS audit coverage."""


def evaluate_coverage(report: dict) -> dict:
    """Determine whether an audit produced usable evidence."""
    if report.get("schema_version") != 1:
        raise ValueError("Unsupported TLS report schema")

    kind = report["kind"]
    data = report["data"]
    completed = False

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
        completed = (
            data["probe"]["outcome"] == "available"
            and data["redirect"]["outcome"] != "not_evaluated"
        )

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
    }