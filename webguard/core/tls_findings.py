"""Convert validated TLS audit results into WebGuard findings."""

from webguard.core.models import Finding


def certificate_failure(data: dict, endpoint: dict) -> Finding:
    """Create a consistent certificate verification finding."""
    return Finding(
        check_id="TLS:certificate-verification",
        category="tls",
        severity="HIGH",
        title="Certificate verification failed",
        detail="The TLS certificate could not be verified.",
        remediation="Review certificate validity, trust and hostname.",
        evidence=(
            f"{endpoint['hostname']}:{endpoint['port']} "
            f"verify_code={data.get('verify_code')}"
        ),
    )


def convert_tls_findings(
    report: dict,
    require_https_upgrade: bool = False,
) -> list[Finding]:
    """Convert validated transport security issues into findings."""
    if report.get("schema_version") != 1:
        raise ValueError("Unsupported TLS report schema")

    findings: list[Finding] = []

    kind = report["kind"]
    data = report["data"]

    if kind == "tls_connectivity":
        if data["status"] == "certificate_verification_failed":
            findings.append(certificate_failure(data, data))

    elif kind == "tls_certificate":
        connectivity = data.get("connectivity")

        if connectivity:
            findings.extend(
                convert_tls_findings({
                    "schema_version": 1,
                    "kind": "tls_connectivity",
                    "data": connectivity,
                    "issues": [],
                })
            )

        certificate = data.get("certificate")

        if data["certificate_status"] == "ok" and certificate:
            expiration = certificate["expiration_status"]

            endpoint = (
                f"{connectivity['hostname']}:{connectivity['port']}"
                if connectivity else "Unknown endpoint"
            )

            if expiration == "expired":
                findings.append(
                    Finding(
                        check_id="TLS:expired",
                        category="tls",
                        severity="HIGH",
                        title="Expired TLS certificate",
                        detail="The certificate validity period has ended.",
                        remediation="Renew the TLS certificate.",
                        evidence=endpoint,
                    )
                )

            elif expiration == "expiring_soon":
                findings.append(
                    Finding(
                        check_id="TLS:expiring-soon",
                        category="tls",
                        severity="MEDIUM",
                        title="TLS certificate expiring soon",
                        detail="The certificate is approaching expiration.",
                        remediation="Renew the certificate before expiration.",
                        evidence=endpoint,
                    )
                )

    elif kind == "tls_protocols":
        target = data["target"]
        endpoint = f"{target['hostname']}:{target['port']}"

        if data["status"] == "ok":
            for probe in data["probes"]:
                version = probe["requested_version"]
                outcome = probe["outcome"]

                if probe.get("evidence_code") in {
                    "certificate_verification_failed",
                    "CERTIFICATE_VERIFY_FAILED",
                }:
                    findings.append(
                        certificate_failure(probe, target)
                    )

                if (
                    version in {"TLSv1", "TLSv1.1"}
                    and outcome == "confirmed_supported"
                ):
                    findings.append(
                        Finding(
                            check_id="TLS:legacy-version",
                            category="tls",
                            severity="HIGH",
                            title=f"Legacy protocol supported: {version}",
                            detail="An outdated TLS version is supported.",
                            remediation="Disable legacy TLS and use TLS 1.2 or 1.3.",
                            evidence=f"{endpoint} {version}",
                        )
                    )

            for recommendation in data.get("recommendations") or []:
                if (
                    recommendation
                    and recommendation["code"] == "review_tls_1_3"
                ):
                    findings.append(
                        Finding(
                            check_id="TLS:review-1.3",
                            category="tls",
                            severity="INFO",
                            title="Review TLS 1.3 availability",
                            detail="TLS 1.3 was rejected in the observed probe.",
                            remediation="Review TLS 1.3 support and configuration.",
                            evidence=endpoint,
                        )
                    )

    elif kind == "https_availability":
        if data["outcome"] == "certificate_verification_failed":
            findings.append(
                certificate_failure(data, data["target"])
            )

    elif kind == "http_redirect":
        source = data["source"]
        probe = data["probe"]
        redirect = data["redirect"]

        endpoint = (
            f"{source['scheme']}://"
            f"{source['hostname']}:{source['port']}"
        )

        if (
            source["scheme"] == "https"
            and probe["outcome"] == "certificate_verification_failed"
        ):
            findings.append(certificate_failure(probe, source))

        if (
            probe["outcome"] == "available"
            and redirect["outcome"] == "downgrade"
        ):
            findings.append(
                Finding(
                    check_id="HTTPS:downgrade",
                    category="tls",
                    severity="HIGH",
                    title="HTTPS redirects to HTTP",
                    detail="The first redirect points to an insecure HTTP origin.",
                    remediation="Use HTTPS for redirect destinations.",
                    evidence=endpoint,
                )
            )

        elif (
            require_https_upgrade
            and source["scheme"] == "http"
            and probe["outcome"] == "available"
            and redirect["outcome"] in {
                "no_redirect",
                "same_scheme_redirect",
            }
            and "review_https_upgrade" in (
                data.get("recommendations") or []
            )
        ):
            findings.append(
                Finding(
                    check_id="HTTPS:no-upgrade",
                    category="tls",
                    severity="MEDIUM",
                    title="Required HTTPS upgrade missing",
                    detail="The observed first response does not upgrade to HTTPS.",
                    remediation="Configure HTTP-to-HTTPS redirection.",
                    evidence=endpoint,
                )
            )

    else:
        raise ValueError("Unsupported TLS audit kind")

    return findings