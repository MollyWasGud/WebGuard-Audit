import ipaddress
import re
from collections.abc import Callable
from datetime import datetime
from math import isfinite
from typing import Literal, TypedDict, TypeVar, get_args
from unicodedata import category

from webguard.auditors.https import (
    _DEFAULT_PORTS,
    _REDIRECT_STATUSES,
    HTTPRedirectAuditResult,
    HTTPSAvailabilityResult,
    _HTTPAuditDiagnostic,
    _HTTPResultDiagnostics,
)
from webguard.auditors.tls import (
    _TLS_SETUP_DIAGNOSTIC,
    _TLS_VERSION_DIAGNOSTIC,
    TLSCertificateAuditResult,
    TLSConnectivityResult,
    TLSProtocolAuditResult,
    _normalize_hostname,
    _TLSAuditDiagnostic,
    _TLSResultDiagnostics,
)

AuditKind = Literal[
    "tls_connectivity",
    "tls_certificate",
    "tls_protocols",
    "https_availability",
    "http_redirect",
]
RawAuditResult = (
    TLSConnectivityResult
    | TLSCertificateAuditResult
    | TLSProtocolAuditResult
    | HTTPSAvailabilityResult
    | HTTPRedirectAuditResult
)

TLSStatus = Literal[
    "ok",
    "invalid_input",
    "tls_setup_error",
    "connection_error",
    "timeout",
    "certificate_verification_failed",
    "tls_handshake_error",
]
TLSStage = Literal["validation", "tls_setup", "connect", "handshake"]
CertificateStatus = Literal["ok", "not_collected", "metadata_error", "invalid_options"]
ExpirationStatus = Literal["current", "expiring_soon", "expired"]
ProtocolStatus = Literal["ok", "invalid_input"]
ProtocolOutcome = Literal[
    "confirmed_supported", "client_restricted", "server_rejected", "inconclusive"
]
HTTPOutcome = Literal[
    "available",
    "invalid_input",
    "certificate_verification_failed",
    "connection_refused",
    "timeout",
    "invalid_http_response",
    "unsupported_http_response",
    "tls_error",
    "transport_error",
]
HTTPStage = Literal[
    "validation", "tls_setup", "connect", "handshake", "request", "response"
]
Scheme = Literal["http", "https"]
RedirectOutcome = Literal[
    "not_evaluated",
    "no_redirect",
    "unsupported_redirect_status",
    "missing_location",
    "empty_location",
    "ambiguous_location",
    "invalid_location",
    "unsupported_scheme",
    "same_scheme_redirect",
    "upgrade",
    "downgrade",
]
IssueCode = Literal["invalid_value", "unsafe_text", "value_too_long"]


class ReportIssue(TypedDict):
    field: str
    code: IssueCode


class SafeEndpoint(TypedDict):
    hostname: str | None
    port: int | None


class SafeConnectivity(SafeEndpoint, _TLSResultDiagnostics):
    status: TLSStatus
    failed_stage: TLSStage | None
    tls_version: str | None
    cipher_suite: str | None
    error_message: str | None
    verify_code: int | None


class SafeSAN(TypedDict):
    type: Literal["dns", "ip"]
    value: str | None


class SafeCertificateMetadata(TypedDict):
    subject: str | None
    issuer: str | None
    serial_number: str | None
    sans: list[SafeSAN | None] | None
    not_valid_before: str | None
    not_valid_after: str | None
    remaining_seconds: float | int | None
    expiration_status: ExpirationStatus
    sha256_fingerprint: str | None


class SafeCertificate(TypedDict):
    connectivity: SafeConnectivity | None
    certificate_status: CertificateStatus
    certificate: SafeCertificateMetadata | None
    certificate_error: str | None


class SafeProtocolProbe(_TLSResultDiagnostics):
    requested_version: str
    outcome: ProtocolOutcome
    evidence_code: str | None
    negotiated_version: str | None
    cipher_suite: str | None
    secret_bits: int | None
    failed_stage: TLSStage | None
    error_message: str | None
    verify_code: int | None


class SafeRecommendation(TypedDict):
    code: str
    message: str


class SafeProtocols(TypedDict):
    target: SafeEndpoint
    status: ProtocolStatus
    error_message: str | None
    probes: list[SafeProtocolProbe]
    not_probed: list[str | None] | None
    recommendations: list[SafeRecommendation | None] | None


class SafeHTTPProbe(_HTTPResultDiagnostics):
    outcome: HTTPOutcome
    http_status: int | None
    failed_stage: HTTPStage | None
    verify_code: int | None
    elapsed_ms: float | int | None


class SafeHTTPS(SafeHTTPProbe):
    target: SafeEndpoint
    is_redirect: bool | None


class SafeRedirectSource(SafeEndpoint):
    scheme: Scheme | None


class SafeRedirectDestination(SafeRedirectSource):
    verification: Literal["not_attempted"] | None


class SafeRedirectAssessment(TypedDict):
    outcome: RedirectOutcome
    destination: SafeRedirectDestination | None
    same_host: bool | None
    port_changed: bool | None


class SafeRedirect(TypedDict):
    source: SafeRedirectSource
    probe: SafeHTTPProbe
    redirect: SafeRedirectAssessment
    recommendations: list[str | None] | None


class _Report(TypedDict):
    schema_version: Literal[1]
    issues: list[ReportIssue]


class TLSConnectivityReport(_Report):
    kind: Literal["tls_connectivity"]
    data: SafeConnectivity


class TLSCertificateReport(_Report):
    kind: Literal["tls_certificate"]
    data: SafeCertificate


class TLSProtocolsReport(_Report):
    kind: Literal["tls_protocols"]
    data: SafeProtocols


class HTTPSAvailabilityReport(_Report):
    kind: Literal["https_availability"]
    data: SafeHTTPS


class HTTPRedirectReport(_Report):
    kind: Literal["http_redirect"]
    data: SafeRedirect


SafeAuditReport = (
    TLSConnectivityReport
    | TLSCertificateReport
    | TLSProtocolsReport
    | HTTPSAvailabilityReport
    | HTTPRedirectReport
)


class ReportInputError(ValueError):
    """Raised when required reporting data is missing or malformed."""

    def __init__(self) -> None:
        super().__init__("Invalid audit report input")


class _RedactField(ValueError):
    def __init__(self, code: IssueCode) -> None:
        self.code = code


_T = TypeVar("_T")
_Text = TypeVar("_Text", bound=str)
_MISSING = object()

_TLS_DIAGNOSTICS = {
    "invalid_input": "Invalid TLS audit input.",
    "tls_setup_error": _TLS_SETUP_DIAGNOSTIC,
    "connection_error": "TLS transport connection failed.",
    "timeout": "TLS audit timed out.",
    "certificate_verification_failed": "Certificate verification failed.",
    "tls_handshake_error": "TLS handshake failed.",
}
_PROBE_DIAGNOSTICS = {
    **_TLS_DIAGNOSTICS,
    "tls_version_unavailable": _TLS_VERSION_DIAGNOSTIC,
    "runtime_version_unavailable": "The TLS version is unavailable in this runtime.",
    "client_version_policy": "The local TLS policy disallows this version.",
    "client_version_configuration": "The client could not configure the requested version.",
    "unexpected_negotiated_version": "The negotiated version differed from the requested version.",
    "TLSV1_ALERT_PROTOCOL_VERSION": "The peer sent a protocol-version alert.",
    "NO_PROTOCOLS_AVAILABLE": "No protocol version was available under the client policy.",
    "NO_CIPHERS_AVAILABLE": "No cipher was available under the client policy.",
}
_EVIDENCE_CODES = (
    *_PROBE_DIAGNOSTICS,
    "verified_handshake",
    "HANDSHAKE_FAILURE",
    "SSLV3_ALERT_HANDSHAKE_FAILURE",
    "CERTIFICATE_VERIFY_FAILED",
    "UNSUPPORTED_PROTOCOL",
    "WRONG_VERSION_NUMBER",
    "UNEXPECTED_EOF_WHILE_READING",
    "NO_SHARED_CIPHER",
    "TLSV1_ALERT_DECODE_ERROR",
    "SSLV3_ALERT_BAD_CERTIFICATE",
    "TLSV1_ALERT_UNKNOWN_CA",
    "UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
    "LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED",
)
_CERTIFICATE_ERRORS = (
    "Unable to read verified certificate DER",
    "Verified peer supplied no certificate DER",
    "cryptography is required for certificate metadata",
    "Unable to parse verified certificate metadata",
)
_PROTOCOL_ADVICE = {
    "disable_legacy_tls": "Disable the legacy TLS versions confirmed by verified handshakes.",
    "review_tls_1_3": "Review TLS 1.3 availability for the audited endpoint.",
}
_REDIRECT_ADVICE = (
    "https_to_http_downgrade",
    "review_https_upgrade",
    "review_cross_host_redirect",
    "review_unusual_redirect_port",
)
_REQUESTED_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_NEGOTIATED_VERSIONS = ("SSLv3", *_REQUESTED_VERSIONS)
_CIPHER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_SERIAL = re.compile(r"[0-9a-fA-F]{1,128}")
_FINGERPRINT = re.compile(r"[0-9a-fA-F]{64}")
_UTC_DATE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:\+00:00|Z)"
)
_URL_USERINFO = re.compile(r"//[^/?#\s]*@", re.ASCII)
_MAX_DN_LENGTH = 8192
_MAX_SANS = 1024


def _record(value: object) -> dict[str, object] | None:
    # Plain string keys prevent a dictionary lookup from calling an untrusted __eq__.
    if (
        type(value) is dict
        and len(value) <= 64
        and all(type(key) is str for key in value)
    ):
        return value
    return None


def _choice(value: object, allowed: tuple[_Text, ...]) -> _Text | None:
    if type(value) is str:
        for item in allowed:
            if value == item:
                return item
    return None


def _integer(value: object, low: int, high: int) -> int | None:
    return value if type(value) is int and low <= value <= high else None


def _duration(value: object, *, signed: bool = False) -> float | int | None:
    low = -(1 << 53) if signed else 0
    high = 1 << 53
    if type(value) is int:
        return _integer(value, low, high)
    if type(value) is float and isfinite(value) and low <= value <= high:
        return value
    return None


def _boolean(value: object) -> bool | None:
    return value if type(value) is bool else None


def _verification_code(value: object) -> int | None:
    return _integer(value, 0, (1 << 31) - 1)


def _match(value: object, pattern: re.Pattern[str], limit: int) -> str | None:
    if type(value) is str and len(value) <= limit and pattern.fullmatch(value):
        return value
    return None


def _hostname(value: object) -> str | None:
    if type(value) is not str:
        return None
    try:
        _, identity = _normalize_hostname(value)
    except ValueError:
        return None
    try:
        return ipaddress.ip_address(identity).compressed
    except ValueError:
        return identity.lower()


def _distinguished_name(value: object) -> str | None:
    if type(value) is not str:
        return None
    if len(value) > _MAX_DN_LENGTH:
        raise _RedactField("value_too_long")
    if any(
        category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value
    ) or _URL_USERINFO.search(value):
        raise _RedactField("unsafe_text")
    return value


def _utc_date(value: object) -> tuple[str, datetime] | None:
    date = _match(value, _UTC_DATE, 32)
    if date is None:
        return None
    try:
        parsed = datetime.fromisoformat(
            date.removesuffix("Z") + "+00:00" if date.endswith("Z") else date
        )
    except ValueError:
        return None
    return date, parsed


class _Fields:
    """Read one known result shape and record issues using only schema field names."""

    def __init__(
        self, raw: dict[str, object], issues: list[ReportIssue], prefix: str = ""
    ) -> None:
        self.raw = raw
        self.issues = issues
        self.prefix = prefix

    def issue(self, field: str, code: IssueCode = "invalid_value") -> None:
        self.issues.append({"field": self.prefix + field, "code": code})

    def child(self, field: str, value: dict[str, object]) -> "_Fields":
        return _Fields(value, self.issues, self.prefix + field + ".")

    def required_record(self, field: str) -> "_Fields":
        value = _record(self.raw.get(field))
        if value is None:
            raise ReportInputError
        return self.child(field, value)

    def required_choice(self, field: str, allowed: tuple[_Text, ...]) -> _Text:
        value = _choice(self.raw.get(field), allowed)
        if value is None:
            raise ReportInputError
        return value

    def require_keys(self, *keys: str) -> None:
        if not all(key in self.raw for key in keys):
            raise ReportInputError

    def optional(
        self, field: str, validate: Callable[[object], _T | None]
    ) -> _T | None:
        return self.checked(field, self.raw.get(field, _MISSING), validate)

    def checked(
        self, field: str, value: object, validate: Callable[[object], _T | None]
    ) -> _T | None:
        if value is None:
            return None
        try:
            safe = validate(value)
        except _RedactField as error:
            self.issue(field, error.code)
            return None
        if safe is None:
            self.issue(field)
        return safe

    def sequence(
        self, field: str, limit: int, validate: Callable[[str, object], _T | None]
    ) -> list[_T | None] | None:
        values = self.raw.get(field, _MISSING)
        if values is None:
            return None
        if type(values) is not list:
            self.issue(field)
            return None
        if len(values) > limit:
            self.issue(field, "value_too_long")
            return None
        return [
            validate(f"{field}[{index}]", value) for index, value in enumerate(values)
        ]


def _endpoint(fields: _Fields) -> SafeEndpoint:
    return {
        "hostname": fields.optional("hostname", _hostname),
        "port": fields.optional("port", lambda value: _integer(value, 1, 65535)),
    }


def _source_endpoint(fields: _Fields) -> SafeEndpoint:
    fields.require_keys("hostname", "port")
    return _endpoint(fields)


def _diagnostic_codes(fields: _Fields, allowed: tuple[_Text, ...]) -> list[_Text]:
    if "diagnostics" not in fields.raw:
        return []
    if fields.raw["diagnostics"] is None:
        fields.issue("diagnostics")
        return []

    def validate(path: str, value: object) -> _Text | None:
        code = _choice(value, allowed)
        if code is None:
            fields.issue(path)
        return code

    codes = fields.sequence("diagnostics", len(allowed), validate)
    return list(dict.fromkeys(code for code in codes or () if code is not None))


def _connectivity(fields: _Fields) -> SafeConnectivity:
    status = fields.required_choice("status", get_args(TLSStatus))
    fields.require_keys("failed_stage")
    stage = fields.optional(
        "failed_stage", lambda value: _choice(value, get_args(TLSStage))
    )
    version = fields.optional(
        "tls_version", lambda value: _choice(value, _NEGOTIATED_VERSIONS)
    )
    cipher = fields.optional(
        "cipher_suite", lambda value: _match(value, _CIPHER_NAME, 128)
    )
    verify_code = fields.optional("verify_code", _verification_code)
    if (
        (status == "ok" and stage is not None)
        or (status != "ok" and (version is not None or cipher is not None))
        or (status != "certificate_verification_failed" and verify_code is not None)
        or ((status == "tls_setup_error") != (stage == "tls_setup"))
        or (
            stage is not None and (stage == "validation") != (status == "invalid_input")
        )
    ):
        raise ReportInputError
    result: SafeConnectivity = {
        **_source_endpoint(fields),
        "status": status,
        "failed_stage": stage,
        "tls_version": version,
        "cipher_suite": cipher,
        "error_message": _TLS_DIAGNOSTICS.get(status),
        "verify_code": verify_code,
    }
    diagnostics = _diagnostic_codes(fields, get_args(_TLSAuditDiagnostic))
    if diagnostics:
        if (
            status == "invalid_input"
            or stage in ("validation", "tls_setup", "connect")
            or (
                "tls_version_unavailable" in diagnostics
                and (status != "ok" or version is not None)
            )
            or (
                "cipher_metadata_unavailable" in diagnostics
                and (status != "ok" or cipher is not None)
            )
        ):
            raise ReportInputError
        result["diagnostics"] = diagnostics
    return result


def _dns_san(value: object) -> str | None:
    if (
        type(value) is not str
        or len(value) > 255
        or not value.isascii()
        or ":" in value
    ):
        return None
    if _hostname(value.removeprefix("*.")) is None:
        return None
    return value


def _ip_san(value: object) -> str | None:
    if type(value) is not str or len(value) > 45 or "%" in value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _certificate_metadata(fields: _Fields) -> SafeCertificateMetadata:
    def san(path: str, value: object) -> SafeSAN | None:
        entry = _record(value)
        if entry is None:
            fields.issue(path)
            return None
        item = fields.child(path, entry)
        kind = _choice(entry.get("type"), ("dns", "ip"))
        if kind is None:
            item.issue("type")
            return None
        validator = _dns_san if kind == "dns" else _ip_san
        name = validator(entry.get("value"))
        if name is None:
            item.issue("value")
        return {"type": kind, "value": name}

    not_before = fields.optional("not_valid_before", _utc_date)
    not_after = fields.optional("not_valid_after", _utc_date)
    remaining = fields.optional(
        "remaining_seconds", lambda value: _duration(value, signed=True)
    )
    expiration = fields.required_choice("expiration_status", get_args(ExpirationStatus))
    if (
        not_before is not None
        and not_after is not None
        and not_before[1] > not_after[1]
    ):
        raise ReportInputError
    if remaining is not None and (remaining <= 0) != (expiration == "expired"):
        raise ReportInputError
    return {
        "subject": fields.optional("subject", _distinguished_name),
        "issuer": fields.optional("issuer", _distinguished_name),
        "serial_number": fields.optional(
            "serial_number", lambda value: _match(value, _SERIAL, 128)
        ),
        "sans": fields.sequence("sans", _MAX_SANS, san),
        "not_valid_before": not_before[0] if not_before is not None else None,
        "not_valid_after": not_after[0] if not_after is not None else None,
        "remaining_seconds": remaining,
        "expiration_status": expiration,
        "sha256_fingerprint": fields.optional(
            "sha256_fingerprint", lambda value: _match(value, _FINGERPRINT, 64)
        ),
    }


def _certificate(fields: _Fields) -> SafeCertificate:
    status = fields.required_choice("certificate_status", get_args(CertificateStatus))
    connectivity = None
    certificate = None
    diagnostic = None
    if status == "invalid_options":
        diagnostic = "warning_days must be a nonnegative integer"
    else:
        connectivity = _connectivity(fields.required_record("connectivity"))
        if (status in {"ok", "metadata_error"}) != (connectivity["status"] == "ok"):
            raise ReportInputError
        if status == "ok":
            certificate = _certificate_metadata(fields.required_record("certificate"))
        elif status == "metadata_error":
            diagnostic = (
                _choice(fields.raw.get("certificate_error"), _CERTIFICATE_ERRORS)
                or "Unable to collect verified certificate metadata."
            )
    if (
        status == "invalid_options"
        and fields.raw.get("connectivity", _MISSING) is not None
    ) or (status != "ok" and fields.raw.get("certificate", _MISSING) is not None):
        raise ReportInputError
    return {
        "connectivity": connectivity,
        "certificate_status": status,
        "certificate": certificate,
        "certificate_error": diagnostic,
    }


def _protocol_probe(fields: _Fields) -> SafeProtocolProbe:
    outcome = fields.required_choice("outcome", get_args(ProtocolOutcome))
    requested = fields.required_choice("requested_version", _REQUESTED_VERSIONS)
    version = fields.optional(
        "negotiated_version", lambda value: _choice(value, _NEGOTIATED_VERSIONS)
    )
    code = fields.optional(
        "evidence_code", lambda value: _choice(value, _EVIDENCE_CODES)
    )
    stage = fields.optional(
        "failed_stage", lambda value: _choice(value, get_args(TLSStage))
    )
    verify_code = fields.optional("verify_code", _verification_code)
    cipher = fields.optional(
        "cipher_suite", lambda value: _match(value, _CIPHER_NAME, 128)
    )
    secret_bits = fields.optional(
        "secret_bits", lambda value: _integer(value, 0, 65535)
    )
    diagnostics = _diagnostic_codes(fields, get_args(_TLSAuditDiagnostic))
    failed_before_connect = code in (
        "invalid_input",
        "runtime_version_unavailable",
        "client_version_policy",
        "client_version_configuration",
    )
    if diagnostics and (
        failed_before_connect or stage in ("validation", "tls_setup", "connect")
    ):
        raise ReportInputError
    if (
        code == "tls_version_unavailable" or "tls_version_unavailable" in diagnostics
    ) and (
        outcome != "inconclusive"
        or code not in (None, "tls_version_unavailable")
        or any(item is not None for item in (version, stage, verify_code))
    ):
        raise ReportInputError
    if "cipher_metadata_unavailable" in diagnostics:
        cipher_read_possible = code in (
            None,
            "verified_handshake",
            "unexpected_negotiated_version",
            "tls_version_unavailable",
        )
        if (
            not cipher_read_possible
            or outcome in ("client_restricted", "server_rejected")
            or any(
                item is not None for item in (cipher, secret_bits, stage, verify_code)
            )
        ):
            raise ReportInputError
    if (code == "tls_setup_error") != (stage == "tls_setup"):
        raise ReportInputError
    if stage == "tls_setup" and (
        outcome != "inconclusive"
        or any(item is not None for item in (version, cipher, secret_bits, verify_code))
    ):
        raise ReportInputError
    if outcome == "confirmed_supported" and (
        version != requested
        or code != "verified_handshake"
        or stage is not None
        or verify_code is not None
    ):
        raise ReportInputError
    if outcome == "server_rejected" and (
        code != "TLSV1_ALERT_PROTOCOL_VERSION"
        or stage not in (None, "handshake")
        or any(item is not None for item in (version, cipher, secret_bits, verify_code))
    ):
        raise ReportInputError
    diagnostic = None
    if outcome != "confirmed_supported":
        diagnostic = _PROBE_DIAGNOSTICS.get(code) if code is not None else None
        diagnostic = (
            diagnostic
            or {
                "client_restricted": "The client could not probe this version under its TLS policy.",
                "server_rejected": "The peer rejected the requested TLS version.",
                "inconclusive": "The probe did not establish support for the requested TLS version.",
            }[outcome]
        )
    result: SafeProtocolProbe = {
        "requested_version": requested,
        "outcome": outcome,
        "evidence_code": code,
        "negotiated_version": version,
        "cipher_suite": cipher,
        "secret_bits": secret_bits,
        "failed_stage": stage,
        "error_message": diagnostic,
        "verify_code": verify_code,
    }
    if diagnostics:
        result["diagnostics"] = diagnostics
    return result


def _protocols(fields: _Fields) -> SafeProtocols:
    def recommendation(path: str, value: object) -> SafeRecommendation | None:
        entry = fields.checked(path, value, _record)
        if entry is None:
            return None
        code = fields.child(path, entry).optional(
            "code", lambda value: _choice(value, tuple(_PROTOCOL_ADVICE))
        )
        return (
            {"code": code, "message": _PROTOCOL_ADVICE[code]}
            if code is not None
            else None
        )

    status = fields.required_choice("status", get_args(ProtocolStatus))
    raw_probes = fields.raw.get("probes")
    if (
        type(raw_probes) is not list
        or len(raw_probes) > 4
        or bool(raw_probes) != (status == "ok")
    ):
        raise ReportInputError
    probes = []
    outcomes_by_version: dict[str, ProtocolOutcome] = {}
    for index, raw_probe in enumerate(raw_probes):
        probe = _record(raw_probe)
        if probe is None:
            raise ReportInputError
        safe_probe = _protocol_probe(fields.child(f"probes[{index}]", probe))
        requested = safe_probe["requested_version"]
        outcome = safe_probe["outcome"]
        if outcomes_by_version.setdefault(requested, outcome) != outcome:
            raise ReportInputError
        probes.append(safe_probe)
    recommendations = fields.sequence(
        "recommendations", len(_PROTOCOL_ADVICE), recommendation
    )
    confirmed = {
        probe["requested_version"]
        for probe in probes
        if probe["outcome"] == "confirmed_supported"
    }
    advice_supported = {
        "disable_legacy_tls": bool(confirmed & {"TLSv1", "TLSv1.1"}),
        "review_tls_1_3": "TLSv1.2" in confirmed
        and any(
            probe["requested_version"] == "TLSv1.3"
            and probe["outcome"] == "server_rejected"
            for probe in probes
        ),
    }
    if any(
        item is not None and not advice_supported[item["code"]]
        for item in recommendations or ()
    ):
        raise ReportInputError
    target = _source_endpoint(fields.required_record("target"))
    not_probed = fields.sequence(
        "not_probed",
        4,
        lambda path, value: fields.checked(
            path, value, lambda item: _choice(item, _REQUESTED_VERSIONS)
        ),
    )
    if any(version in outcomes_by_version for version in not_probed or ()):
        raise ReportInputError
    return {
        "target": target,
        "status": status,
        "error_message": _TLS_DIAGNOSTICS.get(status),
        "probes": probes,
        "not_probed": not_probed,
        "recommendations": recommendations,
    }


def _http_probe(fields: _Fields) -> SafeHTTPProbe:
    outcome = fields.required_choice("outcome", get_args(HTTPOutcome))
    fields.require_keys("failed_stage")
    stage = fields.optional(
        "failed_stage", lambda value: _choice(value, get_args(HTTPStage))
    )
    status = fields.optional("http_status", lambda value: _integer(value, 200, 599))
    verify_code = fields.optional("verify_code", _verification_code)
    if (
        (outcome == "available" and stage is not None)
        or (outcome != "available" and status is not None)
        or (outcome != "certificate_verification_failed" and verify_code is not None)
        or (stage == "tls_setup" and outcome == "certificate_verification_failed")
    ):
        raise ReportInputError
    result: SafeHTTPProbe = {
        "outcome": outcome,
        "http_status": status,
        "failed_stage": stage,
        "verify_code": verify_code,
        "elapsed_ms": fields.optional("elapsed_ms", _duration),
    }
    diagnostics = _diagnostic_codes(fields, get_args(_HTTPAuditDiagnostic))
    if diagnostics:
        if (
            outcome == "invalid_input"
            or stage in ("validation", "tls_setup", "connect")
            or (
                "http_response_close_failed" in diagnostics
                and stage in ("handshake", "request")
            )
        ):
            raise ReportInputError
        result["diagnostics"] = diagnostics
    return result


def _https(fields: _Fields) -> SafeHTTPS:
    probe = _http_probe(fields)
    status = probe["http_status"]
    is_redirect = fields.optional("is_redirect", _boolean)
    if probe["failed_stage"] == "tls_setup" and is_redirect is not None:
        raise ReportInputError
    if (
        status is not None
        and is_redirect is not None
        and is_redirect != (status in _REDIRECT_STATUSES)
    ):
        raise ReportInputError
    return {
        **probe,
        "target": _source_endpoint(fields.required_record("target")),
        "is_redirect": is_redirect,
    }


def _check_redirect(
    source: SafeRedirectSource,
    probe: SafeHTTPProbe,
    assessment: SafeRedirectAssessment,
    recommendations: list[str | None] | None,
) -> None:
    outcome = assessment["outcome"]
    status = probe["http_status"]
    if (outcome == "not_evaluated") == (probe["outcome"] == "available"):
        raise ReportInputError
    if status is not None:
        if status in _REDIRECT_STATUSES:
            if outcome in {"no_redirect", "unsupported_redirect_status"}:
                raise ReportInputError
        else:
            expected = (
                "unsupported_redirect_status" if status in {305, 306} else "no_redirect"
            )
            if outcome != expected:
                raise ReportInputError

    source_scheme = source["scheme"]
    if source_scheme == "http" and (
        probe["failed_stage"] == "tls_setup"
        or probe["outcome"] == "certificate_verification_failed"
    ):
        raise ReportInputError
    destination = assessment["destination"]
    destination_scheme = destination["scheme"] if destination is not None else None
    has_origin = outcome in {"upgrade", "downgrade", "same_scheme_redirect"}
    same_host = assessment["same_host"]
    port_changed = assessment["port_changed"]
    if not has_origin and (
        destination is not None or same_host is not None or port_changed is not None
    ):
        raise ReportInputError
    if outcome == "upgrade" and (
        source_scheme not in (None, "http") or destination_scheme not in (None, "https")
    ):
        raise ReportInputError
    if outcome == "downgrade" and (
        source_scheme not in (None, "https") or destination_scheme not in (None, "http")
    ):
        raise ReportInputError
    if (
        outcome == "same_scheme_redirect"
        and source_scheme is not None
        and destination_scheme is not None
        and source_scheme != destination_scheme
    ):
        raise ReportInputError

    destination_port = None
    if destination is not None:
        if source["hostname"] is not None and destination["hostname"] is not None:
            hosts_match = source["hostname"] == destination["hostname"]
            if same_host is not None and same_host != hosts_match:
                raise ReportInputError
            same_host = hosts_match
        destination_port = destination["port"]
        if source["port"] is not None and destination_port is not None:
            ports_differ = source["port"] != destination_port
            if port_changed is not None and port_changed != ports_differ:
                raise ReportInputError
            port_changed = ports_differ

    allowed_advice = {
        "https_to_http_downgrade": outcome == "downgrade",
        "review_https_upgrade": outcome in {"no_redirect", "same_scheme_redirect"}
        and source_scheme != "https"
        and destination_scheme != "https",
        "review_cross_host_redirect": has_origin and same_host is not True,
        "review_unusual_redirect_port": has_origin
        and port_changed is not False
        and (
            destination_scheme is None
            or destination_port != _DEFAULT_PORTS[destination_scheme]
        ),
    }
    if any(
        code is not None and not allowed_advice[code] for code in recommendations or ()
    ):
        raise ReportInputError


def _redirect(fields: _Fields) -> SafeRedirect:
    def origin(value: object) -> SafeRedirectDestination | None:
        record = _record(value)
        if record is None:
            return None
        destination = assessment.child("destination", record)
        return {
            **_endpoint(destination),
            "scheme": destination.optional(
                "scheme", lambda value: _choice(value, get_args(Scheme))
            ),
            "verification": destination.optional(
                "verification", lambda value: _choice(value, ("not_attempted",))
            ),
        }

    source = fields.required_record("source")
    assessment = fields.required_record("redirect")
    probe = _http_probe(fields.required_record("probe"))
    safe_source: SafeRedirectSource = {
        **_source_endpoint(source),
        "scheme": source.optional(
            "scheme", lambda value: _choice(value, get_args(Scheme))
        ),
    }
    safe_assessment: SafeRedirectAssessment = {
        "outcome": assessment.required_choice("outcome", get_args(RedirectOutcome)),
        "destination": assessment.optional("destination", origin),
        "same_host": assessment.optional("same_host", _boolean),
        "port_changed": assessment.optional("port_changed", _boolean),
    }
    recommendations = fields.sequence(
        "recommendations",
        len(_REDIRECT_ADVICE),
        lambda path, value: fields.checked(
            path, value, lambda item: _choice(item, _REDIRECT_ADVICE)
        ),
    )
    _check_redirect(safe_source, probe, safe_assessment, recommendations)
    return {
        "source": safe_source,
        "probe": probe,
        "redirect": safe_assessment,
        "recommendations": recommendations,
    }


def to_safe_audit_report(kind: AuditKind, result: RawAuditResult) -> SafeAuditReport:
    """Project an auditor result for JSON reporting without retaining its raw containers."""
    if type(kind) is not str:
        raise ReportInputError
    raw = _record(result)
    if raw is None:
        raise ReportInputError

    issues: list[ReportIssue] = []
    fields = _Fields(raw, issues)
    report: _Report = {"schema_version": 1, "issues": issues}
    if kind == "tls_connectivity":
        return {**report, "kind": kind, "data": _connectivity(fields)}
    if kind == "tls_certificate":
        return {**report, "kind": kind, "data": _certificate(fields)}
    if kind == "tls_protocols":
        return {**report, "kind": kind, "data": _protocols(fields)}
    if kind == "https_availability":
        return {**report, "kind": kind, "data": _https(fields)}
    if kind == "http_redirect":
        return {**report, "kind": kind, "data": _redirect(fields)}
    raise ReportInputError
