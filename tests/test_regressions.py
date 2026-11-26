"""Regression tests for security-review items M1-02 to M1-05. All offline: no network at all."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from webguard.auditors.http_audit import MAX_EVIDENCE, audit, check_cookies, check_csp  # noqa: E402
from webguard.core.models import ResponseData  # noqa: E402


def make(headers, url="https://example.test/"):
    return ResponseData(url=url, status=200, headers=headers)


def ids(findings):
    return {f.check_id for f in findings}


# ---------------- M1-02 sensitive data exposure ----------------
def test_malformed_cookie_names_never_reach_findings():
    for raw in ("bad name=SECRETVALUE", "=SECRETVALUE", "na\x00me=SECRETVALUE", "no-equals-SECRETVALUE", "a(b)=SECRETVALUE"):
        findings = check_cookies(make([("Set-Cookie", raw)]))
        assert ids(findings) == {"COOKIE:malformed"}
        dump = json.dumps([f.to_dict() for f in findings])
        assert "SECRETVALUE" not in dump and "bad name" not in dump and "\x00" not in dump
        assert findings[0].evidence == ""


def test_cookie_name_and_evidence_are_bounded():
    long_name = "s" * 500
    for f in check_cookies(make([("Set-Cookie", f"{long_name}=v")])):
        assert len(f.evidence) <= MAX_EVIDENCE + 3
        assert len(f.title) <= 83


def test_disclosure_headers_are_sanitised():
    headers = [("Server", "Apache/2.4.1 (Debian) token=SECRET123 \x1b[31m"), ("X-Backend-Server", "10.0.3.17")]
    findings = audit(make(headers))
    dump = json.dumps([f.to_dict() for f in findings])
    assert "SECRET123" not in dump and "10.0.3.17" not in dump and "\x1b" not in dump
    assert all(len(f.evidence) <= MAX_EVIDENCE + 3 for f in findings)
    assert "DISC:server" in ids(findings) and "DISC:internal-ip" in ids(findings)


def test_raw_headers_and_body_are_not_in_repr():
    resp = ResponseData("http://127.0.0.1/", 200, [("Set-Cookie", "sid=SECRETVALUE")], "BODYSECRET")
    text = repr(resp) + str(resp)
    assert "SECRETVALUE" not in text and "BODYSECRET" not in text


# ---------------- M1-03 disabled or invalid protections ----------------
def test_hsts_max_age_zero_is_flagged():
    assert "HDR:hsts-disabled" in ids(audit(make([("Strict-Transport-Security", "max-age=0")])))


def test_hsts_invalid_or_short_is_flagged():
    assert "HDR:hsts-invalid" in ids(audit(make([("Strict-Transport-Security", "includeSubDomains")])))
    assert "HDR:hsts-invalid" in ids(audit(make([("Strict-Transport-Security", "max-age=abc")])))
    assert "HDR:hsts-short" in ids(audit(make([("Strict-Transport-Security", "max-age=60")])))
    assert not {"HDR:hsts", "HDR:hsts-invalid", "HDR:hsts-disabled", "HDR:hsts-short"} & ids(
        audit(make([("Strict-Transport-Security", "max-age=31536000; includeSubDomains")])))


def test_invalid_x_frame_options_values():
    for value in ("ALLOW-FROM https://a.test", "FOO", "", "DENY, SAMEORIGIN"):
        assert "HDR:xfo-invalid" in ids(audit(make([("X-Frame-Options", value)]))), value
    assert not {"HDR:xfo-invalid", "HDR:clickjacking"} & ids(audit(make([("X-Frame-Options", "sameorigin")])))


def test_frame_ancestors_must_be_a_real_directive():
    for csp in ("default-src 'self'; report-uri /frame-ancestors", "default-src 'self'; x-frame-ancestors 'none'",
                "default-src 'self' frame-ancestors"):
        assert "HDR:clickjacking" in ids(audit(make([("Content-Security-Policy", csp)]))), csp
    assert "HDR:clickjacking" not in ids(audit(make([("Content-Security-Policy", "FRAME-ANCESTORS 'self'")])))
    assert "HDR:frame-ancestors-wildcard" in ids(audit(make([("Content-Security-Policy", "frame-ancestors *")])))


def test_samesite_attribute_name_and_value_validation():
    assert "COOKIE:samesite" in ids(check_cookies(make([("Set-Cookie", "a=1; Secure; HttpOnly; samesite-x=Lax")])))
    assert "COOKIE:samesite-invalid" in ids(check_cookies(make([("Set-Cookie", "a=1; SameSite=Banana")])))
    assert "COOKIE:samesite-invalid" in ids(check_cookies(make([("Set-Cookie", "a=1; SameSite")])))
    assert "COOKIE:samesite-none-insecure" in ids(check_cookies(make([("Set-Cookie", "a=1; SameSite=None")])))
    assert not {"COOKIE:samesite", "COOKIE:samesite-invalid"} & ids(
        check_cookies(make([("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=lax")])))


def test_cookie_prefix_rules():
    assert "COOKIE:prefix" in ids(check_cookies(make([("Set-Cookie", "__Host-a=1; Secure; Path=/; Domain=x.test")])))
    assert "COOKIE:prefix" not in ids(check_cookies(make([("Set-Cookie", "__Host-a=1; Secure; Path=/; HttpOnly; SameSite=Strict")])))


# ---------------- M1-04 CSP analysis ----------------
def csp(*values):
    return make([("Content-Security-Policy", v) for v in values])


def test_duplicate_directive_first_wins():
    assert "CSP:unsafe-inline" not in ids(check_csp(csp("script-src 'self'; script-src 'unsafe-inline'")))
    assert "CSP:unsafe-inline" in ids(check_csp(csp("script-src 'unsafe-inline'; script-src 'self'")))


def test_nonce_hash_and_strict_dynamic_neutralise_unsafe_inline():
    for extra in ("'nonce-abc123'", "'sha256-AAAA'", "'strict-dynamic'"):
        assert "CSP:unsafe-inline" not in ids(check_csp(csp(f"script-src 'unsafe-inline' {extra}")))


def test_multiple_policies_weakness_only_if_every_policy_has_it():
    strict, weak = "script-src 'self'", "script-src 'self' 'unsafe-inline'"
    assert "CSP:unsafe-inline" not in ids(check_csp(csp(weak, strict)))            # two headers
    assert "CSP:unsafe-inline" not in ids(check_csp(csp(f"{weak}, {strict}")))      # one header, comma-separated
    assert "CSP:unsafe-inline" in ids(check_csp(csp(weak, weak)))


def test_wildcard_detection_is_exact():
    assert "CSP:wildcard" in ids(check_csp(csp("script-src *")))
    assert "CSP:wildcard" in ids(check_csp(csp("default-src https:")))
    assert "CSP:wildcard" not in ids(check_csp(csp("script-src https://*.example.com 'self'")))


def test_script_and_style_policies_are_separate():
    findings = ids(check_csp(csp("script-src 'self'; style-src 'self' 'unsafe-inline'")))
    assert "CSP:style-unsafe-inline" in findings and "CSP:unsafe-inline" not in findings
    assert "CSP:unsafe-inline" in ids(check_csp(csp("default-src 'unsafe-inline'")))     # falls back to default-src


def test_policy_without_script_restriction_and_report_only():
    assert "CSP:no-script-restriction" in ids(check_csp(csp("frame-ancestors 'none'")))
    report_only = make([("Content-Security-Policy-Report-Only", "default-src 'self'")])
    assert ids(check_csp(report_only)) == {"CSP:report-only"}


# ---------------- M1-05 finding accuracy ----------------
def test_cors_wording_and_severity():
    wildcard = [f for f in audit(make([("Access-Control-Allow-Origin", "*")])) if f.check_id == "HDR:cors"][0]
    assert wildcard.severity == "LOW"
    both = audit(make([("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]))
    assert "HDR:cors-credentials" in ids(both) and "HDR:cors" not in ids(both)
    assert "HDR:cors-null" in ids(audit(make([("Access-Control-Allow-Origin", "null")])))


def test_referrer_policy_validation():
    assert "HDR:referrer-invalid" in ids(audit(make([("Referrer-Policy", "banana")])))
    assert "HDR:referrer-weak" in ids(audit(make([("Referrer-Policy", "unsafe-url")])))
    assert "HDR:referrer-weak" in ids(audit(make([("Referrer-Policy", "no-referrer, unsafe-url")])))   # last valid wins
    assert not {"HDR:referrer", "HDR:referrer-invalid", "HDR:referrer-weak"} & ids(
        audit(make([("Referrer-Policy", "strict-origin-when-cross-origin")])))


def test_disclosure_heuristics():
    assert "DISC:x-powered-by" in ids(audit(make([("X-Powered-By", "Express")])))   # reveals technology even without a version
    assert "DISC:server" not in ids(audit(make([("Server", "nginx")])))              # bare product name is not flagged
    assert "DISC:server" in ids(audit(make([("Server", "nginx/1.18.0")])))
    internal = [f for f in audit(make([("X-Backend", "10.1.2.3")])) if f.check_id == "DISC:internal-ip"][0]
    assert internal.evidence == "X-Backend"
