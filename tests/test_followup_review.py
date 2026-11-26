"""Regression tests for the follow-up security review (M1-01 to M1-05). All offline / loopback only."""

import http.client
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from demo.loopback_fetch import FetchRefused, _check_target, fetch  # noqa: E402
from webguard.auditors.http_audit import audit, check_csp  # noqa: E402
from webguard.core.models import ResponseData  # noqa: E402


def make(headers, url="https://example.test/"):
    return ResponseData(url=url, status=200, headers=headers)


def ids(findings):
    return {f.check_id for f in findings}


def one(findings, check_id):
    return [f for f in findings if f.check_id == check_id][0]


def csp(value):
    return make([("Content-Security-Policy", value)])


# ---------------- M1-01: explicit port 0 ----------------
def test_port_zero_is_refused_not_defaulted_to_80(monkeypatch):
    monkeypatch.setattr(http.client.HTTPConnection, "connect",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("connection attempted")))
    with pytest.raises(FetchRefused):
        fetch("http://127.0.0.1:0/")
    with pytest.raises(FetchRefused):
        fetch("http://[::1]:0/")


def test_default_port_is_still_80_and_loopback_rules_stay():
    assert _check_target("http://127.0.0.1/x?y=1") == ("127.0.0.1", 80, "/x?y=1")
    assert _check_target("http://127.0.0.1:8080/")[1] == 8080
    for bad in ("http://localhost/", "https://127.0.0.1/", "http://127.0.0.1@evil.test/"):
        with pytest.raises(FetchRefused):
            _check_target(bad)


# ---------------- M1-02: disclosure evidence and repr ----------------
def test_disclosure_evidence_is_allowlisted():
    cases = {
        "token/1abc123SECRET": "Server",                      # unknown product: only the header name is shown
        "Apache/2.4.1 secret/9.9.9": "Server: apache",       # retain only the allowlisted product
        "Apache/2.4.1-SECRET": "Server",                      # version is not strictly numeric
        "nginx/1.18.0": "Server: nginx",
    }
    for value, expected in cases.items():
        finding = one(audit(make([("Server", value)])), "DISC:server")
        assert finding.evidence == expected, value
    assert one(audit(make([("X-Powered-By", "evilprod/1.2.3")])), "DISC:x-powered-by").evidence == "X-Powered-By"
    for f in audit(make([("Server", "token/1abc123SECRET")])):
        assert "SECRET" not in json.dumps(f.to_dict())
    assert "DISC:server" not in ids(audit(make([("Server", "token/abc123SECRET")])))   # no version shape, nothing reported


def test_repr_does_not_expose_url_tokens():
    url = "https://user:pw@example.test:8443/path/secretpath?token=SECRETTOKEN&k=v#frag"
    resp = ResponseData(url, 200, [("Set-Cookie", "sid=COOKIESECRET")], "BODYSECRET")
    for text in (repr(resp), str(resp), f"{resp!r}", f"{[resp]}"):
        for secret in ("SECRETTOKEN", "user", "pw@", "secretpath", "frag", "COOKIESECRET", "BODYSECRET", "k=v"):
            assert secret not in text, (secret, text)
        assert "example.test" in text and "8443" in text
    assert "unparseable" in repr(ResponseData("http://[::1", 200, []))
    assert isinstance(repr(ResponseData("http://x:99999/?t=SECRET", 200, [])), str)


# ---------------- M1-03: HSTS validation ----------------
@pytest.mark.parametrize("value", [
    "max-age=31536000; max-age=0",               # duplicate max-age
    "max-age=0; max-age=31536000",
    "max-age=31536000; includeSubDomains; includeSubDomains",
    "max-age=" + "9" * 5000,                     # oversized number must not raise
    "max-age=" + "9" * 13,
    "max-age=²",                            # superscript two: str.isdigit() is True but int() fails
    "max-age=١٢٣",                # Arabic-Indic digits
    "max-age=-5",
    "max-age=1e9",
    "max-age=",
    "max-age=31536000; include SubDomains",      # bad directive syntax
    "includeSubDomains",
])
def test_malformed_hsts_is_invalid_and_never_raises(value):
    findings = audit(make([("Strict-Transport-Security", value)]))
    assert "HDR:hsts-invalid" in ids(findings), value


def test_valid_hsts_forms_are_accepted():
    for value in ("max-age=31536000", 'max-age="31536000"', "max-age=31536000;", "MAX-AGE=31536000; includeSubDomains; preload",
                  "max-age=31536000; unknown-ext=1"):
        found = ids(audit(make([("Strict-Transport-Security", value)])))
        assert not {"HDR:hsts", "HDR:hsts-invalid", "HDR:hsts-disabled", "HDR:hsts-short"} & found, value


def test_audit_survives_garbage_headers():
    garbage = [("Strict-Transport-Security", "max-age=" + "9" * 100_000), ("Referrer-Policy", "\x00" * 50),
               ("Set-Cookie", "²=²"), ("Content-Security-Policy", ";;;,,,; ;"), ("X-Frame-Options", "\n")]
    assert isinstance(audit(make(garbage)), list)


# ---------------- M1-04: CSP accuracy ----------------
def test_strict_dynamic_does_not_suppress_style_findings():
    assert "CSP:style-unsafe-inline" in ids(check_csp(csp("style-src 'unsafe-inline' 'strict-dynamic'")))
    assert "CSP:unsafe-inline" not in ids(check_csp(csp("script-src 'unsafe-inline' 'strict-dynamic'")))
    both = ids(check_csp(csp("default-src 'unsafe-inline' 'strict-dynamic'")))
    assert "CSP:style-unsafe-inline" in both and "CSP:unsafe-inline" not in both
    assert "CSP:style-unsafe-inline" not in ids(check_csp(csp("style-src 'unsafe-inline' 'nonce-abc'")))


def test_script_src_elem_counts_as_a_script_restriction():
    assert "CSP:no-script-restriction" not in ids(check_csp(csp("script-src-elem 'self'")))
    assert "CSP:no-script-restriction" in ids(check_csp(csp("script-src-attr 'self'")))   # attributes only: elements open


def test_script_elem_and_attr_directives_are_analysed():
    assert "CSP:unsafe-inline" in ids(check_csp(csp("script-src-elem 'self' 'unsafe-inline'")))
    assert "CSP:unsafe-inline" in ids(check_csp(csp("script-src 'self'; script-src-attr 'unsafe-inline'")))
    assert "CSP:unsafe-inline" in ids(check_csp(csp("script-src-elem 'self' 'unsafe-inline'; script-src 'self'")))
    assert "CSP:unsafe-inline" not in ids(
        check_csp(csp("script-src 'self' 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'self'")))
    assert "CSP:wildcard" in ids(check_csp(csp("script-src-elem *")))
    assert "CSP:style-unsafe-inline" in ids(check_csp(csp("style-src-elem 'unsafe-inline'")))


# ---------------- M1-05: Referrer-Policy fields and IP validation ----------------
def test_multiple_referrer_policy_header_fields():
    weak_last = make([("Referrer-Policy", "no-referrer"), ("Referrer-Policy", "unsafe-url")])
    strong_last = make([("Referrer-Policy", "unsafe-url"), ("Referrer-Policy", "no-referrer")])
    assert "HDR:referrer-weak" in ids(audit(weak_last))
    assert not {"HDR:referrer-weak", "HDR:referrer", "HDR:referrer-invalid"} & ids(audit(strong_last))
    assert "HDR:referrer-invalid" in ids(audit(make([("Referrer-Policy", ""), ("Referrer-Policy", "banana")])))
    assert "HDR:referrer" in ids(audit(make([("Referrer-Policy", "")])))


@pytest.mark.parametrize("value", ["999.1.1.1", "10.999.1.1", "300.168.1.1", "010.0.0.1", "172.32.0.1", "1.2.3.4",
                                   "10.0.0.1.2", "v1.10.0.0.1", "192.169.1.1"])
def test_not_a_real_private_ip_gives_no_finding(value):
    assert "DISC:internal-ip" not in ids(audit(make([("X-Backend", value)])))


@pytest.mark.parametrize("value", ["10.0.3.17", "192.168.1.1", "172.16.0.1", "172.31.255.255", "host=10.1.2.3:8080"])
def test_real_private_ip_gives_finding_with_header_name_only(value):
    finding = one(audit(make([("X-Backend", value)])), "DISC:internal-ip")
    assert finding.evidence == "X-Backend"


def test_m1_02_disclosure_markers_are_not_reported(monkeypatch, tmp_path):
    from webguard.core.audit_integration import integrate_audit_results
    from webguard.reporting.html_report import generate_html_report
    from webguard.reporting.json_report import generate_json_report

    version = "314.159.265"
    header_name = "X-SYNTH-M1-PRIVATE-MARKER"
    findings = audit(make([("Server", f"APACHE/{version}"), (header_name, "10.1.2.3")]))
    assert one(findings, "DISC:server").evidence == "Server: apache"
    assert one(findings, "DISC:internal-ip").evidence == "Private IPv4 address detected"

    monkeypatch.chdir(tmp_path)
    result = integrate_audit_results(findings, [], {"POL-007"})
    json_text = generate_json_report(result).read_text(encoding="utf-8")
    html_text = generate_html_report(result).read_text(encoding="utf-8")
    report = json.loads(json_text)
    json.dumps(report, allow_nan=False)
    assert {"DISC:server", "DISC:internal-ip"} <= {
        item["check_id"] for item in report["findings"]
    }
    assert "Internal IP address in a response header" in html_text
    evidence = json.dumps([finding.to_dict() for finding in findings])
    for marker in (version, header_name, "10.1.2.3"):
        assert all(marker not in text for text in (evidence, json_text, html_text))


@pytest.mark.parametrize(
    ("value", "invalid"),
    [
        pytest.param("31536000", False, id="unquoted"),
        pytest.param('"31536000"', False, id="quoted"),
        pytest.param('"' + "9" * 12 + '"', False, id="local-limit"),
        pytest.param('"' + "9" * 13 + '"', True, id="over-local-limit"),
        pytest.param('"31536000', True, id="opening-quote-only"),
        pytest.param('31536000"', True, id="closing-quote-only"),
        pytest.param('""31536000""', True, id="repeated-quotes"),
        pytest.param('"31"536000"', True, id="embedded-quote"),
    ],
)
def test_m1_03_hsts_max_age_requires_one_balanced_quote_pair(value, invalid):
    found = ids(audit(make([("Strict-Transport-Security", f"max-age={value}")])))
    assert ("HDR:hsts-invalid" in found) is invalid


def test_m1_03_hsts_invalid_wording_describes_local_validation():
    value = "max-age=" + "9" * 13
    finding = one(
        audit(make([("Strict-Transport-Security", value)])), "HDR:hsts-invalid"
    )
    assert "this auditor" in finding.detail.lower()
    assert "12" in finding.detail


@pytest.mark.parametrize(
    ("policy", "reported"),
    [
        pytest.param(
            "default-src 'unsafe-eval'; script-src-elem 'self'; script-src-attr 'self'",
            True,
            id="default-fallback",
        ),
        pytest.param(
            "script-src 'unsafe-eval'; script-src-elem 'self'; script-src-attr 'self'",
            True,
            id="script-directive",
        ),
        pytest.param(
            "script-src 'self'; script-src-elem 'unsafe-eval'", False, id="element-only"
        ),
        pytest.param(
            "script-src 'self'; script-src-attr 'unsafe-eval'",
            False,
            id="attribute-only",
        ),
        pytest.param(
            "default-src 'unsafe-eval'; script-src 'self'",
            False,
            id="script-overrides-default",
        ),
    ],
)
def test_m1_04_csp_eval_uses_script_and_default_sources(policy, reported):
    assert ("CSP:unsafe-eval" in ids(check_csp(csp(policy)))) is reported


def test_m1_04_csp_attribute_wildcard_is_not_a_network_source():
    found = ids(check_csp(csp("script-src 'self'; script-src-attr *")))
    assert "CSP:wildcard" not in found
    assert "CSP:wildcard" in ids(
        check_csp(csp("script-src-elem *; script-src-attr 'none'"))
    )


@pytest.mark.parametrize(
    ("policy", "context"),
    [
        pytest.param(
            "script-src 'self'; script-src-elem 'unsafe-inline'",
            "script elements",
            id="elements",
        ),
        pytest.param(
            "script-src 'self'; script-src-attr 'unsafe-inline'",
            "event-handler attributes",
            id="attributes",
        ),
    ],
)
def test_m1_04_csp_inline_finding_names_its_context(policy, context):
    finding = one(check_csp(csp(policy)), "CSP:unsafe-inline")
    assert context in finding.title


def test_m1_05_referrer_warning_distinguishes_downgrade():
    response = make(
        [
            ("Referrer-Policy", "no-referrer"),
            ("Referrer-Policy", "no-referrer-when-downgrade, unknown"),
        ]
    )
    finding = one(audit(response), "HDR:referrer-weak")
    assert finding.severity == "LOW"
    assert finding.evidence == "no-referrer-when-downgrade"
    assert "same security level" in finding.detail
    assert "omits" in finding.detail and "HTTPS-to-HTTP" in finding.detail


def test_m1_02_internal_ip_uses_fixed_evidence_for_unlisted_header():
    response = make([("X-SYNTH-M1-PRIVATE-MARKER", "10.1.2.3")])
    finding = one(audit(response), "DISC:internal-ip")
    assert finding.evidence == "Private IPv4 address detected"
