import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from demo.loopback_fetch import fetch  # noqa: E402
from demo.servers import HardenedHandler, WeakHandler, start  # noqa: E402
from webguard.auditors.http_audit import audit, summarize  # noqa: E402
from webguard.auditors.http_audit.cookies import audit_cookies, is_sensitive, parse_set_cookie  # noqa: E402
from webguard.auditors.http_audit.csp import audit_csp, effective, parse_csp  # noqa: E402
from webguard.auditors.http_audit.disclosure import audit_disclosure  # noqa: E402
from webguard.auditors.http_audit.headers import audit_headers  # noqa: E402
from webguard.core.models import ResponseData  # noqa: E402


def resp(headers=(), url="https://example.com/", body=""):
    return ResponseData(url, 200, list(headers), body)


def ids(findings):
    return {f.check_id for f in findings}


# ---------- models ----------
def test_header_lookup_is_case_insensitive_and_keeps_duplicates():
    r = resp([("set-cookie", "a=1"), ("Set-Cookie", "b=2")])
    assert r.get("SET-COOKIE") == "a=1" and r.get_all("set-cookie") == ["a=1", "b=2"]
    assert r.get("Missing") is None


# ---------- cookies ----------
def test_cookie_value_is_never_kept():
    c = parse_set_cookie("PHPSESSID=SUPERSECRETVALUE; Path=/; Secure")
    assert c.name == "PHPSESSID" and "SUPERSECRETVALUE" not in repr(c)
    findings = audit_cookies(resp([("Set-Cookie", "PHPSESSID=SUPERSECRETVALUE; Path=/")]))
    assert all("SUPERSECRETVALUE" not in str(f.to_dict()) for f in findings)


def test_sensitive_name_detection():
    assert all(is_sensitive(n) for n in ("PHPSESSID", "JSESSIONID", "auth_token", "sid", "remember_me"))
    assert not any(is_sensitive(n) for n in ("theme", "inside_flag", "csrf_token", "lang"))


def test_good_cookie_has_no_findings():
    good = "__Host-session=x; Path=/; Secure; HttpOnly; SameSite=Strict"
    assert audit_cookies(resp([("Set-Cookie", good)])) == []


def test_session_cookie_over_https_flags_severity_high_and_medium():
    findings = audit_cookies(resp([("Set-Cookie", "sessionid=x; Path=/")]))
    sev = {f.check_id: f.severity for f in findings}
    assert sev["COOKIE:no-secure"] == "HIGH" and sev["COOKIE:no-httponly"] == "MEDIUM"


def test_plain_cookie_is_less_severe_than_session_cookie():
    findings = audit_cookies(resp([("Set-Cookie", "theme=dark; Path=/")]))
    assert {f.severity for f in findings} == {"MEDIUM", "LOW"} and "COOKIE:no-secure" in ids(findings)


def test_csrf_cookie_may_be_readable_by_js():
    assert "COOKIE:no-httponly" not in ids(audit_cookies(resp([("Set-Cookie", "csrftoken=x; Secure; SameSite=Lax")])))


def test_samesite_none_requires_secure_and_prefix_rules():
    assert "COOKIE:samesite-none-insecure" in ids(audit_cookies(resp([("Set-Cookie", "a=1; SameSite=None; HttpOnly")])))
    assert "COOKIE:host-prefix" in ids(audit_cookies(resp([("Set-Cookie", "__Host-a=1; Secure; Path=/app; HttpOnly; SameSite=Lax")])))
    assert "COOKIE:secure-prefix" in ids(audit_cookies(resp([("Set-Cookie", "__Secure-a=1; HttpOnly; SameSite=Lax")])))


def test_broad_domain_and_long_lived_session_cookie():
    c = "session=x; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Max-Age=99999999"
    assert {"COOKIE:broad-domain", "COOKIE:long-lived"} <= ids(audit_cookies(resp([("Set-Cookie", c)])))


def test_secure_flag_over_http_is_only_a_low_note_for_session_cookies():
    f = audit_cookies(resp([("Set-Cookie", "sessionid=x; HttpOnly; SameSite=Lax")], url="http://127.0.0.1/"))
    assert [x.check_id for x in f] == ["COOKIE:no-secure-http"] and f[0].severity == "LOW"


# ---------- CSP ----------
def test_parse_csp_first_directive_wins():
    assert parse_csp("script-src a; script-src b; img-src 'self'") == {"script-src": ["a"], "img-src": ["'self'"]}


def test_effective_falls_back_to_default_src():
    pol = parse_csp("default-src 'self'")
    assert effective(pol, "script-src") == ["'self'"] and effective(parse_csp("img-src *"), "script-src") is None


def test_missing_and_report_only_csp():
    assert ids(audit_csp(resp())) == {"CSP:missing"}
    assert ids(audit_csp(resp([("Content-Security-Policy-Report-Only", "default-src 'self'")]))) == {"CSP:report-only"}


def test_unsafe_inline_flagged_but_neutralised_by_nonce():
    weak = audit_csp(resp([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")]))
    assert "CSP:unsafe-inline" in ids(weak)
    strong = audit_csp(resp([("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'")]))
    assert "CSP:unsafe-inline" not in ids(strong)  # browsers ignore unsafe-inline when a nonce is present


def test_unsafe_inline_inherited_from_default_src():
    f = audit_csp(resp([("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")]))
    assert any(x.check_id == "CSP:unsafe-inline" and x.evidence == "default-src" for x in f)


def test_wildcards_schemes_and_http_sources():
    pol = "script-src * data: http://cdn.example.com https:; object-src 'none'; base-uri 'none'"
    got = ids(audit_csp(resp([("Content-Security-Policy", pol)])))
    assert {"CSP:wildcard-source", "CSP:scheme-source", "CSP:http-source"} <= got


def test_policy_without_script_restriction_and_object_src():
    got = ids(audit_csp(resp([("Content-Security-Policy", "img-src 'self'")])))
    assert {"CSP:no-script-restriction", "CSP:object-src"} <= got


def test_each_of_several_policies_is_checked():
    r = resp([("Content-Security-Policy", "default-src 'none'"), ("Content-Security-Policy", "script-src 'unsafe-inline'")])
    assert "CSP:unsafe-inline" in ids(audit_csp(r))


def test_strict_policy_is_clean():
    pol = "default-src 'none'; script-src 'self' 'nonce-x'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    assert audit_csp(resp([("Content-Security-Policy", pol)])) == []


# ---------- headers ----------
def test_hsts_rules():
    assert "HEADER:hsts-missing" in ids(audit_headers(resp()))
    assert "HEADER:hsts-short" in ids(audit_headers(resp([("Strict-Transport-Security", "max-age=3600")])))
    assert "HEADER:hsts-disabled" in ids(audit_headers(resp([("Strict-Transport-Security", "max-age=0")])))
    assert "HEADER:hsts-invalid" in ids(audit_headers(resp([("Strict-Transport-Security", "includeSubDomains")])))
    good = ids(audit_headers(resp([("Strict-Transport-Security", "max-age=31536000; includeSubDomains")])))
    assert not {i for i in good if i.startswith("HEADER:hsts")}


def test_hsts_not_demanded_over_http():
    got = ids(audit_headers(resp(url="http://127.0.0.1/")))
    assert "HEADER:hsts-missing" not in got
    assert "HEADER:hsts-over-http" in ids(audit_headers(resp([("Strict-Transport-Security", "max-age=1")], url="http://x/")))


def test_frame_ancestors_supersedes_x_frame_options():
    assert "HEADER:clickjacking" in ids(audit_headers(resp()))
    assert "HEADER:clickjacking" not in ids(audit_headers(resp([("Content-Security-Policy", "frame-ancestors 'none'")])))
    assert "HEADER:clickjacking" not in ids(audit_headers(resp([("X-Frame-Options", "DENY")])))
    assert "HEADER:xfo-invalid" in ids(audit_headers(resp([("X-Frame-Options", "ALLOW-FROM https://a.com")])))


def test_report_only_csp_does_not_count_as_frame_protection():
    r = resp([("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")])
    assert "HEADER:clickjacking" in ids(audit_headers(r))


def test_referrer_nosniff_xss_and_permissions():
    got = ids(audit_headers(resp([("Referrer-Policy", "unsafe-url"), ("X-XSS-Protection", "1; mode=block")])))
    assert {"HEADER:referrer-unsafe", "HEADER:xss-filter", "HEADER:nosniff", "HEADER:permissions-policy"} <= got
    ok = ids(audit_headers(resp([("X-Content-Type-Options", "NoSniff"), ("Referrer-Policy", "no-referrer")])))
    assert "HEADER:nosniff" not in ok and "HEADER:referrer-missing" not in ok


def test_cors_checks():
    assert "HEADER:cors-wildcard-creds" in ids(audit_headers(resp([("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")])))
    assert "HEADER:cors-null" in ids(audit_headers(resp([("Access-Control-Allow-Origin", "null")])))
    assert "HEADER:cors-wildcard" in ids(audit_headers(resp([("Access-Control-Allow-Origin", "*")])))


def test_cache_check_only_for_session_responses():
    assert "HEADER:cache-sensitive" in ids(audit_headers(resp([("Set-Cookie", "sessionid=x")])))
    assert "HEADER:cache-sensitive" not in ids(audit_headers(resp([("Set-Cookie", "sessionid=x"), ("Cache-Control", "no-store")])))
    assert "HEADER:cache-sensitive" not in ids(audit_headers(resp([("Set-Cookie", "theme=dark")])))


# ---------- disclosure ----------
def test_version_banners_and_tech_headers():
    got = audit_disclosure(resp([("Server", "Apache/2.4.49 (Unix)"), ("X-Powered-By", "PHP/7.2.1"), ("X-Generator", "Drupal")]))
    sev = {f.evidence: f.severity for f in got}
    assert sev["Server: Apache/2.4.49 (Unix)"] == "LOW" and sev["X-Powered-By: PHP/7.2.1"] == "LOW" and sev["X-Generator: Drupal"] == "INFO"
    assert audit_disclosure(resp([("Server", "nginx")]))[0].severity == "INFO"


def test_private_ip_in_headers_but_not_public_ip():
    assert "DISCLOSURE:internal-ip" in ids(audit_disclosure(resp([("X-Backend-Server", "10.0.3.17")])))
    assert "DISCLOSURE:internal-ip" in ids(audit_disclosure(resp([("Via", "1.1 172.20.1.5")])))
    assert "DISCLOSURE:internal-ip" not in ids(audit_disclosure(resp([("Via", "1.1 8.8.8.8"), ("X-Note", "172.40.1.1")])))


def test_body_error_leaks():
    assert "DISCLOSURE:stack-trace" in ids(audit_disclosure(resp(body="Traceback (most recent call last):\n  File")))
    assert "DISCLOSURE:sql-error" in ids(audit_disclosure(resp(body="You have an error in your SQL syntax near")))
    assert "DISCLOSURE:directory-listing" in ids(audit_disclosure(resp(body="<title>Index of /backup</title>")))
    assert "DISCLOSURE:html-comment" in ids(audit_disclosure(resp(body="<!-- TODO remove admin password -->")))
    assert audit_disclosure(resp(body="<!-- navigation -->")) == []


def test_evidence_is_truncated():
    big = "Traceback (most recent call last)" + "x" * 500
    assert all(len(f.evidence) <= 80 for f in audit_disclosure(resp(body=big)))


# ---------- integration on real loopback servers ----------
def test_weak_vs_hardened_server_end_to_end():
    results = {}
    for name, handler in (("weak", WeakHandler), ("hard", HardenedHandler)):
        server, url = start(handler)
        try:
            results[name] = audit(fetch(url))
        finally:
            server.shutdown()
    weak, hard = summarize(results["weak"]), summarize(results["hard"])
    assert weak["HIGH"] >= 1 and weak["MEDIUM"] >= 4
    assert hard["CRITICAL"] == hard["HIGH"] == hard["MEDIUM"] == hard["LOW"] == 0
    assert sum(weak.values()) > sum(hard.values()) + 10


def test_demo_fetcher_refuses_non_loopback_hosts():
    with pytest.raises(PermissionError):
        fetch("http://example.com/")


def test_audit_is_sorted_and_deduplicated():
    r = resp([("Set-Cookie", "sessionid=x"), ("Set-Cookie", "sessionid=x")])
    findings = audit(r)
    keys = [f.key() for f in findings]
    assert len(keys) == len(set(keys))
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert [order.index(f.severity) for f in findings] == sorted((order.index(f.severity) for f in findings), reverse=True)
