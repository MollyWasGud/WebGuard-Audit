"""Security-header checks. Context-aware: e.g. CSP frame-ancestors supersedes X-Frame-Options."""

from __future__ import annotations

import re

from ...core.models import Finding, ResponseData
from .cookies import is_sensitive, parse_set_cookie
from .csp import policies

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
SIX_MONTHS = 15_552_000  # seconds


def _f(check, severity, title, detail, fix, header, evidence=""):
    return Finding(f"HEADER:{check}", "headers", severity, title, detail, fix, evidence, MDN + header)


def audit_headers(resp: ResponseData) -> list[Finding]:
    out: list[Finding] = []

    # --- HSTS (only meaningful over HTTPS) ---
    hsts = resp.get("Strict-Transport-Security")
    if resp.is_https:
        if hsts is None:
            out.append(_f("hsts-missing", "MEDIUM", "Strict-Transport-Security missing",
                          "Browsers may connect over HTTP first, allowing SSL-stripping.",
                          "Send Strict-Transport-Security: max-age=31536000; includeSubDomains", "Strict-Transport-Security"))
        else:
            match = re.search(r'max-age\s*=\s*"?(\d+)', hsts, re.I)
            age = int(match.group(1)) if match else None
            if age is None:
                out.append(_f("hsts-invalid", "MEDIUM", "HSTS header has no valid max-age", "Browsers ignore it.",
                              "Add max-age=31536000", "Strict-Transport-Security", hsts))
            elif age == 0:
                out.append(_f("hsts-disabled", "MEDIUM", "HSTS disabled (max-age=0)", "Clears any stored HSTS policy.",
                              "Use a long max-age", "Strict-Transport-Security", hsts))
            elif age < SIX_MONTHS:
                out.append(_f("hsts-short", "LOW", "HSTS max-age is short (< 180 days)", "Protection lapses quickly.",
                              "Use at least 15552000, ideally 31536000", "Strict-Transport-Security", hsts))
            if "includesubdomains" not in hsts.lower():
                out.append(_f("hsts-subdomains", "INFO", "HSTS does not cover subdomains", "Subdomains stay downgradable.",
                              "Add includeSubDomains if all subdomains support HTTPS", "Strict-Transport-Security", hsts))
    elif hsts is not None:
        out.append(_f("hsts-over-http", "INFO", "HSTS sent over plain HTTP", "Browsers ignore HSTS on HTTP responses.",
                      "Send it only over HTTPS", "Strict-Transport-Security"))

    # --- MIME sniffing ---
    if (resp.get("X-Content-Type-Options") or "").strip().lower() != "nosniff":
        out.append(_f("nosniff", "LOW", "X-Content-Type-Options: nosniff missing", "Browsers may sniff files as scripts.",
                      "Send X-Content-Type-Options: nosniff", "X-Content-Type-Options"))

    # --- Clickjacking: CSP frame-ancestors (modern) supersedes X-Frame-Options ---
    frame_ancestors = any("frame-ancestors" in p for p in policies(resp))
    xfo = resp.get("X-Frame-Options")
    if not frame_ancestors:
        if xfo is None:
            out.append(_f("clickjacking", "MEDIUM", "No clickjacking protection",
                          "Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed.",
                          "Send CSP frame-ancestors 'none' (or X-Frame-Options: DENY)", "X-Frame-Options"))
        elif xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            out.append(_f("xfo-invalid", "LOW", "X-Frame-Options has an unsupported value",
                          "ALLOW-FROM is obsolete and ignored by modern browsers.", "Use DENY/SAMEORIGIN or frame-ancestors",
                          "X-Frame-Options", xfo))

    # --- Referrer / Permissions ---
    referrer = (resp.get("Referrer-Policy") or "").strip().lower()
    if not referrer:
        out.append(_f("referrer-missing", "LOW", "Referrer-Policy missing", "Full URLs may leak to other sites.",
                      "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)", "Referrer-Policy"))
    elif referrer == "unsafe-url":
        out.append(_f("referrer-unsafe", "MEDIUM", "Referrer-Policy is unsafe-url", "Full URLs leak even over HTTP.",
                      "Use strict-origin-when-cross-origin", "Referrer-Policy", referrer))
    elif referrer == "no-referrer-when-downgrade":
        out.append(_f("referrer-weak", "LOW", "Referrer-Policy is no-referrer-when-downgrade",
                      "Full URLs leak to other HTTPS sites.", "Use strict-origin-when-cross-origin", "Referrer-Policy", referrer))
    if resp.get("Permissions-Policy") is None:
        out.append(_f("permissions-policy", "INFO", "Permissions-Policy missing",
                      "Powerful browser features are not explicitly restricted.",
                      "Send e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()", "Permissions-Policy"))

    # --- Legacy XSS filter ---
    xss = (resp.get("X-XSS-Protection") or "").strip()
    if xss.startswith("1"):
        out.append(_f("xss-filter", "LOW", "Legacy X-XSS-Protection enabled",
                      "The old filter can itself create vulnerabilities; modern browsers removed it.",
                      "Send X-XSS-Protection: 0 (or remove) and rely on CSP", "X-XSS-Protection", xss))

    # --- CORS ---
    origin = (resp.get("Access-Control-Allow-Origin") or "").strip()
    creds = (resp.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    if origin == "*" and creds:
        out.append(_f("cors-wildcard-creds", "HIGH", "CORS wildcard with credentials",
                      "Dangerous misconfiguration; reflects trust to every origin.", "Allow specific origins only",
                      "Access-Control-Allow-Origin", origin))
    elif origin == "null":
        out.append(_f("cors-null", "MEDIUM", "CORS allows the 'null' origin", "Sandboxed pages can read responses.",
                      "Remove 'null'", "Access-Control-Allow-Origin", origin))
    elif origin == "*":
        out.append(_f("cors-wildcard", "LOW", "CORS allows any origin", "Fine for public data only.",
                      "Restrict origins if responses are not public", "Access-Control-Allow-Origin", origin))

    # --- Caching of authenticated responses ---
    cookies = [parse_set_cookie(c) for c in resp.get_all("Set-Cookie")]
    if any(c and is_sensitive(c.name) for c in cookies) and "no-store" not in (resp.get("Cache-Control") or "").lower():
        out.append(_f("cache-sensitive", "LOW", "Session-setting response may be cached",
                      "Shared caches could store a response that sets a session cookie.",
                      "Send Cache-Control: no-store", "Cache-Control", resp.get("Cache-Control") or "(missing)"))
    return out
