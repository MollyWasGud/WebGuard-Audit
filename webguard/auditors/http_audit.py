"""HTTP Security Auditor (Module 1).

Reads a ResponseData (headers + cookies) and returns a list of Finding objects.
It never makes network requests: the CLI fetches the page after scope checks.
"""

from __future__ import annotations

from ..core.models import SEVERITIES, Finding, ResponseData


def _f(check_id, category, severity, title, detail, fix, evidence=""):
    return Finding(check_id, category, severity, title, detail, fix, evidence)


def check_headers(resp: ResponseData) -> list[Finding]:
    out = []
    csp = resp.get("Content-Security-Policy") or ""

    if resp.is_https and not resp.get("Strict-Transport-Security"):
        out.append(_f("HDR:hsts", "headers", "MEDIUM", "HSTS missing",
                      "Browsers may still use plain HTTP.",
                      "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    if (resp.get("X-Content-Type-Options") or "").lower() != "nosniff":
        out.append(_f("HDR:nosniff", "headers", "LOW", "X-Content-Type-Options missing",
                      "Browser may guess file types (MIME sniffing).",
                      "Add X-Content-Type-Options: nosniff"))
    if not resp.get("X-Frame-Options") and "frame-ancestors" not in csp.lower():
        out.append(_f("HDR:clickjacking", "headers", "MEDIUM", "Clickjacking protection missing",
                      "The page can be embedded in a hostile frame.",
                      "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"))
    if not resp.get("Referrer-Policy"):
        out.append(_f("HDR:referrer", "headers", "LOW", "Referrer-Policy missing",
                      "Full URLs may leak to other sites.",
                      "Add Referrer-Policy: strict-origin-when-cross-origin"))
    if resp.get("Access-Control-Allow-Origin") == "*":
        out.append(_f("HDR:cors", "headers", "MEDIUM", "CORS allows any origin",
                      "Any website can read responses.", "Allow only trusted origins",
                      "Access-Control-Allow-Origin: *"))
    return out


def check_csp(resp: ResponseData) -> list[Finding]:
    csp = resp.get("Content-Security-Policy")
    if not csp:
        return [_f("CSP:missing", "csp", "MEDIUM", "Content-Security-Policy missing",
                   "No browser-side defence against XSS.",
                   "Add a CSP such as default-src 'self'")]
    out = []
    for token, sev in (("'unsafe-inline'", "MEDIUM"), ("'unsafe-eval'", "MEDIUM")):
        if token in csp:
            out.append(_f(f"CSP:{token.strip(chr(39))}", "csp", sev, f"CSP allows {token}",
                          "Weakens protection against XSS.", f"Remove {token} from the policy",
                          token))
    if " * " in f" {csp} " or "default-src *" in csp:
        out.append(_f("CSP:wildcard", "csp", "MEDIUM", "CSP uses a wildcard source",
                      "Scripts or content can load from anywhere.", "List trusted sources only"))
    return out


def check_disclosure(resp: ResponseData) -> list[Finding]:
    out = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        value = resp.get(name)
        if value and any(ch.isdigit() for ch in value):
            out.append(_f(f"DISC:{name.lower()}", "disclosure", "LOW",
                          f"{name} header reveals version",
                          "Attackers can look up known bugs for that version.",
                          f"Remove or hide the {name} header", f"{name}: {value}"[:80]))
    return out


def check_cookies(resp: ResponseData) -> list[Finding]:
    out = []
    for raw in resp.get_all("Set-Cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]          # the cookie VALUE is never kept
        flags = [p.lower() for p in parts[1:]]
        if resp.is_https and "secure" not in flags:
            out.append(_f("COOKIE:secure", "cookies", "MEDIUM", f"Cookie '{name}' missing Secure",
                          "Cookie can be sent over plain HTTP.", "Add the Secure flag", name))
        if "httponly" not in flags:
            out.append(_f("COOKIE:httponly", "cookies", "MEDIUM", f"Cookie '{name}' missing HttpOnly",
                          "JavaScript (XSS) can read the cookie.", "Add the HttpOnly flag", name))
        if not any(p.startswith("samesite") for p in flags):
            out.append(_f("COOKIE:samesite", "cookies", "LOW", f"Cookie '{name}' missing SameSite",
                          "Cookie is sent on cross-site requests (CSRF risk).",
                          "Add SameSite=Lax or Strict", name))
    return out


def audit(resp: ResponseData) -> list[Finding]:
    """Run all checks. Most severe first."""
    findings = check_headers(resp) + check_csp(resp) + check_disclosure(resp) + check_cookies(resp)
    return sorted(findings, key=lambda f: -SEVERITIES.index(f.severity))


def summarize(findings: list[Finding]) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
