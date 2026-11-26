"""HTTP Security Auditor (Module 1).

Reads a ResponseData (headers + cookies) and returns a list of Finding objects.
It never makes network requests: the CLI fetches the page after scope checks.

Safety rules (security review M1-02):
- cookie VALUES are never read into a finding; malformed cookie names are never echoed
- all evidence goes through clean(): printable ASCII only and length-bounded
- raw headers and bodies are never logged or put in a finding
"""

from __future__ import annotations

import ipaddress
import re

from ..core.models import SEVERITIES, Finding, ResponseData

MAX_EVIDENCE = 60
TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")            # RFC 6265 cookie-name token
SESSIONISH = re.compile(r"sess|sid|auth|token|jwt|login", re.I)    # cookies that hold a login
IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
PRODUCT_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]*/[0-9][A-Za-z0-9_.\-]*")   # only used to DETECT the shape
VERSION_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}")
# Disclosure evidence is built ONLY from this allowlist; any other value is never shown (it could be a secret).
KNOWN_PRODUCTS = {"apache", "nginx", "php", "express", "microsoft-iis", "iis", "tomcat", "jetty", "openssl", "python",
                  "basehttp", "werkzeug", "gunicorn", "lighttpd", "caddy", "litespeed", "asp.net", "node.js"}
HSTS_MAX_DIGITS = 12   # longer numbers are treated as malformed (browsers cap the value anyway)
HSTS_DIRECTIVE = re.compile(r"[A-Za-z0-9_\-]+(?:=[^;\s]*)?")
REFERRER_VALID = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                  "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
HSTS_MIN_SECONDS = 15_552_000  # 180 days


def clean(text: object, limit: int = MAX_EVIDENCE) -> str:
    """Printable ASCII only, length-bounded: safe to show in a report."""
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(text))
    return text[:limit] + ("..." if len(text) > limit else "")


def _f(check_id, category, severity, title, detail, fix, evidence=""):
    return Finding(check_id, category, severity, clean(title, 80), detail, fix, clean(evidence))


# ---------------------------------------------------------------- CSP helpers
def parse_csp(policy_text: str) -> dict[str, list[str]]:
    """'a x; b y' -> {'a': ['x'], 'b': ['y']}. Directive names are case-insensitive; the first duplicate wins."""
    policy: dict[str, list[str]] = {}
    for part in policy_text.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in policy:
            policy[tokens[0].lower()] = tokens[1:]
    return policy


def enforced_policies(resp: ResponseData) -> list[dict[str, list[str]]]:
    """Every enforced policy (one header may hold several, comma-separated). Report-Only is not enforced."""
    found = []
    for value in resp.get_all("Content-Security-Policy"):
        for chunk in value.split(","):
            policy = parse_csp(chunk)
            if policy:
                found.append(policy)
    return found


# CSP3 fallback chains: the specific directive, then script-src / style-src, then default-src.
SCRIPT_CHAINS = (("script-src-elem", "script-src", "default-src"),    # <script> elements
                 ("script-src-attr", "script-src", "default-src"))    # inline event handlers (onclick=...)
STYLE_CHAINS = (("style-src-elem", "style-src", "default-src"),
                ("style-src-attr", "style-src", "default-src"))


def _effective(policy: dict, chain: tuple) -> list[str] | None:
    """First directive of the chain that the policy sets. None = this policy does not restrict it."""
    for directive in chain:
        if directive in policy:
            return policy[directive]
    return None


def _weak_in_all(policies: list[dict], chain: tuple, test) -> bool:
    """A weakness counts only if EVERY policy that restricts this chain has it (another policy would block it)."""
    restricting = [s for s in (_effective(p, chain) for p in policies) if s is not None]
    return bool(restricting) and all(test([t.lower() for t in s]) for s in restricting)


def _weak_any_chain(policies: list[dict], chains: tuple, test) -> bool:
    return any(_weak_in_all(policies, chain, test) for chain in chains)


def _script_inline_allowed(tokens: list[str]) -> bool:
    """nonce, hash and 'strict-dynamic' all switch 'unsafe-inline' off for SCRIPTS."""
    neutralised = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                      for t in tokens)
    return "'unsafe-inline'" in tokens and not neutralised


def _style_inline_allowed(tokens: list[str]) -> bool:
    """For STYLES only nonce and hash neutralise 'unsafe-inline'. 'strict-dynamic' is a script-only keyword."""
    neutralised = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens)
    return "'unsafe-inline'" in tokens and not neutralised


def check_csp(resp: ResponseData) -> list[Finding]:
    policies = enforced_policies(resp)
    if not policies:
        if resp.get_all("Content-Security-Policy-Report-Only"):
            return [_f("CSP:report-only", "csp", "LOW", "CSP is report-only (not enforced)",
                       "A Report-Only policy only reports violations, it blocks nothing.",
                       "Switch to the enforcing Content-Security-Policy header once the policy is tested")]
        return [_f("CSP:missing", "csp", "MEDIUM", "Content-Security-Policy missing",
                   "No browser-side defence against XSS.", "Add a CSP such as default-src 'self'")]
    out = []
    if all(_effective(p, SCRIPT_CHAINS[0]) is None for p in policies):   # no script-src-elem, script-src or default-src
        out.append(_f("CSP:no-script-restriction", "csp", "MEDIUM", "CSP does not restrict scripts",
                      "No script-src, script-src-elem or default-src, so any script may run.",
                      "Add script-src 'self' or default-src 'self'"))
    script_checks = (
        ("CSP:unsafe-inline", "MEDIUM", "CSP allows 'unsafe-inline' scripts", _script_inline_allowed, "'unsafe-inline'",
         "Use nonces or hashes instead of 'unsafe-inline'"),
        ("CSP:unsafe-eval", "MEDIUM", "CSP allows 'unsafe-eval' scripts", lambda t: "'unsafe-eval'" in t, "'unsafe-eval'",
         "Remove 'unsafe-eval' and avoid eval()"),
        ("CSP:wildcard", "MEDIUM", "CSP script sources are too broad",
         lambda t: any(x in ("*", "http:", "https:", "data:") for x in t), "wildcard or scheme-only source",
         "List the exact trusted script origins"),
    )
    for check_id, sev, title, test, evidence, fix in script_checks:
        if _weak_any_chain(policies, SCRIPT_CHAINS, test):
            out.append(_f(check_id, "csp", sev, title, "Weakens protection against XSS.", fix, evidence))
    if _weak_any_chain(policies, STYLE_CHAINS, _style_inline_allowed):
        out.append(_f("CSP:style-unsafe-inline", "csp", "LOW", "CSP allows 'unsafe-inline' styles",
                      "Inline styles can be abused for data leaks; lower risk than scripts.", "Use nonces or hashes for styles",
                      "'unsafe-inline'"))
    if _weak_any_chain(policies, STYLE_CHAINS, lambda t: "*" in t):
        out.append(_f("CSP:style-wildcard", "csp", "LOW", "CSP style sources allow any origin",
                      "Stylesheets can load from anywhere.", "List the exact trusted style origins", "*"))
    return out


# ---------------------------------------------------------------- headers
def _hsts_max_age(value: str) -> int | None:
    """Valid max-age in seconds, or None if the header is malformed. Never raises.

    Invalid: a directive with bad syntax, a repeated directive (RFC 6797: browsers ignore the header),
    a missing max-age, or a max-age that is not plain ASCII digits (or is absurdly long).
    """
    seen, max_age = set(), None
    for raw in value.split(";"):
        directive = raw.strip()
        if not directive:
            continue
        if not HSTS_DIRECTIVE.fullmatch(directive):
            return None
        name, _, val = directive.partition("=")
        name = name.lower()
        if name in seen:                       # duplicate directive (for example two max-age values)
            return None
        seen.add(name)
        if name == "max-age":
            val = val.strip('"')
            if not re.fullmatch(r"[0-9]{1,%d}" % HSTS_MAX_DIGITS, val):
                return None
            max_age = int(val)
    return max_age


def check_headers(resp: ResponseData) -> list[Finding]:
    out = []
    policies = enforced_policies(resp)

    if resp.is_https:  # browsers ignore HSTS sent over plain HTTP
        hsts = resp.get("Strict-Transport-Security")
        age = _hsts_max_age(hsts) if hsts else None
        if not hsts:
            out.append(_f("HDR:hsts", "headers", "MEDIUM", "HSTS missing", "Browsers may still use plain HTTP.",
                          "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        elif age is None:
            out.append(_f("HDR:hsts-invalid", "headers", "MEDIUM", "HSTS max-age missing or invalid",
                          "Browsers ignore an HSTS header without a valid max-age.", "Use max-age=31536000"))
        elif age == 0:
            out.append(_f("HDR:hsts-disabled", "headers", "MEDIUM", "HSTS is disabled (max-age=0)",
                          "max-age=0 tells browsers to forget HSTS.", "Use max-age=31536000", "max-age=0"))
        elif age < HSTS_MIN_SECONDS:
            out.append(_f("HDR:hsts-short", "headers", "LOW", "HSTS max-age is short",
                          "A short lifetime leaves users unprotected between visits.", "Use at least 15552000 (180 days)",
                          f"max-age={age}"))

    if (resp.get("X-Content-Type-Options") or "").strip().lower() != "nosniff":
        out.append(_f("HDR:nosniff", "headers", "LOW", "X-Content-Type-Options missing",
                      "Browser may guess file types (MIME sniffing).", "Add X-Content-Type-Options: nosniff"))

    xfo_values = resp.get_all("X-Frame-Options")
    xfo_ok = len(xfo_values) == 1 and xfo_values[0].strip().upper() in {"DENY", "SAMEORIGIN"}
    ancestors = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]  # real directive, not a substring
    if ancestors and all("*" in a for a in ancestors):
        out.append(_f("HDR:frame-ancestors-wildcard", "headers", "MEDIUM", "frame-ancestors allows any site",
                      "Any website can embed this page.", "Use frame-ancestors 'none' or 'self'", "*"))
    elif not ancestors and not xfo_ok:
        if xfo_values:
            out.append(_f("HDR:xfo-invalid", "headers", "MEDIUM", "X-Frame-Options value is invalid or obsolete",
                          "Only DENY and SAMEORIGIN are valid (ALLOW-FROM is ignored by browsers).",
                          "Use X-Frame-Options: DENY or CSP frame-ancestors 'none'"))
        else:
            out.append(_f("HDR:clickjacking", "headers", "MEDIUM", "Clickjacking protection missing",
                          "The page can be embedded in a hostile frame.",
                          "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"))

    referrer = ",".join(resp.get_all("Referrer-Policy"))   # several header fields are combined like one list
    if not referrer.strip(", "):
        out.append(_f("HDR:referrer", "headers", "LOW", "Referrer-Policy missing", "Full URLs may leak to other sites.",
                      "Add Referrer-Policy: strict-origin-when-cross-origin"))
    else:
        valid = [t.strip().lower() for t in referrer.split(",") if t.strip().lower() in REFERRER_VALID]
        if not valid:
            out.append(_f("HDR:referrer-invalid", "headers", "LOW", "Referrer-Policy value is invalid",
                          "Browsers ignore unknown values, so the default applies.",
                          "Use Referrer-Policy: strict-origin-when-cross-origin"))
        elif valid[-1] in ("unsafe-url", "no-referrer-when-downgrade"):  # the last valid value is the one browsers use
            out.append(_f("HDR:referrer-weak", "headers", "LOW", "Referrer-Policy leaks full URLs",
                          "Full URLs (with paths and queries) are sent to other sites.",
                          "Use strict-origin-when-cross-origin or no-referrer", valid[-1]))

    origin = (resp.get("Access-Control-Allow-Origin") or "").strip()
    credentials = (resp.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    if origin == "*" and credentials:
        out.append(_f("HDR:cors-credentials", "headers", "MEDIUM", "CORS wildcard combined with credentials",
                      "Invalid and dangerous combination; browsers reject it, but it shows a misconfigured policy.",
                      "Allow only specific trusted origins", "Access-Control-Allow-Origin: *"))
    elif origin == "*":
        out.append(_f("HDR:cors", "headers", "LOW", "CORS allows any origin",
                      "Any website can read this response. Fine for public data, risky for private data.",
                      "Allow only trusted origins if the response is not public", "Access-Control-Allow-Origin: *"))
    elif origin.lower() == "null":
        out.append(_f("HDR:cors-null", "headers", "MEDIUM", "CORS trusts the 'null' origin",
                      "Sandboxed pages and local files can send the 'null' origin.", "Do not allow 'null'",
                      "Access-Control-Allow-Origin: null"))
    return out


# ---------------------------------------------------------------- disclosure
def _is_private_ipv4(text: str) -> bool:
    """True only for a REAL private IPv4 address (999.1.1.1 and 010.1.1.1 are rejected by ipaddress)."""
    for candidate in IPV4_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if any(address in network for network in PRIVATE_NETWORKS):
            return True
    return False


def _safe_products(value: str) -> str:
    """'Apache/2.4.1 token=SECRET' -> 'Apache/2.4.1'. Only allowlisted products with a numeric version survive."""
    kept = []
    for match in PRODUCT_VERSION.findall(value):
        product, _, version = match.partition("/")
        if product.lower() in KNOWN_PRODUCTS and VERSION_RE.fullmatch(version):
            kept.append(f"{product}/{version}")
    return " ".join(kept[:3])


def check_disclosure(resp: ResponseData) -> list[Finding]:
    out = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = resp.get(name)
        if not value:
            continue
        has_version_shape = bool(PRODUCT_VERSION.search(value))
        if has_version_shape or name != "Server":  # a bare Server name is common; the others always reveal technology
            safe = _safe_products(value)           # allowlisted summary, or just the header NAME
            out.append(_f(f"DISC:{name.lower()}", "disclosure", "LOW", f"{name} header reveals technology",
                          "Attackers can look up known bugs for that product or version.",
                          f"Remove or hide the {name} header", f"{name}: {safe}" if safe else name))
    for key, value in resp.headers:
        if key.lower() != "set-cookie" and _is_private_ipv4(value):
            out.append(_f("DISC:internal-ip", "disclosure", "MEDIUM", "Internal IP address in a response header",
                          "Reveals the private network layout.", "Remove the internal address from the header", key))
    return out


# ---------------------------------------------------------------- cookies
def check_cookies(resp: ResponseData) -> list[Finding]:
    out = []
    for raw in resp.get_all("Set-Cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name, eq, _value = parts[0].partition("=")  # the cookie VALUE is dropped here and never used
        name = name.strip()
        if not eq or not TOKEN_RE.fullmatch(name):
            out.append(_f("COOKIE:malformed", "cookies", "LOW", "Malformed Set-Cookie header ignored",
                          "The cookie name is not valid, so browsers may reject it.", "Use a valid cookie name (RFC 6265 token)"))
            continue
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            key, _, val = part.partition("=")
            attrs.setdefault(key.strip().lower(), val.strip())
        sev = "MEDIUM" if SESSIONISH.search(name) else "LOW"
        label = clean(name, 40)
        if resp.is_https and "secure" not in attrs:
            out.append(_f("COOKIE:secure", "cookies", sev, f"Cookie '{label}' missing Secure",
                          "Cookie can be sent over plain HTTP.", "Add the Secure flag", name))
        if "httponly" not in attrs:
            out.append(_f("COOKIE:httponly", "cookies", sev, f"Cookie '{label}' missing HttpOnly",
                          "JavaScript (XSS) can read the cookie.", "Add the HttpOnly flag", name))
        samesite = attrs.get("samesite")  # exact attribute name only: "samesite-x" does not count
        if samesite is None:
            out.append(_f("COOKIE:samesite", "cookies", "LOW", f"Cookie '{label}' missing SameSite",
                          "Cookie is sent on cross-site requests (CSRF risk).", "Add SameSite=Lax or Strict", name))
        elif samesite.lower() not in {"strict", "lax", "none"}:
            out.append(_f("COOKIE:samesite-invalid", "cookies", "LOW", f"Cookie '{label}' has an invalid SameSite value",
                          "Browsers ignore unknown values, so the protection is not applied.",
                          "Use SameSite=Lax, Strict or None", name))
        elif samesite.lower() == "none" and "secure" not in attrs:
            out.append(_f("COOKIE:samesite-none-insecure", "cookies", "MEDIUM",
                          f"Cookie '{label}' uses SameSite=None without Secure",
                          "Browsers reject SameSite=None cookies that are not Secure.", "Add the Secure flag", name))
        if name.startswith("__Secure-") and "secure" not in attrs or (
                name.startswith("__Host-") and ("secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs)):
            out.append(_f("COOKIE:prefix", "cookies", "MEDIUM", f"Cookie '{label}' breaks its name prefix rules",
                          "__Secure- needs Secure; __Host- needs Secure, Path=/ and no Domain.",
                          "Follow the prefix rules or rename the cookie", name))
    return out


# ---------------------------------------------------------------- entry points
def audit(resp: ResponseData) -> list[Finding]:
    """Run all checks. Duplicates removed, most severe first."""
    seen, findings = set(), []
    for f in check_headers(resp) + check_csp(resp) + check_disclosure(resp) + check_cookies(resp):
        if f.key() not in seen:
            seen.add(f.key())
            findings.append(f)
    return sorted(findings, key=lambda f: -SEVERITIES.index(f.severity))


def summarize(findings: list[Finding]) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
