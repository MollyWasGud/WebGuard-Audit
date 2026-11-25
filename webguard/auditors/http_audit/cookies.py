"""Cookie audit. Only cookie NAMES and ATTRIBUTES are read - values are never stored or reported."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...core.models import Finding, ResponseData

SENSITIVE = re.compile(r"(sess|jwt|auth|login|remember|token|(^|[_\-.])sid($|[_\-.\d]))", re.I)
CSRF = re.compile(r"(csrf|xsrf)", re.I)
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"
LONG_LIVED = 30 * 24 * 3600  # seconds


@dataclass
class Cookie:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)  # lower-case attribute name -> value


def parse_set_cookie(raw: str) -> Cookie | None:
    parts = [p.strip() for p in raw.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return Cookie(parts[0].split("=", 1)[0].strip(), attrs)  # value deliberately discarded


def is_sensitive(name: str) -> bool:
    return bool(SENSITIVE.search(name)) and not CSRF.search(name)


def describe(cookie: Cookie) -> str:
    flags = [k if k not in ("samesite", "path") else f"{k}={cookie.attrs[k]}" for k in sorted(cookie.attrs)
             if k in ("secure", "httponly", "samesite", "path", "domain", "max-age", "expires")]
    return f"{cookie.name} [{', '.join(flags) or 'no attributes'}]"


def audit_cookies(resp: ResponseData) -> list[Finding]:
    out: list[Finding] = []
    for raw in resp.get_all("Set-Cookie"):
        cookie = parse_set_cookie(raw)
        if cookie is None:
            continue
        a, name, evidence = cookie.attrs, cookie.name, describe(cookie)
        sensitive = is_sensitive(name)
        kind = "session/auth cookie" if sensitive else "cookie"

        def add(check, severity, title, detail, fix):
            out.append(Finding(f"COOKIE:{check}", "cookies", severity, title, detail, fix, evidence, MDN))

        if "secure" not in a:
            if resp.is_https:
                add("no-secure", "HIGH" if sensitive else "MEDIUM", f"{kind.capitalize()} missing Secure flag",
                    "The cookie can be sent over plain HTTP and intercepted.", "Add the Secure attribute.")
            elif sensitive:
                add("no-secure-http", "LOW", "Session cookie set over plain HTTP without Secure",
                    "Site is not using HTTPS, so the cookie travels in clear text.", "Serve over HTTPS and add Secure.")
        if "httponly" not in a and not CSRF.search(name):
            add("no-httponly", "MEDIUM" if sensitive else "LOW", f"{kind.capitalize()} missing HttpOnly flag",
                "JavaScript (and therefore XSS) can read the cookie.", "Add the HttpOnly attribute.")
        samesite = a.get("samesite", "").lower()
        if not samesite:
            add("no-samesite", "MEDIUM" if sensitive else "LOW", f"{kind.capitalize()} missing SameSite",
                "Older browsers send it on cross-site requests, enabling CSRF.", "Add SameSite=Lax or Strict.")
        elif samesite == "none" and "secure" not in a:
            add("samesite-none-insecure", "HIGH", "SameSite=None without Secure",
                "Browsers reject this cookie; it indicates a misconfiguration.", "Add Secure or use Lax/Strict.")
        elif samesite not in ("lax", "strict", "none"):
            add("samesite-invalid", "LOW", "Invalid SameSite value", "Browsers ignore unknown values.", "Use Lax, Strict or None.")
        if name.startswith("__Host-") and not ("secure" in a and a.get("path") == "/" and "domain" not in a):
            add("host-prefix", "MEDIUM", "__Host- prefix rules violated",
                "Requires Secure, Path=/ and no Domain; browsers will reject it.", "Fix the attributes or drop the prefix.")
        if name.startswith("__Secure-") and "secure" not in a:
            add("secure-prefix", "MEDIUM", "__Secure- prefix without Secure", "Browsers will reject the cookie.", "Add Secure.")
        if sensitive and a.get("domain"):
            add("broad-domain", "LOW", "Session cookie shared with subdomains",
                "Any subdomain (even a vulnerable one) can read or overwrite it.", "Omit Domain, or use the __Host- prefix.")
        max_age = a.get("max-age", "")
        if sensitive and max_age.lstrip("-").isdigit() and int(max_age) > LONG_LIVED:
            add("long-lived", "LOW", "Long-lived session cookie", "A stolen cookie stays valid for a long time.",
                "Use a session cookie or a short Max-Age.")
    return out
