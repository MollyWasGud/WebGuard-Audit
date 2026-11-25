"""Content-Security-Policy parser and context-aware analyser.

Context-aware means we follow the CSP specification instead of just checking presence:
  * script-src falls back to default-src;
  * 'unsafe-inline' is IGNORED by browsers when a nonce or hash is present (so it is not a weakness then);
  * a report-only policy does not protect anyone;
  * several policies must ALL pass, so each enforced policy is analysed separately.
"""

from __future__ import annotations

from ...core.models import Finding, ResponseData

REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def parse_csp(value: str) -> dict[str, list[str]]:
    """'a b; c d' -> {'a': ['b'], 'c': ['d']}. The first occurrence of a directive wins (per spec)."""
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            policy.setdefault(tokens[0].lower(), tokens[1:])
    return policy


def policies(resp: ResponseData, header: str = "Content-Security-Policy") -> list[dict[str, list[str]]]:
    """Every policy in the header (multiple headers and comma-joined policies are both allowed)."""
    return [parse_csp(p) for value in resp.get_all(header) for p in value.split(",") if p.strip()]


def effective(policy: dict[str, list[str]], directive: str) -> list[str] | None:
    """Sources that actually govern a directive (falls back to default-src)."""
    return policy.get(directive, policy.get("default-src"))


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.lower().startswith(NONCE_OR_HASH) for s in sources)


def _add(out, check, severity, title, detail, fix, evidence=""):
    out.append(Finding(f"CSP:{check}", "csp", severity, title, detail, fix, evidence, REF))


def _check_sources(out, directive: str, sources: list[str], strict: bool) -> None:
    """strict=True for scripts (XSS impact), False for styles (limited impact)."""
    lowered = [s.lower() for s in sources]
    protected = _has_nonce_or_hash(sources) or "'strict-dynamic'" in lowered
    if "'unsafe-inline'" in lowered and not protected:
        _add(out, "unsafe-inline", "HIGH" if strict else "LOW", f"'unsafe-inline' allowed in {directive}",
             "Inline scripts run, so an injected <script> defeats the policy." if strict else "Inline styles allowed.",
             "Remove 'unsafe-inline'; use nonces or hashes.", directive)
    if "'unsafe-eval'" in lowered and strict:
        _add(out, "unsafe-eval", "MEDIUM", f"'unsafe-eval' allowed in {directive}",
             "eval()-style execution lets injected strings become code.", "Remove 'unsafe-eval'.", directive)
    if "*" in lowered:
        _add(out, "wildcard-source", "HIGH" if strict else "LOW", f"Wildcard (*) source in {directive}",
             "Content can be loaded from any host.", "List only the hosts you need.", directive)
    for scheme in ("data:", "http:", "https:"):
        if scheme in lowered and strict:
            severity = "HIGH" if scheme == "data:" else "MEDIUM"
            _add(out, "scheme-source", severity, f"Scheme-wide source '{scheme}' in {directive}",
                 "Any content of that scheme is trusted, including attacker-hosted files.", "Use explicit hosts instead.",
                 f"{directive} {scheme}")
    for source in lowered:
        if source.startswith("http://"):
            _add(out, "http-source", "MEDIUM", f"Insecure http:// source in {directive}",
                 "Plain HTTP content can be tampered with in transit.", "Use https:// sources.", f"{directive} {source}")


def audit_csp(resp: ResponseData) -> list[Finding]:
    out: list[Finding] = []
    enforced = policies(resp)
    if not enforced:
        if resp.get_all("Content-Security-Policy-Report-Only"):
            _add(out, "report-only", "LOW", "CSP is report-only (not enforced)",
                 "Violations are reported but nothing is blocked.", "Move to Content-Security-Policy once tuned.")
        else:
            _add(out, "missing", "MEDIUM", "No Content-Security-Policy header",
                 "No browser-side defence against XSS and content injection.", "Add a restrictive CSP.")
        return out
    for policy in enforced:
        script = effective(policy, "script-src")
        if script is None:
            _add(out, "no-script-restriction", "MEDIUM", "CSP does not restrict scripts",
                 "Neither script-src nor default-src is set.", "Add script-src 'self' (plus nonces).")
        else:
            _check_sources(out, "script-src" if "script-src" in policy else "default-src", script, strict=True)
        style = effective(policy, "style-src")
        if style is not None:
            _check_sources(out, "style-src" if "style-src" in policy else "default-src", style, strict=False)
        objects = effective(policy, "object-src")
        if objects is None or [s.lower() for s in objects] != ["'none'"]:
            _add(out, "object-src", "LOW", "object-src is not 'none'",
                 "Legacy plugins (Flash/Java) can still be embedded.", "Add object-src 'none'.")
        if "base-uri" not in policy:
            nonce_based = script is not None and _has_nonce_or_hash(script)
            _add(out, "base-uri", "LOW" if nonce_based else "INFO", "base-uri not restricted",
                 "An injected <base> tag can redirect relative script URLs"
                 + (" and hijack nonce-based scripts." if nonce_based else "."), "Add base-uri 'none' or 'self'.")
    return out
