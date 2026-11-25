# Module 1 - HTTP Security Auditor

**What it does:** reads an HTTP response (headers and cookies) and reports weak or missing
security settings, with a severity and a fix for each one.

**File:** `webguard/auditors/http_audit.py` (about 250 lines, standard library only).

## Checks
- **Headers:** HSTS (HTTPS only; max-age missing, zero or short), X-Content-Type-Options, clickjacking protection
  (valid X-Frame-Options or a real CSP frame-ancestors directive), Referrer-Policy (valid values), CORS.
- **CSP:** real directive parsing (first duplicate wins), several policies, report-only not counted, `default-src` fallback,
  nonce/hash/strict-dynamic cancel `'unsafe-inline'`, wildcard sources, scripts and styles judged separately.
- **Information disclosure:** version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version`.
- **Cookies:** Secure, HttpOnly and SameSite flags.

## How it fits the team tool
- Input: `ResponseData` and output: list of `Finding` (both in `webguard/core/models.py`).
- `audit(resp)` makes **no network request**. The CLI fetches the page after scope checks.
- Reports and scoring read the same `Finding` list as the TLS module.

## Ethical design
- Passive checks only: it reads one response and sends no attack traffic.
- Cookie values are never stored. Only a valid cookie name is kept as evidence; malformed names are never echoed.
- All evidence is printable ASCII and length-bounded. Raw headers and bodies are hidden from `repr()`/logs.
- The demo fetcher is direct (no proxy), refuses redirects and hostnames, and only talks to loopback IP addresses.

## Attack lifecycle mapping
Reconnaissance and vulnerability analysis: finds weaknesses an attacker would use
(XSS, clickjacking, session theft, version-based exploits).

## Demo
`python demo/run_demo.py` audits a weak local server (14 findings) and a hardened one (0).

## Limitations / future work
Looks at one response only; does not crawl pages; no CSP source-list matching beyond wildcards and scheme-only sources.
