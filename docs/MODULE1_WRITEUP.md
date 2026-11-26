# Module 1 - HTTP Security Auditor

**What it does:** reads an HTTP response (headers and cookies) and reports weak or missing
security settings, with a severity and a fix for each one.

**File:** `webguard/auditors/http_audit.py` (standard library only).

## Checks
- **Headers:** HSTS (HTTPS only, with malformed, missing, zero, and short max-age checks), X-Content-Type-Options, clickjacking protection
  (valid X-Frame-Options or a real CSP frame-ancestors directive), Referrer-Policy (valid values), CORS.
- **CSP:** real directive parsing (first duplicate wins), several policies, report-only not counted, `default-src` fallback,
  nonce/hash/strict-dynamic cancel `'unsafe-inline'`, wildcard sources, scripts and styles judged separately.
- **Information disclosure:** version-shaped technology headers and RFC 1918 addresses. Evidence uses
  allowlisted product identifiers without versions, and fixed labels for private addresses.
- **Cookies:** Secure, HttpOnly and SameSite flags.

## How it fits the team tool
- Input: `ResponseData` and output: list of `Finding` (both in `webguard/core/models.py`).
- `audit(resp)` makes **no network request**. The CLI fetches a bounded response from the approved HTTP origin after scope and authorisation checks. The current HTTPS plan omits content-header analysis.
- Member 3 combines the HTTP findings with findings mapped from validated Member 2 results.

## Ethical design
- Passive checks only: it reads one response and sends no attack traffic.
- Cookie values are never stored. Only a valid cookie name is kept as evidence; malformed names are never echoed.
- All evidence is printable ASCII and length-bounded. Raw headers and bodies are hidden from `repr()`/logs.
- The demo fetcher is direct (no proxy), refuses redirects and hostnames, and only talks to loopback IP addresses.

## Attack lifecycle mapping
Reconnaissance and vulnerability analysis: finds weaknesses an attacker would use
(XSS, clickjacking, session theft, version-based exploits).

## Demo
`python -B demo/run_demo.py` compares weak and hardened loopback fixtures.
The follow-up review recorded 14 findings for the weak fixture and zero for
the hardened fixture. Step 44 covers the integrated CLI demonstration.

## Limitations / future work
The auditor inspects one response without crawling pages or emulating a browser.
JavaScript string evaluation uses script-src with default-src fallback.
Inline checks distinguish script elements and event-handler attributes, and script
network-source checks apply to elements. Other browser CSP semantics are outside this check.

HSTS accepts ASCII digits with either no quotes or one balanced pair. The auditor
flags duplicate directives and applies a local 12-digit limit.
The no-referrer-when-downgrade warning distinguishes same-security-level requests
and upgrades from HTTPS-to-HTTP downgrades, which omit the referrer.

Evidence minimization protects the tested disclosure paths. Pattern matching
cannot identify every possible secret.
