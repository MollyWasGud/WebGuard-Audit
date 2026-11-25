# Module 1 - HTTP Security Auditor

**What it does:** reads an HTTP response (headers and cookies) and reports weak or missing
security settings, with a severity and a fix for each one.

**File:** `webguard/auditors/http_audit.py` (about 100 lines, standard library only).

## Checks
- **Headers:** HSTS (HTTPS only), X-Content-Type-Options, clickjacking protection
  (X-Frame-Options or CSP frame-ancestors), Referrer-Policy, CORS `*`.
- **CSP:** missing policy, `'unsafe-inline'`, `'unsafe-eval'`, wildcard source.
- **Information disclosure:** version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version`.
- **Cookies:** Secure, HttpOnly and SameSite flags.

## How it fits the team tool
- Input: `ResponseData` and output: list of `Finding` (both in `webguard/core/models.py`).
- `audit(resp)` makes **no network request**. The CLI fetches the page after scope checks.
- Reports and scoring read the same `Finding` list as the TLS module.

## Ethical design
- Passive checks only: it reads one response and sends no attack traffic.
- Cookie values are never stored. Only the cookie name is kept as evidence.
- The demo servers and fetcher work on `127.0.0.1` only.

## Attack lifecycle mapping
Reconnaissance and vulnerability analysis: finds weaknesses an attacker would use
(XSS, clickjacking, session theft, version-based exploits).

## Demo
`python demo/run_demo.py` audits a weak local server (13 findings) and a hardened one (0).

## Limitations / future work
Looks at one response only; does not crawl pages; CSP check is basic (no nonce or hash logic).
