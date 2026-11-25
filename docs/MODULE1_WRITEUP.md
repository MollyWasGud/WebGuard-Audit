# Module 1 - HTTP Security Auditor (write-up for the team README / report)

**Author:** Muhammad Harith Syamel bin Mohd Noor Azam (Member 1)
**Scope:** security headers, Content-Security-Policy, information disclosure, cookies.

## What it does
Takes one HTTP response (URL, status, headers, body) and returns a prioritised list of findings, each with severity,
explanation, remediation, safe evidence and a reference link. It is non-invasive: it only analyses a response the
scope-validated fetcher already obtained.

| Area | Checks |
|---|---|
| Headers | HSTS (presence, max-age, subdomains; only on HTTPS), X-Content-Type-Options, clickjacking (X-Frame-Options **or** CSP frame-ancestors), Referrer-Policy, Permissions-Policy, legacy X-XSS-Protection, CORS (wildcard, wildcard+credentials, null), caching of session responses |
| CSP | missing / report-only, script and style sources, `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`/`http:`/`https:` schemes, `http://` hosts, object-src, base-uri, multiple policies |
| Disclosure | Server/X-Powered-By/framework version banners, private IPs in headers, stack traces, SQL errors, directory listings, sensitive HTML comments |
| Cookies | Secure, HttpOnly, SameSite (incl. None without Secure), `__Host-`/`__Secure-` prefix rules, broad Domain, long-lived session cookies |

## Originality (what is not just "is the header present?")
- **Spec-aware CSP logic:** `script-src` falls back to `default-src`; `'unsafe-inline'` is ignored by browsers when a
  nonce/hash/`'strict-dynamic'` is present so it is *not* reported then; report-only does not protect; every policy in
  multiple headers is checked.
- **Context-aware severity:** a session cookie missing HttpOnly is MEDIUM, a theme cookie is LOW; CSRF cookies are exempt
  from HttpOnly; HSTS is not demanded over plain HTTP; CSP `frame-ancestors` satisfies the clickjacking check.
- **Cross-header correlation:** a response that sets a session cookie without `Cache-Control: no-store` is flagged.

## Ethical design decisions
| Decision | Why |
|---|---|
| Module makes no network requests | Scope validation, dry-run and kill switch stay in one audited place (Member 4) |
| Cookie values never read or stored | Session values are credentials; evidence only needs name and flags |
| Evidence truncated to 80 chars | Prevents reports from copying large leaked content |
| Demo servers and fetcher bound to loopback | Safe default; demo can never touch a real site |

## Testing
33 pytest tests (cookies, CSP, headers, disclosure, ordering/de-duplication) plus an integration test that audits a
deliberately weak and a hardened local server: weak = 1 HIGH, 5 MEDIUM, 12 LOW, 2 INFO; hardened = only 1 INFO.

## Challenges and solutions
- **Avoiding false positives in CSP:** presence checks flagged policies that were actually safe (nonce + unsafe-inline).
  Solved by parsing directives and following fallback/neutralisation rules from the CSP specification.
- **Duplicate headers:** several `Set-Cookie` lines collapse in a dictionary. Solved by using a list of pairs in `ResponseData`.
- **Shared interface:** four people write modules in parallel. Solved with a tiny `Finding`/`ResponseData` contract and a pure function `audit()`.

## Future improvements
Meta-tag CSP, `Clear-Site-Data`, COOP/COEP/CORP, cookie value entropy checks (opt-in), subresource integrity, and a
per-finding confidence level.

## References
MDN Web Docs - HTTP headers, CSP, Set-Cookie; OWASP Secure Headers Project; OWASP Web Security Testing Guide (information gathering);
W3C Content Security Policy Level 3; RFC 6265bis (cookies); RFC 6797 (HSTS).
