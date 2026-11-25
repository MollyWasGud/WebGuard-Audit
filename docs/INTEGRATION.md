# Integration guide: Module 1 (HTTP Security Auditor)

Owner: Member 1. This module is **pure analysis**: it never opens a network connection.

## The contract (agree on this with Member 2, 3 and 4 TODAY)

```python
# webguard/core/models.py
ResponseData(url, status, headers=[(name, value), ...], body="")   # headers is a LIST of pairs (keeps duplicate Set-Cookie)
Finding(check_id, category, severity, title, detail, remediation, evidence="", reference="")
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
```

| Who | What they do with it |
|---|---|
| **Member 4** (CLI, ethics) | Validates scope, fetches the page (requests/urllib), builds `ResponseData` and calls `audit(resp)` |
| **Member 2** (TLS/HTTPS) | Returns `list[Finding]` with `category="tls"` using the same `Finding` class |
| **Member 3** (scoring/reports) | Receives all findings; maps `severity` to weights; reads `evidence`/`remediation` for the report |

If a teammate already wrote a different `Finding`, adapt `models.py` (rename fields) and keep the same meaning. Everything else in Module 1 only uses `ResponseData.get/get_all/is_https/headers/body`.

### Calling it (Member 4)

```python
import requests
from webguard.core.models import ResponseData
from webguard.auditors.http_audit import audit

r = requests.get(url, timeout=10, allow_redirects=False)
# requests merges duplicate headers; to keep every Set-Cookie use the raw headers:
headers = list(r.raw.headers.items())            # urllib3 HTTPHeaderDict; use .getlist("Set-Cookie") for duplicates
cookies = r.raw.headers.getlist("Set-Cookie")
headers = [(k, v) for k, v in r.headers.items() if k.lower() != "set-cookie"] + [("Set-Cookie", c) for c in cookies]
findings = audit(ResponseData(r.url, r.status_code, headers, r.text[:200_000]))
```
Use `allow_redirects=False` so headers of the page you scoped are audited, not another site's.

## Adding it to the team repo with YOUR OWN commits

Everyone must have meaningful commits, so do not just upload a zip.

```bash
git clone https://github.com/<team>/<repo>.git && cd <repo>
git checkout -b feature/http-auditor
# copy from this module: webguard/core/models.py (if not present), webguard/auditors/http_audit/, demo/, tests/test_http_audit.py, docs/
git add webguard/core/models.py            && git commit -m "feat(models): shared Finding/ResponseData contract"
git add webguard/auditors/http_audit/cookies.py webguard/auditors/http_audit/__init__.py && git commit -m "feat(cookies): audit Secure/HttpOnly/SameSite and prefix rules"
git add webguard/auditors/http_audit/csp.py    && git commit -m "feat(csp): spec-aware CSP analyser"
git add webguard/auditors/http_audit/headers.py && git commit -m "feat(headers): HSTS, clickjacking, referrer, CORS checks"
git add webguard/auditors/http_audit/disclosure.py && git commit -m "feat(disclosure): version, internal IP and error leaks"
git add demo tests && git commit -m "test: unit tests and loopback weak/hardened demo"
git push -u origin feature/http-auditor      # then open a Pull Request on GitHub
```
(`git config user.email` must be your GitHub email so the commits count for you.)

## Ethics built into Module 1
- No network access in the module (scope, dry-run, kill switch stay in Member 4's code).
- Cookie **values are never read or stored**; evidence contains names and attribute flags only.
- Evidence strings are truncated to 80 characters.
- The demo fetcher refuses every host except `127.0.0.1`, `localhost` and `::1`.
