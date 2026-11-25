"""Information-disclosure checks: software versions, internal IPs, error pages, risky HTML comments."""

from __future__ import annotations

import re

from ...core.models import Finding, ResponseData

REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
VERSIONED = re.compile(r"[A-Za-z][\w.\-]*/\d|\b\d+\.\d+")
TECH_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime", "X-Drupal-Cache")
PRIVATE_IP = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
BODY_RULES = [  # (check id, severity, title, regex)
    ("stack-trace", "HIGH", "Stack trace / debug output in response",
     re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|Fatal error:.* on line \d+|Stack trace:", re.I)),
    ("sql-error", "HIGH", "Database error message in response",
     re.compile(r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[|pg_query\(\)|SQLite3::|Unclosed quotation mark", re.I)),
    ("directory-listing", "MEDIUM", "Directory listing enabled", re.compile(r"<title>Index of /", re.I)),
]
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
RISKY_COMMENT = re.compile(r"password|passwd|secret|api[_-]?key|todo|fixme|debug|credential", re.I)


def _add(out, check, severity, title, detail, fix, evidence=""):
    out.append(Finding(f"DISCLOSURE:{check}", "disclosure", severity, title, detail, fix, evidence[:80], REF))


def audit_disclosure(resp: ResponseData) -> list[Finding]:
    out: list[Finding] = []
    server = resp.get("Server")
    if server:
        if VERSIONED.search(server):
            _add(out, "server-version", "LOW", "Server header reveals software version",
                 "Attackers can look up known vulnerabilities for that exact version.",
                 "Hide the version (e.g. ServerTokens Prod, server_tokens off).", f"Server: {server}")
        else:
            _add(out, "server-banner", "INFO", "Server header reveals software name", "Helps fingerprinting.",
                 "Remove or genericise the Server header.", f"Server: {server}")
    for name in TECH_HEADERS:
        value = resp.get(name)
        if value:
            _add(out, "tech-header", "LOW" if VERSIONED.search(value) else "INFO", f"{name} reveals technology",
                 "Discloses the framework/runtime used.", f"Remove the {name} header.", f"{name}: {value}")
    for key, value in resp.headers:
        if key.lower() not in ("set-cookie",) and PRIVATE_IP.search(value):
            _add(out, "internal-ip", "MEDIUM", f"Internal IP address leaked in {key}",
                 "Reveals private network layout.", "Strip internal addresses from response headers.", f"{key}: {value}")
    for check, severity, title, pattern in BODY_RULES:
        match = pattern.search(resp.body)
        if match:
            _add(out, check, severity, title, "Verbose output helps an attacker understand internals.",
                 "Disable debug mode and show generic error pages.", match.group(0))
    for comment in COMMENT.findall(resp.body):
        if RISKY_COMMENT.search(comment):
            _add(out, "html-comment", "LOW", "Sensitive-looking keyword in HTML comment",
                 "Developer comments are visible to every visitor.", "Remove comments before deployment.", comment.strip())
    return out
