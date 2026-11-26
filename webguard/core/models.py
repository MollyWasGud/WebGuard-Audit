"""Shared data contract between WebGuard modules.

Member 4 (CLI/ethics) fetches a page AFTER scope validation and builds a ResponseData.
Members 1 and 2 turn it into Findings. Member 3 scores and reports the Findings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Finding:
    check_id: str          # stable id, e.g. "CSP:unsafe-inline"
    category: str          # "headers" | "csp" | "disclosure" | "cookies" | "tls" ...
    severity: str          # one of SEVERITIES
    title: str
    detail: str            # why it matters
    remediation: str       # how to fix
    evidence: str = ""     # short, SAFE evidence (never a cookie value or secret)
    reference: str = ""    # URL for further reading

    def key(self) -> str:
        return f"{self.check_id}|{self.evidence}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(repr=False)
class ResponseData:
    """Everything the HTTP auditor needs, with NO network access of its own."""

    url: str
    status: int
    # repr=False: raw headers/body can hold secrets, so they never appear in logs or tracebacks
    headers: list[tuple[str, str]] = field(repr=False)   # pairs: duplicates (Set-Cookie) are preserved
    body: str = field(default="", repr=False)

    def __repr__(self) -> str:
        # Only scheme://host:port is shown: the path, query string (tokens!), user:password and fragment are omitted.
        try:
            parts = urlsplit(self.url)
            origin = f"{parts.scheme}://{parts.hostname or ''}" + (f":{parts.port}" if parts.port else "")
        except ValueError:
            origin = "<unparseable>"
        return f"ResponseData(origin={origin!r}, status={self.status})"

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")

    def get(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        return [value for key, value in self.headers if key.lower() == name.lower()]
