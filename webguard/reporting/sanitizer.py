"""Redact recognisable sensitive information from report text."""

import re

SENSITIVE_PATTERN = re.compile(
    r"\b(password|passwd|pwd|api[_-]?key|access[_-]?token|"
    r"secret|token|authorization)\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\r\n,;]+)",
    re.IGNORECASE,
)

BEARER_PATTERN = re.compile(
    r"\bBearer\s+[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)


def sanitize_text(text: str) -> str:
    """Redact common credential patterns from text."""
    text = SENSITIVE_PATTERN.sub(r"\1=[REDACTED]", text)
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", text)

    return text