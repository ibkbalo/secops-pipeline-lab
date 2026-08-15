# change_assurance/secret_redaction.py
# Never store raw secrets in Face/reports/logs.

from __future__ import annotations

import re
from typing import Any

REDACTED = "SECRET_REDACTED"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("connection_string", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+")),
]


def redact_text(text: str | None) -> tuple[str, list[dict[str, Any]]]:
    if not text:
        return "", []
    out = text
    hits: list[dict[str, Any]] = []
    for stype, pat in PATTERNS:
        for m in pat.finditer(text):
            hits.append(
                {
                    "secret_type": stype,
                    "status": REDACTED,
                    "span": [m.start(), m.end()],
                }
            )
            out = out.replace(m.group(0), f"[{REDACTED}:{stype}]")
    return out, hits


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        redacted, _ = redact_text(value)
        return redacted
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    return value
