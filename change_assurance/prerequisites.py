# change_assurance/prerequisites.py
# Map unresolved Terraform placeholders → manager-facing prerequisites.
# Advisory only — never creates AWS resources or auto-applies.

from __future__ import annotations

import re
from typing import Any

VERSION = "0.1.0"

# Explicit token → prerequisite (control-specific labels)
KNOWN_PREREQUISITES: dict[str, dict[str, str]] = {
    "REPLACE_CONFIG_ROLE": {
        "id": "aws_config_iam_role",
        "label": "AWS Config IAM role",
        "decision": "Reuse an existing approved Config service role, or create a dedicated role (manager review required).",
    },
    "REPLACE_CONFIG_BUCKET": {
        "id": "aws_config_delivery_bucket",
        "label": "S3 delivery bucket",
        "decision": "Reuse an existing approved Config delivery bucket, or create a dedicated bucket (manager review required).",
    },
    "REPLACE_CLOUDTRAIL_BUCKET": {
        "id": "cloudtrail_s3_bucket",
        "label": "CloudTrail S3 bucket",
        "decision": "Reuse an existing approved trail bucket, or create a dedicated bucket (manager review required).",
    },
    "REPLACE_FLOW_LOGS": {
        "id": "flow_logs_destination",
        "label": "VPC Flow Logs destination",
        "decision": "Choose an approved CloudWatch Logs group or S3 destination before apply.",
    },
    "REPLACE_FLOW_LOGS_ROLE": {
        "id": "flow_logs_iam_role",
        "label": "VPC Flow Logs IAM role",
        "decision": "Reuse an existing approved flow-logs role, or create a dedicated role (manager review required).",
    },
}

_TOKEN_RE = re.compile(r"REPLACE_[A-Z0-9_]+|TODO_[A-Z0-9_]*|\bTODO\b|CHANGEME|YOUR_[A-Z0-9_]+", re.I)


def normalize_token(token: str | None) -> str:
    return str(token or "").strip().upper()


def humanize_token(token: str) -> str:
    t = normalize_token(token)
    if t in KNOWN_PREREQUISITES:
        return KNOWN_PREREQUISITES[t]["label"]
    # REPLACE_CONFIG_ROLE → Config role
    body = re.sub(r"^(REPLACE_|TODO_|YOUR_)", "", t)
    body = body.replace("_", " ").strip().title()
    return body or t or "Unresolved placeholder"


def prerequisites_from_placeholders(
    placeholders: list[dict[str, Any]] | None,
) -> list[dict[str, str]]:
    """Deduped manager-facing prerequisites from placeholder scan hits."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for hit in placeholders or []:
        if not isinstance(hit, dict):
            continue
        token = normalize_token(hit.get("token"))
        if not token:
            continue
        key = token
        if key in seen:
            continue
        seen.add(key)
        known = KNOWN_PREREQUISITES.get(key)
        if known:
            out.append(
                {
                    "token": token,
                    "id": known["id"],
                    "label": known["label"],
                    "decision": known["decision"],
                    "file": str(hit.get("file") or ""),
                }
            )
        else:
            out.append(
                {
                    "token": token,
                    "id": f"placeholder:{token.lower()}",
                    "label": humanize_token(token),
                    "decision": (
                        "Supply an approved value for this placeholder, or generate a "
                        "dedicated prerequisite artifact for manager review before apply."
                    ),
                    "file": str(hit.get("file") or ""),
                }
            )
    return out


def manager_decision_prompt(prerequisites: list[dict[str, str]] | None) -> str | None:
    if not prerequisites:
        return None
    if any(p.get("id", "").startswith("aws_config_") for p in prerequisites):
        return "Reuse existing approved resources or create dedicated ones."
    return "Resolve each missing prerequisite with an approved value or dedicated resource plan."
