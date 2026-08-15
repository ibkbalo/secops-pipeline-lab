# change_assurance/models.py
# Shared change-assurance data models (domain-agnostic).

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

VERSION = "0.1.0"

DOMAINS = (
    "cloud_security",
    "security_engineering",
    "devsecops",
    "ai_security",
    "unknown",
)

ROLE_TO_DOMAIN = {
    "cloud": "cloud_security",
    "security-engineer": "security_engineering",
    "devsecops": "devsecops",
    "ai-security": "ai_security",
}

RECOMMENDATIONS = (
    "RECOMMEND_APPROVE",
    "RECOMMEND_REVIEW",
    "RECOMMEND_REJECT",
    "NO_ACTION_REQUIRED",
)

BLAST_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def domain_for_role(role: str | None) -> str:
    return ROLE_TO_DOMAIN.get(str(role or "").strip().lower(), "unknown")


def new_change_artifact(
    *,
    finding_id: str,
    domain: str,
    artifact_type: str,
    target_environment: str | None = None,
    source_files: list[str] | None = None,
    proposed_changes: list[dict] | None = None,
    content_preview: str | None = None,
    meta: dict | None = None,
) -> dict[str, Any]:
    body = {
        "finding_id": finding_id,
        "domain": domain,
        "artifact_type": artifact_type,
        "target_environment": target_environment,
        "source_files": source_files or [],
        "proposed_changes": proposed_changes or [],
        "content_preview": (content_preview or "")[:4000],
        "meta": meta or {},
    }
    artifact_id = f"artifact_{stable_hash(body)[:12]}"
    return {
        "artifact_id": artifact_id,
        "artifact_hash": stable_hash(body),
        **body,
        "validation": {},
        "dependencies": [],
        "rollback": {},
        "verification": {},
    }


def new_evidence(
    *,
    finding_id: str | None,
    domain: str,
    source_type: str,
    source: str,
    target: str | None = None,
    observed_value: Any = None,
    expected_value: Any = None,
    confidence: str = "MEDIUM",
) -> dict[str, Any]:
    return {
        "evidence_id": f"ev_{stable_hash([finding_id, source, observed_value])[:12]}",
        "finding_id": finding_id,
        "domain": domain,
        "source_type": source_type,
        "source": source,
        "target": target,
        "observed_value": observed_value,
        "expected_value": expected_value,
        "timestamp": now(),
        "confidence": confidence.upper() if isinstance(confidence, str) else "MEDIUM",
    }


def empty_assurance_report(
    *,
    job_id: str | None,
    domain: str,
    role: str | None,
) -> dict[str, Any]:
    return {
        "version": VERSION,
        "type": "change_assurance_report",
        "created_at": now(),
        "job_id": job_id,
        "role": role,
        "domain": domain,
        "finding_status": "UNKNOWN",
        "artifacts": [],
        "evidence": [],
        "dependencies": [],
        "blast_radius": {"level": "UNKNOWN", "reasons": [], "scope": "UNKNOWN"},
        "remediation_risk": {"level": "UNKNOWN", "reasons": []},
        "recommendation": "RECOMMEND_REVIEW",
        "deployment_ready": False,
        "manager_approval_required": True,
        "auto_apply_forbidden": True,
        "manager_context_required": True,
        "manager_questions": [],
        "validation_status": "VALIDATION_UNAVAILABLE",
        "rollback": {"available": "UNKNOWN", "procedure": "UNKNOWN"},
        "verification": {},
        "approval_binding": None,
        "agents": {
            "discovered_by": role,
            "investigated_by": role,
            "remediation_proposed_by": role,
            "impact_analyzed_by": "change_assurance_engine",
            "challenged_by": None,
        },
        "report_text": "",
        "legacy_impact": None,
        "capabilities": [],
        "guardrails": [
            "No agent may authorize itself",
            "Recommendation is not authorization",
            "No automatic remediation execution",
            "Unknown means UNKNOWN, not PASS",
        ],
    }
