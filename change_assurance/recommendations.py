# change_assurance/recommendations.py

from __future__ import annotations

from typing import Any


def _blocking_manager_questions(questions: list[str] | None) -> list[str]:
    """
    Only unresolved decisions that Sentinel cannot safely make force REVIEW.
    Informational considerations (cost notes, region-scope awareness) do not.
    Human authorization is ALWAYS required separately — that alone never forces REVIEW.
    """
    blocking: list[str] = []
    for q in questions or []:
        text = str(q)
        upper = text.upper()
        # Explicit consideration / FYI wording → never blocking
        if "MANAGER CONSIDERATION" in upper or "FOR AWARENESS" in upper:
            continue
        # Legacy / explicit required-context questions remain blocking
        if "MANAGER CONTEXT REQUIRED" in upper:
            blocking.append(text)
            continue
        # Defensive: intentional-public / traffic-interrupt style unknowns
        low = text.lower()
        if any(
            tok in low
            for tok in (
                "intentionally public",
                "interrupt legitimate traffic",
                "break-glass",
                "evidence is insufficient",
            )
        ):
            blocking.append(text)
    return blocking


def recommend(
    *,
    finding_status: str,
    validation_status: str,
    blast_level: str,
    remediation_risk: str,
    destructive: bool,
    placeholders: bool,
    manager_questions: list[str] | None = None,
    protected_asset_hit: bool = False,
    capability_unavailable: bool = False,
    force_reject: bool = False,
    artifact_mapping_uncertain: bool = False,
) -> dict[str, Any]:
    """Advisory only — never authorization."""
    questions = list(manager_questions or [])
    blocking = _blocking_manager_questions(questions)
    considerations = [q for q in questions if q not in blocking]
    reasons: list[str] = []

    if finding_status == "ALREADY_REMEDIATED":
        return {
            "recommendation": "NO_ACTION_REQUIRED",
            "deployment_ready": False,
            "reasons": ["Live state indicates finding already remediated"],
            "manager_approval_required": True,
        }

    if finding_status in {"UNVERIFIED", "ERROR", "UNKNOWN"}:
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "remediation_status": "NOT_READY",
            "execution_ready": False,
            "reasons": [
                f"Finding status={finding_status} — evidence is insufficient or unavailable to confirm the control",
                "Do not approve remediation based on unverified evidence",
            ],
            "manager_approval_required": True,
        }

    if force_reject:
        return {
            "recommendation": "RECOMMEND_REJECT",
            "deployment_ready": False,
            "reasons": ["Hard reject signal (secret / dangerous CI pattern / unsafe container)"],
            "manager_approval_required": True,
        }

    if artifact_mapping_uncertain:
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "reasons": [
                "ARTIFACT_MAPPING_UNCERTAIN",
                "Cannot confidently determine which kit artifacts belong to this finding",
            ],
            "manager_approval_required": True,
        }

    if placeholders:
        reasons.append("Unresolved placeholders in change artifact")
        reasons.append("REMEDIATION_PREREQUISITES_REQUIRED")
    if validation_status == "FAIL" and not placeholders:
        reasons.append("Artifact validation failed")
    if destructive and blast_level in {"CRITICAL", "HIGH"}:
        reasons.append("Destructive actions with elevated blast radius")
    if protected_asset_hit:
        reasons.append("Protected asset would be modified/deleted")

    # Placeholders = prerequisites required (reviewable, not execution-ready; not a hard reject)
    if placeholders:
        return {
            "recommendation": "REMEDIATION_PREREQUISITES_REQUIRED",
            "deployment_ready": False,
            "remediation_status": "PREREQUISITES_REQUIRED",
            "reasons": reasons or ["Unresolved REPLACE_*/TODO/CHANGEME placeholders"],
            "manager_approval_required": True,
            "execution_ready": False,
        }

    if validation_status == "FAIL" or (destructive and blast_level == "CRITICAL") or protected_asset_hit:
        return {
            "recommendation": "RECOMMEND_REJECT",
            "deployment_ready": False,
            "reasons": reasons or ["Change is not safe to authorize"],
            "manager_approval_required": True,
        }

    # Genuine unresolved manager decisions → REVIEW (not merely "human must approve")
    if blocking:
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "remediation_status": "NOT_READY",
            "reasons": reasons
            + [
                f"Blast={blast_level}",
                f"Remediation risk={remediation_risk}",
                f"Unresolved manager decisions: {len(blocking)}",
            ]
            + blocking[:5],
            "manager_approval_required": True,
            "manager_considerations": considerations,
        }

    if (
        capability_unavailable
        or validation_status in {"VALIDATION_UNAVAILABLE", "UNKNOWN"}
        or blast_level in {"HIGH", "CRITICAL", "UNKNOWN"}
        or remediation_risk in {"HIGH", "CRITICAL", "UNKNOWN"}
        or destructive
    ):
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "reasons": reasons
            + [
                f"Blast={blast_level}",
                f"Remediation risk={remediation_risk}",
                f"Validation={validation_status}",
            ],
            "manager_approval_required": True,
            "manager_considerations": considerations,
        }

    if finding_status == "CONFIRMED" and validation_status == "PASS" and not destructive:
        approve_reasons = [
            "Finding confirmed with direct evidence",
            "Validation passed",
            "No destructive actions",
            f"Blast={blast_level}",
            f"Remediation risk={remediation_risk}",
            "AI recommendation is advisory — manager authorization remains mandatory",
        ]
        if considerations:
            approve_reasons.append(
                f"Manager considerations noted ({len(considerations)}) — not blockers"
            )
        return {
            "recommendation": "RECOMMEND_APPROVE",
            "deployment_ready": True,
            "remediation_status": "READY",
            "execution_ready": True,
            "reasons": approve_reasons,
            "manager_approval_required": True,
            "manager_considerations": considerations,
        }

    return {
        "recommendation": "RECOMMEND_REVIEW",
        "deployment_ready": False,
        "reasons": reasons or ["Insufficient confidence"],
        "manager_approval_required": True,
        "manager_considerations": considerations,
    }
