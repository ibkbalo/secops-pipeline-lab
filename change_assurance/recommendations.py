# change_assurance/recommendations.py

from __future__ import annotations

from typing import Any


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
) -> dict[str, Any]:
    """Advisory only — never authorization."""
    questions = manager_questions or []
    reasons: list[str] = []

    if finding_status == "ALREADY_REMEDIATED":
        return {
            "recommendation": "NO_ACTION_REQUIRED",
            "deployment_ready": False,
            "reasons": ["Live state indicates finding already remediated"],
            "manager_approval_required": True,
        }

    if force_reject:
        return {
            "recommendation": "RECOMMEND_REJECT",
            "deployment_ready": False,
            "reasons": ["Hard reject signal (secret / dangerous CI pattern / unsafe container)"],
            "manager_approval_required": True,
        }

    if placeholders:
        reasons.append("Unresolved placeholders in change artifact")
    if validation_status == "FAIL":
        reasons.append("Artifact validation failed")
    if destructive and blast_level in {"CRITICAL", "HIGH"}:
        reasons.append("Destructive actions with elevated blast radius")
    if protected_asset_hit:
        reasons.append("Protected asset would be modified/deleted")

    if placeholders or validation_status == "FAIL" or (destructive and blast_level == "CRITICAL") or protected_asset_hit:
        return {
            "recommendation": "RECOMMEND_REJECT",
            "deployment_ready": False,
            "reasons": reasons or ["Change is not safe to authorize"],
            "manager_approval_required": True,
        }

    if (
        capability_unavailable
        or validation_status in {"VALIDATION_UNAVAILABLE", "UNKNOWN"}
        or blast_level in {"HIGH", "CRITICAL", "UNKNOWN"}
        or remediation_risk in {"HIGH", "CRITICAL", "UNKNOWN"}
        or questions
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
            ]
            + ([f"Manager questions: {len(questions)}"] if questions else []),
            "manager_approval_required": True,
        }

    if finding_status == "CONFIRMED" and validation_status == "PASS" and not destructive:
        return {
            "recommendation": "RECOMMEND_APPROVE",
            "deployment_ready": True,
            "reasons": [
                "Finding confirmed",
                "Validation passed",
                "No destructive actions",
                f"Blast={blast_level}",
            ],
            "manager_approval_required": True,
        }

    return {
        "recommendation": "RECOMMEND_REVIEW",
        "deployment_ready": False,
        "reasons": reasons or ["Insufficient confidence"],
        "manager_approval_required": True,
    }
