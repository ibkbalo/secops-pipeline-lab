# predeploy/remediation_readiness.py
# Map evidence → RECOMMEND_APPROVE | RECOMMEND_REVIEW | RECOMMEND_REJECT

from __future__ import annotations

from typing import Any

VERSION = "0.1.0"


def compute_recommendation(
    *,
    finding_status: str,
    terraform: dict[str, Any] | None,
    blast: dict[str, Any] | None,
    discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Brain recommendation only — never authorization.
    """
    tf = terraform or {}
    blast = blast or {}
    disc = discovery or {}
    flags = tf.get("flags") or {}
    validate = (tf.get("validate") or {}).get("status") or "FAIL"
    plan = (tf.get("plan") or {}).get("status") or "FAIL"
    destructive = (tf.get("plan") or {}).get("destructive_actions") == "PRESENT" or flags.get("destructive_tf")
    placeholders = bool(flags.get("placeholder_unresolved"))
    level = (blast.get("level") or "MEDIUM").upper()
    public_deps = int((disc.get("summary") or {}).get("public_buckets") or 0) + int(
        (disc.get("summary") or {}).get("website_buckets") or 0
    )
    reasons: list[str] = []

    if finding_status == "ALREADY_REMEDIATED":
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "reasons": [
                "Finding appears already remediated in live environment — no change required unless drift expected"
            ],
            "manager_approval_required": True,
            "version": VERSION,
        }

    if placeholders:
        reasons.append("Unresolved Terraform placeholders (e.g. REPLACE_*)")
    if validate == "FAIL":
        reasons.append("Terraform validate failed / incomplete")
    if plan == "FAIL":
        reasons.append("Terraform plan failed or not ready")
    if destructive:
        reasons.append("Destructive Terraform actions present")

    if placeholders or validate == "FAIL" or (plan == "FAIL" and placeholders):
        return {
            "recommendation": "RECOMMEND_REJECT",
            "deployment_ready": False,
            "reasons": reasons or ["Remediation not deployment-ready"],
            "manager_approval_required": True,
            "version": VERSION,
        }

    if destructive or level == "CRITICAL":
        return {
            "recommendation": "RECOMMEND_REJECT" if destructive and level == "CRITICAL" else "RECOMMEND_REVIEW",
            "deployment_ready": False,
            "reasons": reasons
            + [
                f"Blast radius {level}",
                "Destructive or critical-impact change requires human context",
            ],
            "manager_approval_required": True,
            "version": VERSION,
        }

    if (
        level in {"HIGH", "MEDIUM"}
        or public_deps > 0
        or flags.get("iam_change")
        or flags.get("networking_change")
        or "MANAGER CONTEXT REQUIRED" in str(disc.get("potentially_affected_workloads") or "")
    ):
        return {
            "recommendation": "RECOMMEND_REVIEW",
            "deployment_ready": validate == "PASS" and plan in {"PASS", "SKIP"} and not placeholders,
            "reasons": [
                f"Blast radius / operational risk: {level}",
                "Business context or dependency review recommended",
            ]
            + ([f"Public/website buckets: {public_deps}"] if public_deps else []),
            "manager_approval_required": True,
            "version": VERSION,
        }

    if finding_status == "CONFIRMED" and validate == "PASS" and plan in {"PASS", "SKIP"} and not destructive:
        return {
            "recommendation": "RECOMMEND_APPROVE",
            "deployment_ready": True,
            "reasons": [
                "Finding confirmed in live environment",
                "Terraform readiness OK",
                "No destructive actions detected",
                f"Blast radius {level}",
            ],
            "manager_approval_required": True,
            "version": VERSION,
        }

    return {
        "recommendation": "RECOMMEND_REVIEW",
        "deployment_ready": False,
        "reasons": reasons or ["Insufficient confidence — manager review required"],
        "manager_approval_required": True,
        "version": VERSION,
    }
