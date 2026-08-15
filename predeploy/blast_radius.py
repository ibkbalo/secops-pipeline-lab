# predeploy/blast_radius.py
# Classify remediation blast radius from evidence (not finding severity alone).

from __future__ import annotations

from typing import Any

VERSION = "0.1.0"


def classify_blast_radius(
    *,
    finding_ids: list[str] | None = None,
    scope: str = "resource",
    terraform_summary: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    flags: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """
    Returns {level, reasons, operational_risk, score}.
    Levels: LOW | MEDIUM | HIGH | CRITICAL
    """
    flags = flags or {}
    tf = terraform_summary or {}
    disc = discovery or {}
    reasons: list[str] = []
    score = 0

    scope_l = (scope or "resource").lower()
    if scope_l in {"account", "account-wide", "organization", "org"}:
        score += 40
        reasons.append(f"Scope is {scope_l}")
    elif scope_l in {"region", "regional"}:
        score += 20
        reasons.append("Regional scope")

    destroys = int(tf.get("destroy") or 0)
    replaces = int(tf.get("replace") or 0)
    modifies = int(tf.get("modify") or 0)
    creates = int(tf.get("create") or 0)

    if destroys > 0:
        score += 50
        reasons.append(f"Terraform plan destroys {destroys} resource(s)")
    if replaces > 0:
        score += 35
        reasons.append(f"Terraform plan replaces {replaces} resource(s)")
    if modifies > 5:
        score += 15
        reasons.append(f"Many modifications ({modifies})")

    if flags.get("iam_change"):
        score += 30
        reasons.append("IAM / privilege change")
    if flags.get("networking_change"):
        score += 30
        reasons.append("Networking / SG / NACL / routing change")
    if flags.get("destructive_tf"):
        score += 40
        reasons.append("Destructive Terraform actions detected")
    if flags.get("placeholder_unresolved"):
        score += 25
        reasons.append("Unresolved Terraform placeholders")
    if flags.get("public_workload_dependency"):
        score += 35
        reasons.append("Workload may depend on public/exposed access")
    if flags.get("data_access_change"):
        score += 25
        reasons.append("Data access / public exposure control change")

    # Soft signals from discovery
    if int(disc.get("public_buckets") or 0) > 0:
        score += 25
        reasons.append("Public S3 buckets detected")
    if int(disc.get("website_buckets") or 0) > 0:
        score += 30
        reasons.append("S3 static website buckets detected")

    if score >= 80:
        level = "CRITICAL"
        op = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
        op = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
        op = "MEDIUM"
    else:
        level = "LOW"
        op = "LOW"
        if not reasons:
            reasons.append("Isolated / additive control with no destructive plan signals")

    # Isolated create-only account BPA without public deps → can stay LOW even if account-wide
    if (
        scope_l in {"account", "account-wide"}
        and creates <= 2
        and destroys == 0
        and replaces == 0
        and not flags.get("public_workload_dependency")
        and int(disc.get("public_buckets") or 0) == 0
        and int(disc.get("website_buckets") or 0) == 0
        and not flags.get("iam_change")
        and not flags.get("networking_change")
    ):
        if level in {"HIGH", "CRITICAL"}:
            level = "MEDIUM"
            op = "MEDIUM"
            reasons.append("Account-wide but additive/non-destructive; operational risk moderated")
        elif level == "MEDIUM" and score <= 45:
            level = "LOW"
            op = "LOW"
            reasons.append("Account-wide additive control with no public workload dependency")

    return {
        "level": level,
        "operational_risk": op,
        "score": score,
        "reasons": reasons,
        "scope": scope,
        "version": VERSION,
    }
