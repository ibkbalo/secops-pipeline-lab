# change_assurance/capabilities/identities.py
# Separated security identities for Sentinel remediation lifecycle.

from __future__ import annotations

from typing import Any

from change_assurance.capabilities.types import (
    IDENTITY_BOOTSTRAP_PROVISIONER,
    IDENTITY_REMEDIATION_EXECUTOR,
    IDENTITY_SCANNER_PLANNER,
)

# Lab defaults — never grant self-escalation to the remediation executor.
DEFAULT_SCANNER_PROFILE = "sentinel-demo"
DEFAULT_SCANNER_ROLE = "SentinelStacksDemoRead"
DEFAULT_EXECUTION_ROLE = "SentinelStacksRemediationRole"
DEFAULT_EXECUTION_PROFILE = "sentinel-remediation"
# Human console operator — NOT an automatic machine bootstrap identity.
LAB_HUMAN_OPERATOR = "sentinel-operator"


def resolve_identities(job: dict[str, Any] | None = None, *, account_id: str | None = None) -> dict[str, Any]:
    """Resolve scanner/planner vs remediation executor vs bootstrap path (metadata only)."""
    job = job or {}
    acct = str(account_id or job.get("aws_account_id") or "").strip() or None
    planning_profile = (
        job.get("planning_profile")
        or job.get("scanner_profile")
        or job.get("aws_profile")
        or DEFAULT_SCANNER_PROFILE
    )
    planning_identity = job.get("planning_identity") or (
        f"arn:aws:iam::{acct}:role/{DEFAULT_SCANNER_ROLE}" if acct else DEFAULT_SCANNER_ROLE
    )
    execution_role = job.get("execution_role") or DEFAULT_EXECUTION_ROLE
    execution_profile = job.get("execution_profile") or DEFAULT_EXECUTION_PROFILE
    execution_identity = job.get("execution_identity") or (
        f"arn:aws:iam::{acct}:role/{execution_role}" if acct else f"role/{execution_role}"
    )

    # Lab has no programmatic privileged bootstrap executor today.
    # sentinel-operator is a human console principal, not a machine apply identity.
    # Remediation role and scanner must never act as bootstrap provisioners.
    bootstrap_executor_available = False
    bootstrap_path = {
        "kind": IDENTITY_BOOTSTRAP_PROVISIONER,
        "status": "NO_PROGRAMMATIC_BOOTSTRAP_EXECUTOR",
        "lab_human_operator": LAB_HUMAN_OPERATOR,
        "note": (
            "No configured machine identity holds iam:PutRolePolicy on the remediation role. "
            "Capability provisioning requires an explicitly authorized administrator-controlled "
            "bootstrap path (customer install/update). sentinel-operator is a human console "
            "operator and must not be silently treated as an agent bootstrap executor."
        ),
        "forbidden_executors": [execution_identity, planning_identity],
        "self_escalation_forbidden": True,
    }

    return {
        IDENTITY_SCANNER_PLANNER: {
            "profile": planning_profile,
            "identity": planning_identity,
            "role_name": DEFAULT_SCANNER_ROLE,
            "writes_allowed": False,
        },
        IDENTITY_REMEDIATION_EXECUTOR: {
            "profile": execution_profile,
            "identity": execution_identity,
            "role_name": execution_role,
            "may_modify_own_iam": False,
            "writes_allowed_after_approval": True,
        },
        IDENTITY_BOOTSTRAP_PROVISIONER: bootstrap_path,
        "bootstrap_executor_available": bootstrap_executor_available,
        "account_id": acct,
    }
