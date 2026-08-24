# change_assurance/approval_integrity.py
# Cryptographic-style binding of manager approval to exact reviewed change.
# Never executes remediations. Recommendation != authorization.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from change_assurance.models import now, stable_hash

VERSION = "0.2.0-p3"

INVALIDATION_REASONS = (
    "ARTIFACT_CHANGED",
    "PLAN_CHANGED",
    "SOURCE_ARTIFACT_CHANGED",
    "ACCOUNT_MISMATCH",
    "REGION_MISMATCH",
    "EXECUTION_ROLE_CHANGED",
    "PARTIAL_EXECUTION_CHANGED_STATE",
    "TARGET_CHANGED",
    "ENVIRONMENT_CHANGED",
    "ASSURANCE_REPORT_CHANGED",
    "LIVE_STATE_CHANGED",
    "DEPENDENCY_CHANGED",
    "COMMIT_CHANGED",
    "DIFF_CHANGED",
    "RECOMMENDATION_CHANGED",
)


def _change_hash(artifacts: list[dict]) -> str:
    parts = []
    for a in artifacts:
        parts.append(
            {
                "artifact_id": a.get("artifact_id"),
                "artifact_hash": a.get("artifact_hash"),
                "proposed_changes": a.get("proposed_changes"),
                "content_preview": a.get("content_preview"),
                "source_files": a.get("source_files"),
                "meta_fingerprint": (a.get("meta") or {}).get("repo_fingerprint")
                or (a.get("meta") or {}).get("git_diff_hash")
                or (a.get("meta") or {}).get("plan_hash"),
            }
        )
    return stable_hash(parts)


def _plan_hashes(artifacts: list[dict]) -> dict[str, str | None]:
    out: dict[str, str | None] = {
        "terraform_plan_hash": None,
        "saved_plan_sha256": None,
        "source_artifact_sha256": None,
        "plan_account_id": None,
        "plan_region": None,
        "execution_role": None,
        "execution_identity": None,
        "saved_plan_path": None,
        "git_diff_hash": None,
        "configuration_diff_hash": None,
        "policy_diff_hash": None,
        "plan_or_diff_hash": None,
    }
    plan_parts = []
    for a in artifacts:
        meta = a.get("meta") or {}
        val = a.get("validation") or {}
        analysis = val.get("analysis") or {}
        reviewed = analysis.get("reviewed_plan") or (analysis.get("plan") or {}).get("reviewed_plan")
        atype = str(a.get("artifact_type") or "")
        if atype == "terraform":
            if isinstance(reviewed, dict) and reviewed.get("plan_content_hash"):
                ph = str(reviewed["plan_content_hash"])
                out["terraform_plan_hash"] = ph
                out["saved_plan_sha256"] = reviewed.get("saved_plan_sha256") or meta.get("saved_plan_sha256")
                out["source_artifact_sha256"] = (
                    reviewed.get("source_artifact_sha256") or meta.get("source_artifact_sha256")
                )
                out["plan_account_id"] = reviewed.get("account_id") or meta.get("plan_account_id")
                out["plan_region"] = reviewed.get("region") or meta.get("plan_region")
                out["execution_role"] = reviewed.get("execution_role") or meta.get("execution_role")
                out["execution_identity"] = (
                    reviewed.get("execution_identity") or meta.get("execution_identity")
                )
                out["saved_plan_path"] = reviewed.get("saved_plan_path") or meta.get("saved_plan_path")
                plan_parts.append(ph)
                if out["saved_plan_sha256"]:
                    plan_parts.append(str(out["saved_plan_sha256"]))
                if out["execution_role"]:
                    plan_parts.append(f"role:{out['execution_role']}")
            else:
                ph = meta.get("plan_hash") or stable_hash(analysis.get("plan") or a.get("proposed_changes") or {})
                out["terraform_plan_hash"] = ph
                plan_parts.append(ph)
            if meta.get("source_artifact_sha256") and not out["source_artifact_sha256"]:
                out["source_artifact_sha256"] = meta.get("source_artifact_sha256")
            if meta.get("execution_role") and not out["execution_role"]:
                out["execution_role"] = meta.get("execution_role")
            if meta.get("execution_identity") and not out["execution_identity"]:
                out["execution_identity"] = meta.get("execution_identity")
            if meta.get("saved_plan_path") and not out["saved_plan_path"]:
                out["saved_plan_path"] = meta.get("saved_plan_path")
        if meta.get("git_diff_hash"):
            out["git_diff_hash"] = meta.get("git_diff_hash")
            plan_parts.append(meta.get("git_diff_hash"))
        if meta.get("configuration_diff_hash"):
            out["configuration_diff_hash"] = meta.get("configuration_diff_hash")
            plan_parts.append(meta.get("configuration_diff_hash"))
        if meta.get("policy_diff_hash"):
            out["policy_diff_hash"] = meta.get("policy_diff_hash")
            plan_parts.append(meta.get("policy_diff_hash"))
        if not plan_parts:
            plan_parts.append(stable_hash(a.get("proposed_changes") or analysis.get("plan") or {}))
    out["plan_or_diff_hash"] = stable_hash(plan_parts)
    return out


def assurance_report_hash(report: dict[str, Any] | None) -> str:
    if not report:
        return stable_hash({})
    # Normalize: exclude volatile timestamps/paths
    slim = {
        "domain": report.get("domain"),
        "primary_finding_id": report.get("primary_finding_id"),
        "finding_status": report.get("finding_status"),
        "recommendation": report.get("recommendation"),
        "validation_status": report.get("validation_status"),
        "blast_radius": report.get("blast_radius"),
        "remediation_risk": report.get("remediation_risk"),
        "artifacts": [
            {
                "artifact_id": a.get("artifact_id"),
                "artifact_hash": a.get("artifact_hash"),
                "artifact_type": a.get("artifact_type"),
            }
            for a in (report.get("artifacts") or [])
        ],
        "live_state_fingerprint": report.get("live_state_fingerprint"),
        "repo_fingerprint": report.get("repo_fingerprint"),
    }
    return stable_hash(slim)


def build_approval_binding(
    *,
    job_id: str,
    finding_id: str | None,
    artifacts: list[dict],
    target_environment: str | None,
    recommendation: str | None,
    assurance_report: dict | None = None,
    target_identity: str | None = None,
    manager_decision: str | None = None,
) -> dict[str, Any]:
    artifact_hashes = [a.get("artifact_hash") for a in artifacts if a.get("artifact_hash")]
    plans = _plan_hashes(artifacts)
    live_fp = None
    repo_fp = None
    if assurance_report:
        live_fp = assurance_report.get("live_state_fingerprint")
        repo_fp = assurance_report.get("repo_fingerprint")
    if not repo_fp:
        for a in artifacts:
            repo_fp = (a.get("meta") or {}).get("repo_fingerprint") or repo_fp
    return {
        "version": VERSION,
        "job_id": job_id,
        "finding_id": finding_id,
        "artifact_ids": [a.get("artifact_id") for a in artifacts],
        "artifact_id": (artifacts[0].get("artifact_id") if artifacts else None),
        "artifact_hash": stable_hash(artifact_hashes),
        "change_hash": _change_hash(artifacts),
        "assurance_report_hash": assurance_report_hash(assurance_report),
        "target_environment": target_environment,
        "target_identity": target_identity,
        "live_state_fingerprint": live_fp,
        "repo_fingerprint": repo_fp,
        "recommendation_at_bind": recommendation,
        "manager_decision": manager_decision,
        "approval_timestamp": now() if manager_decision else None,
        "bound_at": now(),
        "status": "APPROVED_FOR_EXECUTION" if manager_decision == "approved" else "PENDING_MANAGER_DECISION",
        **plans,
    }


def validate_approval_binding(
    binding: dict[str, Any] | None,
    *,
    artifacts: list[dict],
    target_environment: str | None,
    assurance_report: dict | None = None,
    target_identity: str | None = None,
) -> dict[str, Any]:
    if not binding:
        return {
            "valid": False,
            "status": "NO_BINDING",
            "integrity": "NONE",
            "reason": "No approval binding present",
            "reasons": [],
        }
    if binding.get("manager_decision") not in {"approved", "APPROVED", "APPROVED_FOR_EXECUTION"} and binding.get(
        "status"
    ) not in {"APPROVED_FOR_EXECUTION", "approved"}:
        # Pending bindings are not "valid approvals"
        if binding.get("status") == "PENDING_MANAGER_DECISION":
            return {
                "valid": False,
                "status": "PENDING_MANAGER_DECISION",
                "integrity": "PENDING",
                "reason": "Awaiting manager decision",
                "reasons": [],
            }

    current = build_approval_binding(
        job_id=str(binding.get("job_id") or ""),
        finding_id=binding.get("finding_id"),
        artifacts=artifacts,
        target_environment=target_environment,
        recommendation=binding.get("recommendation_at_bind"),
        assurance_report=assurance_report,
        target_identity=target_identity or binding.get("target_identity"),
    )
    reasons: list[str] = []
    if binding.get("artifact_hash") != current.get("artifact_hash"):
        reasons.append("ARTIFACT_CHANGED")
    if binding.get("change_hash") != current.get("change_hash"):
        reasons.append("ARTIFACT_CHANGED")
    if binding.get("plan_or_diff_hash") != current.get("plan_or_diff_hash"):
        reasons.append("PLAN_CHANGED")
    if binding.get("terraform_plan_hash") and binding.get("terraform_plan_hash") != current.get(
        "terraform_plan_hash"
    ):
        reasons.append("PLAN_CHANGED")
    if binding.get("saved_plan_sha256") and binding.get("saved_plan_sha256") != current.get(
        "saved_plan_sha256"
    ):
        reasons.append("PLAN_CHANGED")
    if binding.get("source_artifact_sha256") and binding.get("source_artifact_sha256") != current.get(
        "source_artifact_sha256"
    ):
        reasons.append("SOURCE_ARTIFACT_CHANGED")
        reasons.append("ARTIFACT_CHANGED")
    if binding.get("plan_account_id") and current.get("plan_account_id"):
        if str(binding.get("plan_account_id")) != str(current.get("plan_account_id")):
            reasons.append("ACCOUNT_MISMATCH")
            reasons.append("TARGET_CHANGED")
    if binding.get("plan_region") and current.get("plan_region"):
        if str(binding.get("plan_region")).lower() != str(current.get("plan_region")).lower():
            reasons.append("REGION_MISMATCH")
            reasons.append("TARGET_CHANGED")
    if binding.get("execution_role") and current.get("execution_role"):
        if str(binding.get("execution_role")) != str(current.get("execution_role")):
            reasons.append("EXECUTION_ROLE_CHANGED")
            reasons.append("TARGET_CHANGED")
    if binding.get("execution_identity") and current.get("execution_identity"):
        if str(binding.get("execution_identity")) != str(current.get("execution_identity")):
            reasons.append("EXECUTION_ROLE_CHANGED")
            reasons.append("TARGET_CHANGED")
    if binding.get("git_diff_hash") and binding.get("git_diff_hash") != current.get("git_diff_hash"):
        reasons.append("DIFF_CHANGED")
    if (binding.get("target_environment") or None) != (target_environment or None):
        reasons.append("ENVIRONMENT_CHANGED")
        reasons.append("TARGET_CHANGED")
    if (binding.get("target_identity") or None) != (target_identity or binding.get("target_identity") or None):
        if target_identity is not None and binding.get("target_identity") != target_identity:
            reasons.append("TARGET_CHANGED")
    if binding.get("assurance_report_hash") and binding.get("assurance_report_hash") != current.get(
        "assurance_report_hash"
    ):
        reasons.append("ASSURANCE_REPORT_CHANGED")
    if binding.get("live_state_fingerprint") and current.get("live_state_fingerprint"):
        if binding.get("live_state_fingerprint") != current.get("live_state_fingerprint"):
            reasons.append("LIVE_STATE_CHANGED")
    if binding.get("repo_fingerprint") and current.get("repo_fingerprint"):
        if binding.get("repo_fingerprint") != current.get("repo_fingerprint"):
            reasons.append("COMMIT_CHANGED")
    # Recommendation drift after approval → re-review (not always invalidate execution auth, but flag)
    rec_now = (assurance_report or {}).get("recommendation")
    if (
        binding.get("recommendation_at_bind")
        and rec_now
        and binding.get("recommendation_at_bind") != rec_now
    ):
        reasons.append("RECOMMENDATION_CHANGED")

    reasons = sorted(set(reasons))
    if reasons:
        soft = set(reasons) <= {"LIVE_STATE_CHANGED", "RECOMMENDATION_CHANGED"}
        status = "REVALIDATION_REQUIRED" if soft else "APPROVAL_INVALIDATED"
        return {
            "valid": False,
            "status": status,
            "integrity": "INVALIDATED" if status == "APPROVAL_INVALIDATED" else "REVALIDATION_REQUIRED",
            "reason": "; ".join(reasons),
            "reasons": reasons,
        }
    return {
        "valid": True,
        "status": "BINDING_VALID",
        "integrity": "VALID",
        "reason": "Hashes match approved change",
        "reasons": [],
    }


def seal_manager_approval(
    *,
    job: dict[str, Any],
    assurance_report: dict[str, Any] | None,
    decision: str,
    finding_decisions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Create sealed approval binding for an approve decision.
    Does NOT execute remediation.
    """
    artifacts = (assurance_report or {}).get("artifacts") or job.get("assurance_artifacts") or []
    target_identity = None
    if assurance_report:
        target_identity = assurance_report.get("target_identity")
        if not target_identity:
            rp = assurance_report.get("repo_fingerprint")
            if isinstance(rp, dict):
                target_identity = rp.get("commit_sha")
    binding = build_approval_binding(
        job_id=str(job.get("job_id") or ""),
        finding_id=(assurance_report or {}).get("primary_finding_id"),
        artifacts=artifacts,
        target_environment=(artifacts[0].get("target_environment") if artifacts else None),
        recommendation=(assurance_report or {}).get("recommendation"),
        assurance_report=assurance_report,
        target_identity=target_identity,
        manager_decision="approved" if decision == "approve" else decision,
    )
    if decision == "approve":
        binding["status"] = "APPROVED_FOR_EXECUTION"
        binding["execution_authorized"] = True
        binding["execution_performed"] = False
        binding["manager_decision"] = "approved"
    else:
        binding["status"] = f"MANAGER_{decision.upper()}"
        binding["execution_authorized"] = False
        binding["execution_performed"] = False
    binding["finding_decisions"] = finding_decisions or {}
    # Job-level full approval only if all findings approved
    fids = (assurance_report or {}).get("focus_finding_ids") or []
    binding["job_fully_approved"] = (
        decision == "approve" and job_fully_approved(finding_decisions, fids if fids else [binding.get("finding_id")])
    )
    return binding


def persist_binding(workspace: Path | str, job_id: str, binding: dict[str, Any]) -> Path:
    workspace = Path(workspace)
    out = workspace / "approvals"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{job_id}.json"
    path.write_text(json.dumps(binding, indent=2), encoding="utf-8")
    return path


def load_binding(workspace: Path | str, job_id: str) -> dict[str, Any] | None:
    path = Path(workspace) / "approvals" / f"{job_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def job_fully_approved(finding_decisions: dict[str, str] | None, finding_ids: list[str] | None) -> bool:
    """Job is fully approved only if every finding is approved or no_action_required."""
    if not finding_ids:
        return True
    decisions = finding_decisions or {}
    ok = {"approved", "approve", "no_action_required", "NO_ACTION_REQUIRED", "accept_risk"}
    for fid in finding_ids:
        d = str(decisions.get(fid) or "").lower()
        if d not in ok and d not in {"accepted_risk", "accept-risk"}:
            return False
    return True
