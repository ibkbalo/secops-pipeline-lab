# change_assurance/execution_recovery.py
# Generic Terraform partial-execution + recovery plan rebinding.
# Never auto-applies. Never silently reuses prior approval after state changes.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from change_assurance.models import now
from change_assurance.plan_ingestion import ingest_reviewed_plan_for_finding, sha256_file

VERSION = "0.1.0-partial-exec"

STATUS_PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
STATUS_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
STATUS_FAILED_AFTER_PARTIAL = "FAILED_AFTER_PARTIAL_SUCCESS"

INVALIDATION_PARTIAL_EXECUTION = "PARTIAL_EXECUTION_CHANGED_STATE"

EXECUTION_LABEL_PARTIAL = "PARTIAL EXECUTION — RECOVERY REQUIRED"
PREVIOUS_EXECUTION_LABEL = "FAILED AFTER PARTIAL SUCCESS"


def _load_job(workspace: Path, job_id: str) -> dict[str, Any]:
    path = workspace / "jobs" / f"{job_id}.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _save_job(workspace: Path, job: dict[str, Any]) -> Path:
    path = workspace / "jobs" / f"{job['job_id']}.json"
    path.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    return path


def _append_audit(workspace: Path, event: dict[str, Any]) -> None:
    audit = workspace / "audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def invalidate_approval_for_partial_execution(
    binding: dict[str, Any] | None,
    *,
    reason: str = INVALIDATION_PARTIAL_EXECUTION,
    detail: str | None = None,
) -> dict[str, Any]:
    """Mark a sealed approval invalid after infrastructure state changed mid-apply."""
    binding = dict(binding or {})
    binding["status"] = "APPROVAL_INVALIDATED"
    binding["integrity"] = "INVALIDATED"
    binding["valid"] = False
    binding["execution_authorized"] = False
    binding["manager_decision"] = None
    binding["invalidation_reasons"] = sorted(
        set(list(binding.get("invalidation_reasons") or []) + [reason])
    )
    binding["invalidated_at"] = now()
    binding["invalidation_detail"] = detail or (
        "Infrastructure state changed during a human-triggered Terraform apply. "
        "Prior approval no longer authorizes execution; review the recovery plan."
    )
    binding["reason"] = reason
    binding["reasons"] = list(binding["invalidation_reasons"])
    return binding


def record_partial_terraform_execution(
    workspace: Path | str,
    job_id: str,
    finding_id: str,
    *,
    approved_plan_path: str | Path,
    approved_plan_sha256: str,
    succeeded_resources: list[str],
    failure_reason: str,
    failed_action: str | None = None,
    destroyed_resources: list[str] | None = None,
    modified_resources: list[str] | None = None,
    execution_timestamp: str | None = None,
    human_triggered: bool = True,
    platform_auto_execution: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    """
    Record a real Terraform apply that partially succeeded then failed.
    Invalidates prior approval. Does NOT apply, retry, or rollback.
    """
    workspace = Path(workspace)
    job = _load_job(workspace, job_id)
    plan_path = Path(approved_plan_path)
    disk_sha = sha256_file(plan_path).lower() if plan_path.is_file() else None
    expected = approved_plan_sha256.lower()
    if disk_sha and disk_sha != expected:
        raise ValueError(
            f"Approved plan SHA mismatch on disk: expected {expected}, got {disk_sha}"
        )

    attempt = {
        "version": VERSION,
        "finding_id": finding_id,
        "result": STATUS_PARTIAL_EXECUTION,
        "execution_result": STATUS_FAILED_AFTER_PARTIAL,
        "approved_plan_path": str(plan_path),
        "approved_plan_sha256": expected,
        "succeeded_resources": list(succeeded_resources),
        "destroyed_resources": list(destroyed_resources or []),
        "modified_resources": list(modified_resources or []),
        "failure_reason": failure_reason,
        "failed_action": failed_action,
        "recovery_required": True,
        "human_triggered_execution": bool(human_triggered),
        "platform_auto_execution": bool(platform_auto_execution),
        "automatic_rollback": False,
        "automatic_retry": False,
        "automatic_apply": False,
        "case_resolved": False,
        "executed_at": execution_timestamp or now(),
        "recorded_at": now(),
        "note": note,
    }

    attempts = list(job.get("execution_attempts") or [])
    attempts.append(attempt)
    job["execution_attempts"] = attempts

    finding_exec = dict(job.get("finding_execution") or {})
    finding_exec[finding_id] = {
        "status": STATUS_RECOVERY_REQUIRED,
        "execution_status": EXECUTION_LABEL_PARTIAL,
        "previous_execution": PREVIOUS_EXECUTION_LABEL,
        "latest_attempt": attempt,
        "succeeded_resources": list(succeeded_resources),
        "remaining_action_required": True,
        "prior_approval_valid": False,
        "recovery_plan_bound": False,
    }
    job["finding_execution"] = finding_exec

    # Invalidate sealed approval — must not authorize recovery
    old_binding = job.get("approval_binding")
    invalidated = invalidate_approval_for_partial_execution(
        old_binding if isinstance(old_binding, dict) else None,
        reason=INVALIDATION_PARTIAL_EXECUTION,
        detail=(
            f"Partial Terraform execution for {finding_id}: created "
            f"{len(succeeded_resources)} resource(s), then failed "
            f"({failed_action or failure_reason}). Recovery plan required."
        ),
    )
    # Preserve reference to the plan that was actually applied
    invalidated["invalidated_saved_plan_sha256"] = expected
    invalidated["invalidated_saved_plan_path"] = str(plan_path)
    job["approval_binding"] = invalidated
    job["approval_status"] = "APPROVAL_INVALIDATED"
    job["execution_authorized"] = False
    job["execution_performed"] = True  # attempted — not "NOT PERFORMED"
    job["apply_status"] = "partial_failed"
    job["apply_note"] = (
        f"PARTIAL_EXECUTION for {finding_id}: succeeded={succeeded_resources}; "
        f"failure={failed_action or failure_reason}. Recovery required."
    )

    # Reset this finding's decision to pending; keep siblings intact
    decisions = dict(job.get("finding_decisions") or {})
    decisions[finding_id] = "pending_recovery"
    job["finding_decisions"] = decisions
    job["manager_decision"] = None
    job["status"] = "pending_approval"
    job["updated_at"] = now()

    # Persist invalidated approval file
    try:
        from change_assurance import approval_integrity as ca_appr

        ca_appr.persist_binding(workspace, job_id, invalidated)
    except Exception:
        pass

    _append_audit(
        workspace,
        {
            "event": "terraform_partial_execution",
            "job_id": job_id,
            "finding_id": finding_id,
            "attempt": attempt,
            "approval_invalidation": INVALIDATION_PARTIAL_EXECUTION,
            "at": now(),
        },
    )
    _save_job(workspace, job)
    # Persist cross-job remediation lifecycle (scan jobs must not erase this)
    try:
        from change_assurance.remediation_ledger import upsert_execution_state

        acct = str(job.get("aws_account_id") or "")
        region = str(job.get("region") or "")
        if acct and region:
            upsert_execution_state(
                workspace,
                provider="aws",
                account_id=acct,
                region=region,
                control_id=finding_id,
                remediation_state=STATUS_RECOVERY_REQUIRED,
                finding_state="OPEN",
                attempt=attempt,
                finding_execution=(job.get("finding_execution") or {}).get(finding_id),
                approval={
                    "status": "APPROVAL_INVALIDATED",
                    "invalidation_reasons": [INVALIDATION_PARTIAL_EXECUTION],
                    "invalidated_saved_plan_sha256": expected,
                    "manager_decision": None,
                    "execution_authorized": False,
                },
                prerequisite_decision=(job.get("prerequisite_decisions") or {}).get(finding_id),
                prerequisite_resources={
                    addr: {
                        "status": "EXISTS",
                        "evidence_quality": "TRUSTED_EXECUTION_HISTORY",
                        "terraform_address": addr,
                    }
                    for addr in succeeded_resources
                },
                source_artifact={
                    "path": ((job.get("prerequisite_resolutions") or {}).get(finding_id) or {}).get(
                        "artifact_path"
                    ),
                    "sha256": ((job.get("prerequisite_resolutions") or {}).get(finding_id) or {}).get(
                        "artifact_sha256"
                    ),
                },
                job_id=job_id,
            )
    except Exception:
        pass
    return {
        "status": STATUS_RECOVERY_REQUIRED,
        "attempt": attempt,
        "approval_status": "APPROVAL_INVALIDATED",
        "invalidation_reason": INVALIDATION_PARTIAL_EXECUTION,
        "manager_decision": "PENDING",
        "execution_label": EXECUTION_LABEL_PARTIAL,
        "case_resolved": False,
        "auto_apply": False,
        "auto_retry": False,
        "auto_rollback": False,
    }


def bind_recovery_terraform_plan(
    workspace: Path | str,
    job_id: str,
    finding_id: str,
    *,
    recovery_plan_path: str | Path,
    expected_plan_sha256: str,
    source_artifact_path: str | Path | None = None,
    source_artifact_sha256: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    execution_role: str | None = None,
    execution_profile: str | None = None,
    expected_create: int | None = None,
) -> dict[str, Any]:
    """
    Bind a NEW recovery plan after partial execution. Does not approve or apply.
    Prior approval remains invalidated; manager must re-approve this plan.
    """
    workspace = Path(workspace)
    job = _load_job(workspace, job_id)
    plan_path = Path(recovery_plan_path)
    if not plan_path.is_file():
        raise FileNotFoundError(f"Recovery plan missing: {plan_path}")
    disk_sha = sha256_file(plan_path).lower()
    expected = expected_plan_sha256.lower()
    if disk_sha != expected:
        raise ValueError(f"Recovery plan SHA mismatch: expected {expected}, got {disk_sha}")

    plans = dict(job.get("reviewed_terraform_plans") or {})
    previous = dict(plans.get(finding_id) or {})
    # Preserve prior plan binding in immutable history (do not rewrite past entries)
    if previous:
        history = list(job.get("reviewed_plan_history") or [])
        prev_sha = (
            previous.get("plan_sha256")
            or previous.get("saved_plan_sha256")
            or previous.get("prior_plan_sha256")
        )
        already = {
            (h.get("plan_sha256") or h.get("saved_plan_sha256") or h.get("prior_plan_sha256"))
            for h in history
            if isinstance(h, dict)
        }
        if prev_sha and prev_sha not in already:
            archived = dict(previous)
            archived.setdefault(
                "status",
                previous.get("status") or "SUPERSEDED",
            )
            archived["archived_at"] = now()
            archived["executable"] = False
            history.append(archived)
            job["reviewed_plan_history"] = history

    ref = {
        "finding_id": finding_id,
        "plan_path": str(plan_path),
        "saved_plan_path": str(plan_path),
        "working_directory": str(plan_path.parent),
        "source_artifact_path": str(source_artifact_path) if source_artifact_path else None,
        "source_artifact_sha256": (source_artifact_sha256 or "").lower() or None,
        "account_id": account_id or job.get("aws_account_id"),
        "region": region or job.get("region"),
        "execution_role": execution_role or job.get("execution_role"),
        "execution_profile": execution_profile or job.get("execution_profile"),
        "execution_identity": None,
        "plan_kind": "recovery",
        "status": "CURRENT",
        "plan_review_status": "REVIEW_REQUIRED",
        "executable": True,
        "superseded": False,
    }
    if ref["execution_role"] and ref["account_id"]:
        ref["execution_identity"] = (
            f"arn:aws:iam::{ref['account_id']}:role/{ref['execution_role']}"
        )

    plans[finding_id] = ref
    job["reviewed_terraform_plans"] = plans

    reviewed = ingest_reviewed_plan_for_finding(
        job,
        finding_id,
        source_artifact_path=source_artifact_path,
        source_artifact_sha256=source_artifact_sha256,
        account_id=ref["account_id"],
        region=ref["region"],
    )
    if not reviewed:
        raise RuntimeError("Failed to ingest recovery plan")
    summary = reviewed.get("summary") or {}
    if expected_create is not None and int(summary.get("create") or 0) != int(expected_create):
        raise ValueError(
            f"Recovery plan create count {summary.get('create')} != expected {expected_create}"
        )
    if int(summary.get("modify") or 0) != 0 or int(summary.get("destroy") or 0) != 0:
        # Allow but flag — still bind; Manager Mode will show actual counts
        pass

    # Attach recovery metadata onto finding_execution (preserve prior_* / succeeded)
    finding_exec = dict(job.get("finding_execution") or {})
    fe = dict(finding_exec.get(finding_id) or {})
    # Immediate prior = plan being replaced (especially a previous recovery plan).
    # Do not keep an older prior_* when superseding recovery → recovery.
    prev_sha = previous.get("plan_sha256") or previous.get("saved_plan_sha256")
    if previous.get("plan_kind") == "recovery" and prev_sha:
        prior_path = previous.get("plan_path") or previous.get("saved_plan_path")
        prior_sha = prev_sha
        prior_summary = previous.get("summary")
    else:
        prior_path = fe.get("prior_recovery_plan_path") or previous.get("prior_plan_path") or previous.get(
            "plan_path"
        )
        prior_sha = fe.get("prior_recovery_plan_sha256") or previous.get("prior_plan_sha256") or previous.get(
            "plan_sha256"
        ) or previous.get("saved_plan_sha256")
        prior_summary = fe.get("prior_recovery_plan_summary") or previous.get("prior_summary") or previous.get(
            "summary"
        )
    fe.update(
        {
            "status": STATUS_RECOVERY_REQUIRED,
            "execution_status": EXECUTION_LABEL_PARTIAL,
            "previous_execution": PREVIOUS_EXECUTION_LABEL,
            "recovery_plan_bound": True,
            "recovery_plan_path": str(plan_path),
            "recovery_plan_sha256": disk_sha,
            "recovery_plan_summary": summary,
            "recovery_resources": list(reviewed.get("resource_addresses") or []),
            "recovery_plan_status": "CURRENT",
            "recovery_plan_review_status": "REVIEW_REQUIRED",
            "recovery_plan_superseded": False,
            "prior_approval_valid": False,
            "manager_decision_required": True,
            "cross_control_versioning_addressed": any(
                "aws_s3_bucket_versioning" in str(a)
                for a in (reviewed.get("resource_addresses") or [])
            ),
        }
    )
    if prior_path:
        fe["prior_recovery_plan_path"] = prior_path
    if prior_sha:
        fe["prior_recovery_plan_sha256"] = prior_sha
        fe["prior_recovery_plan_superseded"] = True
        fe["prior_recovery_plan_superseded_reason"] = fe.get(
            "recovery_plan_superseded_reason"
        ) or previous.get("superseded_reason") or "SOURCE_ARTIFACT_CHANGED_AFTER_CROSS_CONTROL_ANALYSIS"
    if prior_summary:
        fe["prior_recovery_plan_summary"] = prior_summary
    # Clear regeneration-required flag once a fresh plan is bound
    if fe.get("recovery_plan_superseded_reason") and fe.get("recovery_plan_status") == "CURRENT":
        fe.pop("recovery_plan_superseded_reason", None)
    # Link recovery SHA onto latest attempt
    attempts = list(job.get("execution_attempts") or [])
    if attempts:
        latest = dict(attempts[-1])
        if str(latest.get("finding_id") or "") == finding_id:
            latest["recovery_plan_path"] = str(plan_path)
            latest["recovery_plan_sha256"] = disk_sha
            latest["recovery_required"] = True
            attempts[-1] = latest
            job["execution_attempts"] = attempts
            fe["latest_attempt"] = latest
    finding_exec[finding_id] = fe
    job["finding_execution"] = finding_exec

    # Enrich bound plan with normalized hashes/summary from ingest
    ref["summary"] = summary
    ref["plan_sha256"] = disk_sha
    ref["saved_plan_sha256"] = disk_sha
    ref["plan_content_hash"] = reviewed.get("plan_content_hash")
    ref["resource_addresses"] = reviewed.get("resource_addresses")
    plans[finding_id] = ref
    job["reviewed_terraform_plans"] = plans

    # Ensure approval stays invalid / pending for recovery plan
    binding = job.get("approval_binding")
    if isinstance(binding, dict):
        binding = invalidate_approval_for_partial_execution(
            binding,
            reason=INVALIDATION_PARTIAL_EXECUTION,
            detail="Recovery plan bound; previous approval does not cover this plan.",
        )
        binding["recovery_plan_sha256"] = disk_sha
        binding["recovery_plan_path"] = str(plan_path)
        job["approval_binding"] = binding
        try:
            from change_assurance import approval_integrity as ca_appr

            ca_appr.persist_binding(workspace, job_id, binding)
        except Exception:
            pass

    decisions = dict(job.get("finding_decisions") or {})
    decisions[finding_id] = "pending_recovery"
    job["finding_decisions"] = decisions
    job["manager_decision"] = None
    job["status"] = "pending_approval"
    job["execution_authorized"] = False
    job["updated_at"] = now()

    _append_audit(
        workspace,
        {
            "event": "terraform_recovery_plan_bound",
            "job_id": job_id,
            "finding_id": finding_id,
            "recovery_plan_path": str(plan_path),
            "recovery_plan_sha256": disk_sha,
            "summary": summary,
            "at": now(),
        },
    )
    _save_job(workspace, job)
    try:
        from change_assurance.remediation_ledger import upsert_execution_state

        acct = str(job.get("aws_account_id") or ref.get("account_id") or "")
        region = str(job.get("region") or ref.get("region") or "")
        if acct and region:
            upsert_execution_state(
                workspace,
                provider="aws",
                account_id=acct,
                region=region,
                control_id=finding_id,
                remediation_state=STATUS_RECOVERY_REQUIRED,
                finding_state="OPEN",
                finding_execution=(job.get("finding_execution") or {}).get(finding_id),
                reviewed_plan={
                    **ref,
                    "summary": summary,
                    "plan_sha256": disk_sha,
                    "resource_addresses": reviewed.get("resource_addresses"),
                },
                approval={
                    "status": "APPROVAL_INVALIDATED",
                    "invalidation_reasons": [INVALIDATION_PARTIAL_EXECUTION],
                    "manager_decision": None,
                    "execution_authorized": False,
                },
                prerequisite_decision=(job.get("prerequisite_decisions") or {}).get(finding_id),
                source_artifact={
                    "path": ref.get("source_artifact_path"),
                    "sha256": ref.get("source_artifact_sha256"),
                },
                job_id=job_id,
            )
    except Exception:
        pass
    return {
        "status": STATUS_RECOVERY_REQUIRED,
        "recovery_plan_path": str(plan_path),
        "recovery_plan_sha256": disk_sha,
        "summary": summary,
        "resource_addresses": reviewed.get("resource_addresses"),
        "reviewed_plan": reviewed,
        "manager_decision": "PENDING",
        "prior_approval_valid": False,
        "execution_label": EXECUTION_LABEL_PARTIAL,
    }


def finding_execution_view(job: dict[str, Any] | None, finding_id: str | None) -> dict[str, Any] | None:
    """Manager Mode helper — per-finding execution/recovery snapshot."""
    if not job or not finding_id:
        return None
    fe = (job.get("finding_execution") or {}).get(str(finding_id))
    if not isinstance(fe, dict):
        return None
    return fe
