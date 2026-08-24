# change_assurance/plan_ingestion.py
# Plan-aware Change Assurance — ingest saved Terraform plans (never apply).
# Source .tf = intended config; reviewed plan = manager change decision truth.

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from change_assurance.models import now, stable_hash

VERSION = "0.1.0-plan-aware"

STATUS_PLAN_REGENERATION_REQUIRED = "PLAN_REGENERATION_REQUIRED"
REASON_SOURCE_AFTER_XCONTROL = "SOURCE_ARTIFACT_CHANGED_AFTER_CROSS_CONTROL_ANALYSIS"

RESOURCE_LABELS: dict[str, str] = {
    "aws_iam_service_linked_role": "AWS Config service-linked IAM role",
    "aws_s3_bucket": "Dedicated AWS Config S3 bucket",
    "aws_s3_bucket_public_access_block": "S3 public-access block",
    "aws_s3_bucket_server_side_encryption_configuration": "S3 server-side encryption configuration",
    "aws_s3_bucket_ownership_controls": "S3 ownership controls",
    "aws_s3_bucket_policy": "S3 bucket policy for config.amazonaws.com",
    "aws_config_configuration_recorder": "AWS Config configuration recorder",
    "aws_config_delivery_channel": "AWS Config delivery channel",
    "aws_config_configuration_recorder_status": "AWS Config recorder status / enablement",
    "aws_accessanalyzer_analyzer": "IAM Access Analyzer",
    "aws_iam_role": "IAM role",
    "aws_iam_policy": "IAM policy",
    "aws_security_group": "Security group",
    "azurerm_resource_group": "Azure resource group",
    "azurerm_storage_account": "Azure storage account",
}

CLOUDTRAIL_HINTS = re.compile(r"cloudtrail|aws-cloudtrail-logs", re.I)


def sha256_file(path: Path | str) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_plan_content_hash(plan_json: dict[str, Any]) -> str:
    """Stable hash of plan actions/addresses (ignore volatile timestamps)."""
    slim = []
    for rc in plan_json.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        slim.append(
            {
                "address": rc.get("address"),
                "type": rc.get("type"),
                "name": rc.get("name"),
                "actions": list((rc.get("change") or {}).get("actions") or []),
            }
        )
    slim.sort(key=lambda x: str(x.get("address") or ""))
    return stable_hash({"resource_changes": slim, "format_version": plan_json.get("format_version")})


def human_label(resource_type: str, address: str | None = None) -> str:
    if resource_type == "aws_iam_service_linked_role" and address and "config" in address.lower():
        return "AWS Config service-linked IAM role"
    if resource_type == "aws_s3_bucket" and address and "config" in address.lower():
        return "Dedicated AWS Config S3 bucket"
    if resource_type == "aws_s3_bucket_policy" and address and "config" in address.lower():
        return "S3 bucket policy for config.amazonaws.com"
    return RESOURCE_LABELS.get(str(resource_type or ""), str(resource_type or "resource"))


def _action_bucket(actions: list[str]) -> str:
    acts = [str(a).lower() for a in (actions or [])]
    if "delete" in acts and "create" in acts:
        return "replace"
    if "delete" in acts:
        return "destroy"
    if "update" in acts:
        return "modify"
    if "create" in acts:
        return "create"
    if "no-op" in acts or "read" in acts:
        return "noop"
    return "other"


def load_plan_json(
    plan_path: Path | str | None = None,
    *,
    plan_json: dict[str, Any] | None = None,
    working_directory: Path | str | None = None,
    terraform_bin: str | None = None,
) -> dict[str, Any]:
    """Load Terraform plan as JSON. Never apply."""
    if plan_json is not None:
        return plan_json
    if not plan_path:
        raise FileNotFoundError("No plan_path or plan_json provided")
    path = Path(plan_path)
    if not path.is_file():
        raise FileNotFoundError(f"Plan not found: {path}")
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8-sig"))

    tf = terraform_bin or shutil.which("terraform")
    if not tf:
        raise RuntimeError("terraform CLI not available to decode .tfplan")
    cwd = Path(working_directory) if working_directory else path.parent
    env = os.environ.copy()
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    proc = subprocess.run(
        [tf, "show", "-json", str(path.resolve())],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"terraform show -json failed: {(proc.stderr or proc.stdout or '')[:800]}")
    return json.loads(proc.stdout)


def normalize_terraform_plan(
    plan_json: dict[str, Any],
    *,
    finding_id: str | None = None,
    source_artifact_path: str | None = None,
    source_artifact_sha256: str | None = None,
    saved_plan_path: str | None = None,
    saved_plan_sha256: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    execution_role: str | None = None,
    execution_profile: str | None = None,
) -> dict[str, Any]:
    """Normalize terraform show -json into Change Assurance plan shape."""
    creates: list[dict[str, Any]] = []
    modifies: list[dict[str, Any]] = []
    destroys: list[dict[str, Any]] = []
    replaces: list[dict[str, Any]] = []
    addresses: list[str] = []

    for rc in plan_json.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        change = rc.get("change") or {}
        actions = list(change.get("actions") or [])
        bucket = _action_bucket(actions)
        if bucket == "noop":
            continue
        entry = {
            "address": rc.get("address"),
            "type": rc.get("type"),
            "name": rc.get("name"),
            "provider": rc.get("provider_name"),
            "actions": actions,
            "label": human_label(str(rc.get("type") or ""), str(rc.get("address") or "")),
        }
        addresses.append(str(rc.get("address") or ""))
        if bucket == "create":
            creates.append(entry)
        elif bucket == "modify":
            modifies.append(entry)
        elif bucket == "destroy":
            destroys.append(entry)
        elif bucket == "replace":
            replaces.append(entry)

    inferred_account = account_id
    inferred_region = region
    blob = json.dumps(plan_json)
    if not inferred_account:
        m = re.search(r'"account_id"\s*:\s*"(\d{12})"', blob)
        if m:
            inferred_account = m.group(1)
    if not inferred_region:
        m = re.search(r'"region"\s*:\s*"(us-[a-z0-9-]+|eu-[a-z0-9-]+|ap-[a-z0-9-]+)"', blob)
        if m:
            inferred_region = m.group(1)

    cloudtrail_touched = any(
        CLOUDTRAIL_HINTS.search(str(x.get("address") or ""))
        or "cloudtrail" in str(x.get("type") or "").lower()
        for x in creates + modifies + destroys + replaces
    )

    deps = plan_dependencies(creates + modifies + replaces + destroys, finding_id=finding_id)
    apply_unknowns = apply_time_considerations(creates)

    content_hash = normalize_plan_content_hash(plan_json)
    summary = {
        "create": len(creates),
        "modify": len(modifies),
        "replace": len(replaces),
        "destroy": len(destroys),
    }
    role_name = (execution_role or "").strip() or None
    identity = None
    if role_name and inferred_account:
        identity = f"arn:aws:iam::{inferred_account}:role/{role_name}"
    elif role_name:
        identity = role_name
    return {
        "version": VERSION,
        "mode": "saved_plan",
        "status": "REVIEWED_PLAN",
        "finding_id": finding_id,
        "source_artifact_path": source_artifact_path,
        "source_artifact_sha256": (source_artifact_sha256 or "").lower() or None,
        "saved_plan_path": saved_plan_path,
        "saved_plan_sha256": (saved_plan_sha256 or "").lower() or None,
        "plan_content_hash": content_hash,
        "plan_generated_at": plan_json.get("timestamp") or now(),
        "account_id": inferred_account,
        "region": inferred_region,
        "execution_role": role_name,
        "execution_profile": (execution_profile or "").strip() or None,
        "execution_identity": identity,
        "summary": summary,
        "destructive_actions": "PRESENT" if (destroys or replaces) else "NONE",
        "resources_to_create": creates,
        "resources_modified": modifies,
        "resources_destroyed": destroys,
        "resources_replaced": replaces,
        "resource_addresses": addresses,
        "cloudtrail_bucket_touched": cloudtrail_touched,
        "dependencies": deps,
        "apply_time_considerations": apply_unknowns,
        "execution_performed": False,
        "apply_forbidden": True,
    }


def plan_dependencies(resources: list[dict[str, Any]], *, finding_id: str | None = None) -> list[dict[str, Any]]:
    types = {str(r.get("type") or "") for r in resources}
    deps: list[dict[str, Any]] = []
    if "aws_config_configuration_recorder" in types or "aws_config_delivery_channel" in types:
        if "aws_iam_service_linked_role" in types:
            deps.append(
                {
                    "type": "config_prerequisite",
                    "id": "Config service-linked role required by recorder",
                    "relation": "required_before",
                    "confidence": "HIGH",
                }
            )
        if "aws_s3_bucket" in types or "aws_s3_bucket_policy" in types:
            deps.append(
                {
                    "type": "config_prerequisite",
                    "id": "Config bucket/policy required for delivery",
                    "relation": "required_before",
                    "confidence": "HIGH",
                }
            )
        deps.append(
            {
                "type": "config_order",
                "id": "recorder before delivery channel",
                "relation": "ordering",
                "confidence": "HIGH",
            }
        )
        if "aws_config_configuration_recorder_status" in types:
            deps.append(
                {
                    "type": "config_order",
                    "id": "delivery channel before recorder is enabled",
                    "relation": "ordering",
                    "confidence": "HIGH",
                }
            )
    if "aws_accessanalyzer_analyzer" in types:
        deps.append(
            {
                "type": "access_analyzer",
                "id": "Regional Access Analyzer create (no IAM permission mutation)",
                "relation": "additive",
                "confidence": "HIGH",
            }
        )
    if any(t.startswith("aws_iam_") for t in types) and any(
        t.startswith("aws_") and not t.startswith("aws_iam_") for t in types
    ):
        if not any(d.get("type") == "config_prerequisite" for d in deps):
            deps.append(
                {
                    "type": "iam_order",
                    "id": "IAM resources required by dependent AWS services",
                    "relation": "required_before",
                    "confidence": "MEDIUM",
                }
            )
    return deps


def apply_time_considerations(creates: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    types = {str(r.get("type") or "") for r in creates}
    if "aws_s3_bucket" in types:
        out.append("S3 bucket name must still be globally available at apply time")
    if "aws_config_configuration_recorder" in types or "aws_s3_bucket" in types:
        out.append("execution identity must have the required IAM, Config, and S3 permissions")
        out.append("AWS API/service conditions can still cause apply-time failure")
    elif types:
        out.append("execution identity must have the required cloud provider permissions")
        out.append("API/service conditions can still cause apply-time failure")
    seen: set[str] = set()
    uniq: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def risk_rationale_from_plan(plan: dict[str, Any], *, base_level: str | None = None) -> dict[str, Any]:
    summary = plan.get("summary") or {}
    creates = int(summary.get("create") or 0)
    modifies = int(summary.get("modify") or 0)
    destroys = int(summary.get("destroy") or 0)
    replaces = int(summary.get("replace") or 0)
    types = {str(r.get("type") or "") for r in (plan.get("resources_to_create") or [])}
    types |= {str(r.get("type") or "") for r in (plan.get("resources_modified") or [])}

    level = (base_level or "MEDIUM").upper()
    if destroys == 0 and replaces == 0 and creates > 0:
        if any(t.startswith("aws_config_") for t in types) or "aws_iam_service_linked_role" in types:
            level = "MEDIUM"
        elif "aws_accessanalyzer_analyzer" in types and creates <= 2:
            level = "LOW"

    if destroys > 0 or replaces > 0:
        rationale = (
            f"{level} because the reviewed plan destroys or replaces existing resources "
            f"(create={creates}, change={modifies}, replace={replaces}, destroy={destroys})."
        )
    elif creates > 0 and modifies == 0:
        parts = []
        if any(t.startswith("aws_iam_") for t in types):
            parts.append("IAM")
        if any(t.startswith("aws_s3_") for t in types):
            parts.append("S3")
        if any(t.startswith("aws_config_") for t in types):
            parts.append("AWS Config")
        created_kinds = ", ".join(parts) if parts else "cloud"
        if any(t.startswith("aws_config_") for t in types):
            rationale = (
                f"{level} because the reviewed Terraform plan creates {created_kinds} resources and enables continuous "
                "configuration recording, but modifies zero existing resources, destroys zero existing resources, "
                "does not touch the existing CloudTrail bucket, and is not expected to interrupt current workloads."
            )
        else:
            rationale = (
                f"{level} because the plan creates {creates} {created_kinds} resource(s) with "
                f"0 CHANGE and 0 DESTROY — additive control enablement, still verify permissions "
                "and naming before apply."
            )
    else:
        rationale = (
            f"{level} based on reviewed plan actions "
            f"(create={creates}, change={modifies}, destroy={destroys})."
        )

    return {
        "level": level,
        "rationale": rationale,
        "reasons": [rationale],
        "plan_summary": summary,
    }


def manager_affect_from_plan(plan: dict[str, Any]) -> dict[str, Any]:
    region = plan.get("region") or "unknown"
    summary = plan.get("summary") or {}
    creates = plan.get("resources_to_create") or []
    create_labels = [str(r.get("address") or r.get("label") or r.get("type")) for r in creates]
    create_human = [str(r.get("label") or r.get("address")) for r in creates]
    deps = [
        str(d.get("id") or d.get("type"))
        for d in (plan.get("dependencies") or [])
        if d.get("id") or d.get("type")
    ]
    unknowns = list(plan.get("apply_time_considerations") or [])
    scope = f"Regional — {region}" if region and region != "unknown" else "Regional"
    lines = [
        f"Scope: {scope}",
        "Terraform plan:",
        f"{int(summary.get('create') or 0)} CREATE",
        f"{int(summary.get('modify') or 0)} CHANGE",
        f"{int(summary.get('destroy') or 0)} DESTROY",
    ]
    if create_labels:
        lines.append("Resources to be created:")
        for i, lab in enumerate(create_labels, 1):
            human = create_human[i - 1] if i - 1 < len(create_human) else lab
            if human and human != lab:
                lines.append(f"{i}. {lab} ({human})")
            else:
                lines.append(f"{i}. {lab}")
    lines.append(
        "Existing resources modified: NONE"
        if not plan.get("resources_modified")
        else "Existing resources modified:"
    )
    for r in plan.get("resources_modified") or []:
        lines.append(f"- {r.get('label') or r.get('address')}")
    lines.append(
        "Existing resources destroyed: NONE"
        if not plan.get("resources_destroyed")
        else "Existing resources destroyed:"
    )
    for r in plan.get("resources_destroyed") or []:
        lines.append(f"- {r.get('label') or r.get('address')}")
    lines.append(
        "Existing CloudTrail bucket: NOT TOUCHED"
        if not plan.get("cloudtrail_bucket_touched")
        else "Existing CloudTrail bucket: PRESENT IN PLAN — review carefully"
    )
    lines.append("Expected downtime: None expected for existing workloads.")
    return {
        "scope": scope,
        "summary_line": (
            f"Scope: {scope}. Plan: {summary.get('create', 0)} CREATE / "
            f"{summary.get('modify', 0)} CHANGE / {summary.get('destroy', 0)} DESTROY."
        ),
        "potentially_affected": "\n".join(lines),
        "plan_create": int(summary.get("create") or 0),
        "plan_modify": int(summary.get("modify") or 0),
        "plan_destroy": int(summary.get("destroy") or 0),
        "resources_to_create": create_labels,
        "resources_modified": [
            str(r.get("label") or r.get("address")) for r in (plan.get("resources_modified") or [])
        ]
        or ["NONE"],
        "resources_destroyed": [
            str(r.get("label") or r.get("address")) for r in (plan.get("resources_destroyed") or [])
        ]
        or ["NONE"],
        "cloudtrail_bucket": "NOT TOUCHED" if not plan.get("cloudtrail_bucket_touched") else "IN PLAN",
        "expected_downtime": "None expected for existing workloads.",
        "known_dependencies": deps,
        "unknowns": unknowns,
        "detail_lines": lines,
    }


def resolve_reviewed_plan_ref(job: dict[str, Any] | None, finding_id: str | None) -> dict[str, Any] | None:
    if not job:
        return None
    fid = str(finding_id or "")
    plans = job.get("reviewed_terraform_plans") or job.get("terraform_plans") or {}
    if isinstance(plans, dict) and fid and isinstance(plans.get(fid), dict):
        ref = plans[fid]
        # Stale / superseded recovery plans are audit-only — not executable reviewed plans
        if ref.get("executable") is False or str(ref.get("status") or "") in {
            STATUS_PLAN_REGENERATION_REQUIRED,
            "PLAN_INVALIDATED",
            "SUPERSEDED",
        }:
            return None
        if ref.get("superseded") or ref.get("plan_kind") == "stale_recovery":
            return None
        return ref
    if fid and isinstance(job.get("reviewed_plan"), dict) and str(job["reviewed_plan"].get("finding_id") or "") in {
        "",
        fid,
    }:
        return job["reviewed_plan"]
    path = job.get("reviewed_plan_path") or job.get("terraform_plan_path")
    if path and (not fid or str(job.get("reviewed_plan_finding_id") or fid) == fid):
        return {"finding_id": fid, "plan_path": path}
    return None


def ingest_reviewed_plan_for_finding(
    job: dict[str, Any],
    finding_id: str,
    *,
    source_artifact_path: str | Path | None = None,
    source_artifact_sha256: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    plan_json: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Ingest reviewed plan for a finding. Never applies."""
    ref = resolve_reviewed_plan_ref(job, finding_id)
    if not ref and plan_json is None:
        return None
    plan_path = (ref or {}).get("plan_path") or (ref or {}).get("saved_plan_path")
    wd = (ref or {}).get("working_directory") or (ref or {}).get("terraform_dir")
    raw = load_plan_json(
        plan_path,
        plan_json=plan_json or (ref or {}).get("plan_json"),
        working_directory=wd,
    )
    saved_sha = None
    if plan_path and Path(plan_path).is_file():
        saved_sha = sha256_file(plan_path)

    src_path = source_artifact_path or (ref or {}).get("source_artifact_path")
    src_sha = source_artifact_sha256 or (ref or {}).get("source_artifact_sha256")
    if src_path and not src_sha and Path(src_path).is_file():
        src_sha = sha256_file(src_path)

    acct = account_id or (ref or {}).get("account_id") or job.get("aws_account_id")
    reg = region or (ref or {}).get("region") or job.get("region")
    exec_role = (
        (ref or {}).get("execution_role")
        or (ref or {}).get("intended_execution_role")
        or job.get("execution_role")
        or job.get("intended_execution_role")
    )
    exec_profile = (
        (ref or {}).get("execution_profile")
        or (ref or {}).get("aws_profile")
        or job.get("execution_profile")
        or job.get("aws_profile")
    )

    normalized = normalize_terraform_plan(
        raw,
        finding_id=finding_id,
        source_artifact_path=str(src_path) if src_path else None,
        source_artifact_sha256=src_sha,
        saved_plan_path=str(plan_path) if plan_path else None,
        saved_plan_sha256=saved_sha,
        account_id=str(acct) if acct else None,
        region=str(reg) if reg else None,
        execution_role=str(exec_role) if exec_role else None,
        execution_profile=str(exec_profile) if exec_profile else None,
    )
    normalized["manager_affect"] = manager_affect_from_plan(normalized)
    normalized["risk"] = risk_rationale_from_plan(normalized)
    return normalized


def validate_plan_artifact_binding(
    plan: dict[str, Any],
    *,
    current_artifact_sha256: str | None,
    expected_account: str | None = None,
    expected_region: str | None = None,
    expected_execution_role: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    bound_sha = (plan.get("source_artifact_sha256") or "").lower()
    cur = (current_artifact_sha256 or "").lower()
    if bound_sha and cur and bound_sha != cur:
        reasons.append("SOURCE_ARTIFACT_CHANGED")
    if expected_account and plan.get("account_id") and str(plan["account_id"]) != str(expected_account):
        reasons.append("ACCOUNT_MISMATCH")
    if expected_region and plan.get("region") and str(plan["region"]).lower() != str(expected_region).lower():
        reasons.append("REGION_MISMATCH")
    if expected_execution_role and plan.get("execution_role"):
        if str(plan["execution_role"]) != str(expected_execution_role):
            reasons.append("EXECUTION_ROLE_CHANGED")
    return {
        "valid": not reasons,
        "status": "PLAN_BINDING_VALID" if not reasons else "PLAN_INVALIDATED",
        "reasons": reasons,
    }


def supersede_reviewed_plan_for_finding(
    job: dict[str, Any],
    finding_id: str,
    *,
    reason: str = REASON_SOURCE_AFTER_XCONTROL,
    new_source_artifact_path: str | None = None,
    new_source_artifact_sha256: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    """
    Mark a bound reviewed/recovery plan as stale after the source Terraform artifact changes.
    Preserves the plan path/SHA in history; clears executable binding.
    Does not generate a new plan, approve, or apply.
    """
    fid = str(finding_id)
    plans = dict(job.get("reviewed_terraform_plans") or {})
    current = dict(plans.get(fid) or {})
    if not current:
        return {"status": STATUS_PLAN_REGENERATION_REQUIRED, "had_plan": False}

    history = list(job.get("reviewed_plan_history") or [])
    archived = dict(current)
    archived["superseded_at"] = now()
    archived["superseded_reason"] = reason
    archived["status"] = STATUS_PLAN_REGENERATION_REQUIRED
    archived["executable"] = False
    history.append(archived)
    job["reviewed_plan_history"] = history

    stale = dict(current)
    stale.update(
        {
            "status": STATUS_PLAN_REGENERATION_REQUIRED,
            "plan_review_status": STATUS_PLAN_REGENERATION_REQUIRED,
            "executable": False,
            "superseded": True,
            "superseded_reason": reason,
            "superseded_at": now(),
            "supersession_detail": detail
            or (
                "Source Terraform artifact changed after cross-control analysis. "
                "Prior recovery plan is retained for audit but is not executable."
            ),
            "prior_plan_path": current.get("plan_path") or current.get("saved_plan_path"),
            "prior_plan_sha256": current.get("plan_sha256")
            or current.get("saved_plan_sha256"),
            "prior_summary": current.get("summary"),
        }
    )
    if new_source_artifact_path:
        stale["source_artifact_path"] = str(new_source_artifact_path)
    if new_source_artifact_sha256:
        stale["source_artifact_sha256"] = str(new_source_artifact_sha256).lower()
    # Clear executable plan binding fields while keeping historical references
    stale["plan_kind"] = "stale_recovery"
    plans[fid] = stale
    job["reviewed_terraform_plans"] = plans

    fe = dict(job.get("finding_execution") or {})
    row = dict(fe.get(fid) or {})
    row["recovery_plan_bound"] = False
    row["recovery_plan_status"] = STATUS_PLAN_REGENERATION_REQUIRED
    row["recovery_plan_superseded"] = True
    row["recovery_plan_superseded_reason"] = reason
    row["prior_recovery_plan_path"] = stale.get("prior_plan_path")
    row["prior_recovery_plan_sha256"] = stale.get("prior_plan_sha256")
    row["prior_recovery_plan_summary"] = stale.get("prior_summary")
    # Keep lifecycle status
    row["status"] = row.get("status") or "RECOVERY_REQUIRED"
    row["execution_status"] = row.get("execution_status") or "PARTIAL EXECUTION — RECOVERY REQUIRED"
    fe[fid] = row
    job["finding_execution"] = fe

    decisions = dict(job.get("finding_decisions") or {})
    decisions[fid] = "pending_recovery"
    job["finding_decisions"] = decisions
    job["manager_decision"] = None
    if job.get("status") == "approved":
        job["status"] = "pending_approval"
    job["execution_authorized"] = False
    return {
        "status": STATUS_PLAN_REGENERATION_REQUIRED,
        "had_plan": True,
        "prior_plan_path": stale.get("prior_plan_path"),
        "prior_plan_sha256": stale.get("prior_plan_sha256"),
        "reason": reason,
    }
