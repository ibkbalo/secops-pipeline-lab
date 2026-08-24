# change_assurance/remediation_ledger.py
# Persistent cross-job remediation lifecycle.
# Scan jobs are snapshots; remediation state survives job supersession.
# Never auto-applies Terraform / never modifies AWS.

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from change_assurance.models import now

VERSION = "0.1.0-lifecycle"

STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
STATUS_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
STATUS_FAILED = "FAILED"
STATUS_SUCCEEDED = "SUCCEEDED"

INVALIDATION_PARTIAL = "PARTIAL_EXECUTION_CHANGED_STATE"

EXECUTION_LABEL_PARTIAL = "PARTIAL EXECUTION — RECOVERY REQUIRED"
PREVIOUS_EXECUTION_LABEL = "FAILED AFTER PARTIAL SUCCESS"


def lifecycle_key(
    *,
    provider: str,
    account_id: str,
    region: str,
    control_id: str,
) -> str:
    """Canonical environment/control identity for remediation continuity."""
    return "|".join(
        [
            str(provider or "unknown").strip().lower(),
            str(account_id or "unknown").strip(),
            str(region or "unknown").strip().lower(),
            str(control_id or "unknown").strip().upper(),
        ]
    )


def key_to_filename(key: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", key)
    return f"{safe}.json"


def ledger_dir(workspace: Path | str) -> Path:
    d = Path(workspace) / "remediation_ledger"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_record(workspace: Path | str, key: str) -> dict[str, Any] | None:
    path = ledger_dir(workspace) / key_to_filename(key)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_record(workspace: Path | str, record: dict[str, Any]) -> Path:
    key = str(record.get("lifecycle_key") or "")
    if not key:
        raise ValueError("record.lifecycle_key required")
    record = dict(record)
    record["version"] = VERSION
    record["updated_at"] = now()
    path = ledger_dir(workspace) / key_to_filename(key)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    # Maintain index
    idx_path = ledger_dir(workspace) / "index.json"
    idx = {}
    if idx_path.is_file():
        try:
            idx = json.loads(idx_path.read_text(encoding="utf-8-sig"))
        except Exception:
            idx = {}
    by_key = dict(idx.get("by_lifecycle_key") or {})
    by_key[key] = {
        "path": str(path),
        "control_id": record.get("control_id"),
        "remediation_state": record.get("remediation_state"),
        "updated_at": record.get("updated_at"),
        "active_job_id": record.get("active_job_id"),
    }
    idx["by_lifecycle_key"] = by_key
    idx["updated_at"] = now()
    idx["version"] = VERSION
    idx_path.write_text(json.dumps(idx, indent=2) + "\n", encoding="utf-8")
    return path


def infer_provider(job: dict[str, Any] | None, finding: dict[str, Any] | None = None) -> str:
    role = str((job or {}).get("role") or "").lower()
    fid = str((finding or {}).get("id") or "").upper()
    if role in {"cloud", "aws"} or fid.startswith("CLOUD-") or fid.startswith("AWS-"):
        return "aws"
    if role in {"azure"} or fid.startswith("AZURE-"):
        return "azure"
    if role in {"devsecops"}:
        return "devsecops"
    if role in {"security-engineer", "security"}:
        return "security"
    if role in {"ai-security", "ai"}:
        return "ai-security"
    return role or "unknown"


def resolve_env_from_job(job: dict[str, Any] | None) -> tuple[str | None, str | None]:
    job = job or {}
    account = (
        job.get("aws_account_id")
        or job.get("account_id")
        or (job.get("approval_binding") or {}).get("plan_account_id")
        or (job.get("approval_binding") or {}).get("target_environment")
    )
    region = (
        job.get("region")
        or (job.get("approval_binding") or {}).get("plan_region")
        or ((job.get("reviewed_terraform_plans") or {}).get("CLOUD-LOG-002") or {}).get("region")
    )
    # Prefer reviewed plan env for any control
    for _fid, ref in (job.get("reviewed_terraform_plans") or {}).items():
        if isinstance(ref, dict):
            account = account or ref.get("account_id")
            region = region or ref.get("region")
    return (str(account) if account else None, str(region) if region else None)


def key_for_control(
    job: dict[str, Any] | None,
    control_id: str,
    *,
    account_id: str | None = None,
    region: str | None = None,
    provider: str | None = None,
) -> str | None:
    acct, reg = resolve_env_from_job(job)
    acct = account_id or acct
    reg = region or reg
    if not acct or not reg or not control_id:
        return None
    return lifecycle_key(
        provider=provider or infer_provider(job, {"id": control_id}),
        account_id=acct,
        region=reg,
        control_id=control_id,
    )


def empty_record(
    *,
    key: str,
    provider: str,
    account_id: str,
    region: str,
    control_id: str,
) -> dict[str, Any]:
    return {
        "version": VERSION,
        "lifecycle_key": key,
        "provider": provider,
        "account_id": str(account_id),
        "region": str(region),
        "control_id": str(control_id).upper(),
        "finding_state": "OPEN",
        "remediation_state": STATUS_NOT_STARTED,
        "prerequisite_decision": None,
        "prerequisite_resources": {},
        "execution_attempts": [],
        "finding_execution": None,
        "reviewed_plan": None,
        "approval": None,
        "source_artifact": None,
        "source_jobs": [],
        "active_job_id": None,
        "created_at": now(),
        "updated_at": now(),
        "auto_apply_forbidden": True,
    }


def upsert_execution_state(
    workspace: Path | str,
    *,
    provider: str,
    account_id: str,
    region: str,
    control_id: str,
    remediation_state: str,
    finding_state: str = "OPEN",
    attempt: dict[str, Any] | None = None,
    finding_execution: dict[str, Any] | None = None,
    reviewed_plan: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    prerequisite_decision: dict[str, Any] | None = None,
    prerequisite_resources: dict[str, Any] | None = None,
    source_artifact: dict[str, Any] | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    key = lifecycle_key(
        provider=provider, account_id=account_id, region=region, control_id=control_id
    )
    rec = load_record(workspace, key) or empty_record(
        key=key,
        provider=provider,
        account_id=account_id,
        region=region,
        control_id=control_id,
    )
    rec["finding_state"] = finding_state
    rec["remediation_state"] = remediation_state
    if attempt:
        attempts = list(rec.get("execution_attempts") or [])
        attempts.append(attempt)
        rec["execution_attempts"] = attempts
    if finding_execution is not None:
        rec["finding_execution"] = finding_execution
    if reviewed_plan is not None:
        rec["reviewed_plan"] = reviewed_plan
    if approval is not None:
        rec["approval"] = approval
    if prerequisite_decision is not None:
        rec["prerequisite_decision"] = prerequisite_decision
    if prerequisite_resources:
        pr = dict(rec.get("prerequisite_resources") or {})
        pr.update(prerequisite_resources)
        rec["prerequisite_resources"] = pr
    if source_artifact is not None:
        rec["source_artifact"] = source_artifact
    if job_id:
        jobs = list(rec.get("source_jobs") or [])
        if job_id not in jobs:
            jobs.append(job_id)
        rec["source_jobs"] = jobs
        rec["active_job_id"] = job_id
    save_record(workspace, rec)
    return rec


def discover_aws_config_prerequisites(
    *,
    account_id: str,
    region: str,
    profile: str | None = None,
    expected_bucket: str | None = None,
) -> dict[str, Any]:
    """
    Read-only AWS discovery for Config SLR + dedicated delivery bucket.
    Never creates/modifies resources.
    """
    bucket = expected_bucket or f"sentinel-aws-config-{account_id}-{region}"
    role_name = "AWSServiceRoleForConfig"
    role_arn = f"arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/{role_name}"
    out: dict[str, Any] = {
        "role": {
            "expected_arn": role_arn,
            "status": "UNKNOWN",
            "evidence_quality": "UNAVAILABLE",
            "evidence_source": None,
        },
        "bucket": {
            "expected_name": bucket,
            "status": "UNKNOWN",
            "evidence_quality": "UNAVAILABLE",
            "evidence_source": None,
        },
        "checked_at": now(),
        "read_only": True,
        "aws_modified": False,
    }
    try:
        import boto3
        from botocore.exceptions import ClientError, BotoCoreError

        session_kwargs: dict[str, Any] = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        session = boto3.Session(**session_kwargs)
        iam = session.client("iam")
        s3 = session.client("s3")
        try:
            resp = iam.get_role(RoleName=role_name)
            arn = (resp.get("Role") or {}).get("Arn") or role_arn
            out["role"] = {
                "expected_arn": role_arn,
                "observed_arn": arn,
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "evidence_source": "iam.get_role",
                "terraform_address": "aws_iam_service_linked_role.config",
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchEntity", "NoSuchEntityException"}:
                out["role"]["status"] = "MISSING"
                out["role"]["evidence_quality"] = "DIRECT"
                out["role"]["evidence_source"] = "iam.get_role"
            else:
                out["role"]["status"] = "UNKNOWN"
                out["role"]["evidence_quality"] = "ERROR"
                out["role"]["error"] = f"{code}: {e.response.get('Error', {}).get('Message', '')[:200]}"
        except BotoCoreError as e:
            out["role"]["status"] = "UNKNOWN"
            out["role"]["evidence_quality"] = "ERROR"
            out["role"]["error"] = str(e)[:200]

        try:
            s3.head_bucket(Bucket=bucket)
            out["bucket"] = {
                "expected_name": bucket,
                "observed_name": bucket,
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "evidence_source": "s3.head_bucket",
                "terraform_address": "aws_s3_bucket.config",
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            http = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in {"404", "NoSuchBucket"} or http == 404:
                out["bucket"]["status"] = "MISSING"
                out["bucket"]["evidence_quality"] = "DIRECT"
                out["bucket"]["evidence_source"] = "s3.head_bucket"
            elif http == 403 or code in {"AccessDenied", "403"}:
                out["bucket"]["status"] = "UNKNOWN"
                out["bucket"]["evidence_quality"] = "INSUFFICIENT"
                out["bucket"]["error"] = "AccessDenied on head-bucket"
            else:
                out["bucket"]["status"] = "UNKNOWN"
                out["bucket"]["evidence_quality"] = "ERROR"
                out["bucket"]["error"] = f"{code}"
        except BotoCoreError as e:
            out["bucket"]["status"] = "UNKNOWN"
            out["bucket"]["evidence_quality"] = "ERROR"
            out["bucket"]["error"] = str(e)[:200]
    except Exception as e:
        out["role"]["error"] = str(e)[:200]
        out["bucket"]["error"] = str(e)[:200]
    return out


def merge_prerequisite_evidence(
    record: dict[str, Any],
    discovery: dict[str, Any] | None,
    *,
    trusted_succeeded: list[str] | None = None,
) -> dict[str, Any]:
    """
    Combine DIRECT AWS discovery with trusted execution history.
    Do not mark MISSING when trusted history says created unless DIRECT proves removed.
    """
    trusted = set(trusted_succeeded or [])
    fe = record.get("finding_execution") or {}
    for r in fe.get("succeeded_resources") or []:
        trusted.add(str(r))
    for att in record.get("execution_attempts") or []:
        for r in att.get("succeeded_resources") or []:
            trusted.add(str(r))

    pr = dict(record.get("prerequisite_resources") or {})
    disc = discovery or {}

    role_d = disc.get("role") or {}
    bucket_d = disc.get("bucket") or {}

    def _resolve(addr: str, disc_row: dict[str, Any], name_or_arn: str) -> dict[str, Any]:
        status = str(disc_row.get("status") or "UNKNOWN")
        quality = str(disc_row.get("evidence_quality") or "UNAVAILABLE")
        if status == "EXISTS":
            return {
                "status": "EXISTS",
                "evidence_quality": quality or "DIRECT",
                "evidence_source": disc_row.get("evidence_source"),
                "identity": disc_row.get("observed_arn") or disc_row.get("observed_name") or name_or_arn,
                "terraform_address": addr,
            }
        if status == "MISSING":
            # DIRECT proof of absence overrides history
            return {
                "status": "MISSING",
                "evidence_quality": "DIRECT",
                "evidence_source": disc_row.get("evidence_source"),
                "identity": name_or_arn,
                "terraform_address": addr,
                "note": "Direct discovery reports resource absent",
            }
        # UNKNOWN / ERROR — fall back to trusted execution history
        if addr in trusted:
            return {
                "status": "EXISTS",
                "evidence_quality": "TRUSTED_EXECUTION_HISTORY",
                "evidence_source": "remediation_ledger.execution_attempts",
                "identity": name_or_arn,
                "terraform_address": addr,
                "note": (
                    "Direct discovery unavailable; trusted partial-execution history "
                    "recorded successful create"
                ),
            }
        return {
            "status": "UNKNOWN",
            "evidence_quality": quality or "UNAVAILABLE",
            "evidence_source": disc_row.get("evidence_source"),
            "identity": name_or_arn,
            "terraform_address": addr,
            "error": disc_row.get("error"),
        }

    account = str(record.get("account_id") or "")
    region = str(record.get("region") or "")
    role_arn = (
        role_d.get("expected_arn")
        or f"arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    )
    bucket = bucket_d.get("expected_name") or f"sentinel-aws-config-{account}-{region}"

    pr["aws_iam_service_linked_role.config"] = _resolve(
        "aws_iam_service_linked_role.config", role_d, role_arn
    )
    pr["aws_s3_bucket.config"] = _resolve("aws_s3_bucket.config", bucket_d, bucket)
    record["prerequisite_resources"] = pr
    record["prerequisite_discovery"] = disc
    return record


def seed_from_job(
    workspace: Path | str,
    job: dict[str, Any],
    control_id: str,
    *,
    account_id: str | None = None,
    region: str | None = None,
    provider: str | None = None,
    run_discovery: bool = True,
) -> dict[str, Any] | None:
    """Promote job-scoped execution/recovery state into the persistent ledger."""
    acct, reg = resolve_env_from_job(job)
    acct = account_id or acct
    reg = region or reg
    if not acct or not reg:
        return None
    prov = provider or infer_provider(job, {"id": control_id})
    key = lifecycle_key(provider=prov, account_id=acct, region=reg, control_id=control_id)
    fe = (job.get("finding_execution") or {}).get(control_id)
    attempts = [
        a for a in (job.get("execution_attempts") or []) if str(a.get("finding_id") or "") == control_id
    ]
    plan_ref = (job.get("reviewed_terraform_plans") or {}).get(control_id)
    decision = (job.get("prerequisite_decisions") or {}).get(control_id)
    resolution = (job.get("prerequisite_resolutions") or {}).get(control_id)
    binding = job.get("approval_binding") if isinstance(job.get("approval_binding"), dict) else None

    rem_state = STATUS_NOT_STARTED
    if isinstance(fe, dict):
        rem_state = str(fe.get("status") or STATUS_RECOVERY_REQUIRED)
    elif attempts:
        rem_state = STATUS_PARTIAL_EXECUTION

    source_artifact = None
    if isinstance(plan_ref, dict):
        source_artifact = {
            "path": plan_ref.get("source_artifact_path"),
            "sha256": plan_ref.get("source_artifact_sha256"),
        }
    elif isinstance(resolution, dict):
        source_artifact = {
            "path": resolution.get("artifact_path"),
            "sha256": resolution.get("artifact_sha256"),
        }

    reviewed_plan = None
    if isinstance(plan_ref, dict):
        reviewed_plan = dict(plan_ref)
        if isinstance(fe, dict) and fe.get("recovery_plan_summary"):
            reviewed_plan["summary"] = fe.get("recovery_plan_summary")
            reviewed_plan["plan_sha256"] = fe.get("recovery_plan_sha256")
            reviewed_plan["resource_addresses"] = fe.get("recovery_resources")

    approval = None
    if binding:
        approval = {
            "status": binding.get("status"),
            "invalidation_reasons": binding.get("invalidation_reasons") or binding.get("reasons"),
            "invalidated_saved_plan_sha256": binding.get("invalidated_saved_plan_sha256")
            or binding.get("saved_plan_sha256"),
            "manager_decision": binding.get("manager_decision"),
            "execution_authorized": binding.get("execution_authorized"),
        }

    rec = upsert_execution_state(
        workspace,
        provider=prov,
        account_id=acct,
        region=reg,
        control_id=control_id,
        remediation_state=rem_state,
        finding_state="OPEN",
        attempt=None,
        finding_execution=fe,
        reviewed_plan=reviewed_plan,
        approval=approval,
        prerequisite_decision=decision,
        source_artifact=source_artifact,
        job_id=str(job.get("job_id") or "") or None,
    )
    # Attach all attempts (replace if seeding)
    if attempts:
        rec["execution_attempts"] = attempts
    if resolution:
        rec["prerequisite_resolution"] = {
            "choice": resolution.get("choice") or (decision or {}).get("choice"),
            "status": resolution.get("status"),
            "resources": resolution.get("resources"),
            "artifact_path": resolution.get("artifact_path"),
            "artifact_sha256": resolution.get("artifact_sha256"),
        }

    trusted = []
    if isinstance(fe, dict):
        trusted = list(fe.get("succeeded_resources") or [])
    discovery = None
    if run_discovery and prov == "aws" and rem_state in {
        STATUS_PARTIAL_EXECUTION,
        STATUS_RECOVERY_REQUIRED,
        STATUS_PARTIAL_EXECUTION,
    }:
        profile = job.get("execution_profile") or "sentinel-remediation"
        discovery = discover_aws_config_prerequisites(
            account_id=acct,
            region=reg,
            profile=str(profile) if profile else None,
        )
    rec = merge_prerequisite_evidence(rec, discovery, trusted_succeeded=trusted)
    save_record(workspace, rec)
    return rec


def _apply_dedicated_artifacts(workspace: Path, job: dict[str, Any], control_id: str, record: dict[str, Any]) -> None:
    """Re-resolve CREATE_DEDICATED artifacts into the job kit so placeholders cannot regress."""
    try:
        from change_assurance.prerequisite_resolution import (
            CHOICE_CREATE_DEDICATED,
            apply_decision_and_regenerate,
            normalize_choice,
            record_decision,
        )

        choice = normalize_choice((record.get("prerequisite_decision") or {}).get("choice"))
        if choice != CHOICE_CREATE_DEDICATED:
            if record.get("remediation_state") not in {
                STATUS_PARTIAL_EXECUTION,
                STATUS_RECOVERY_REQUIRED,
            }:
                return
            choice = CHOICE_CREATE_DEDICATED

        if not (job.get("prerequisite_decisions") or {}).get(control_id):
            record_decision(
                job,
                control_id,
                CHOICE_CREATE_DEDICATED,
                note="Restored from persistent remediation ledger (cross-job continuity)",
                actor="remediation_ledger",
            )
            # Persist decision before regenerate helper reloads job
            jpath = workspace / "jobs" / f"{job['job_id']}.json"
            jpath.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")

        art = record.get("source_artifact") or {}
        art_path = Path(str(art.get("path") or ""))
        body = None
        if art_path.is_file():
            body = art_path.read_text(encoding="utf-8")
            if "REPLACE_CONFIG_" in body:
                body = None

        if body:
            from change_assurance.artifact_persistence import write_and_verify
            from change_assurance.prerequisite_resolution import _update_kit_member

            kit = Path(str(job.get("kit_path") or ""))
            if kit.exists():
                try:
                    write_and_verify(kit, f"terraform/{control_id}.tf", body)
                except Exception:
                    try:
                        _update_kit_member(kit if kit.is_file() else kit, f"terraform/{control_id}.tf", body)
                    except Exception:
                        pass
            res_store = dict(job.get("prerequisite_resolutions") or {})
            prev = dict(res_store.get(control_id) or {})
            prev.update(
                {
                    "choice": CHOICE_CREATE_DEDICATED,
                    "status": "PREREQUISITES_RESOLVED",
                    "artifact_path": str(art_path),
                    "artifact_sha256": art.get("sha256"),
                    "restored_from_ledger": True,
                    "lifecycle_key": record.get("lifecycle_key"),
                }
            )
            if record.get("prerequisite_resolution"):
                prev.setdefault("resources", (record.get("prerequisite_resolution") or {}).get("resources"))
            res_store[control_id] = prev
            job["prerequisite_resolutions"] = res_store
            return

        # Fall back: regenerate dedicated TF via existing resolver (no AWS apply)
        jid = str(job.get("job_id") or "")
        if jid:
            apply_decision_and_regenerate(
                workspace,
                jid,
                control_id,
                CHOICE_CREATE_DEDICATED,
                note="Ledger continuity: regenerate dedicated prerequisites (no apply)",
                findings=[{"id": control_id, "title": control_id, "severity": "high"}],
            )
            # Reload job after regenerate
            reloaded = json.loads((workspace / "jobs" / f"{jid}.json").read_text(encoding="utf-8-sig"))
            job.clear()
            job.update(reloaded)
    except Exception:
        pass


def apply_record_to_job(job: dict[str, Any], record: dict[str, Any], control_id: str) -> dict[str, Any]:
    """Project ledger fields onto a scan job (in-memory). Does not approve or apply."""
    control_id = str(control_id)
    job["aws_account_id"] = job.get("aws_account_id") or record.get("account_id")
    job["region"] = job.get("region") or record.get("region")
    job["execution_role"] = job.get("execution_role") or "SentinelStacksRemediationRole"
    job["execution_profile"] = job.get("execution_profile") or "sentinel-remediation"

    fe_store = dict(job.get("finding_execution") or {})
    if record.get("finding_execution"):
        fe_store[control_id] = dict(record["finding_execution"])
        fe_store[control_id]["lifecycle_key"] = record.get("lifecycle_key")
        fe_store[control_id]["restored_from_ledger"] = True
    job["finding_execution"] = fe_store

    # Merge attempts (append ledger attempts not already present by plan sha)
    existing = list(job.get("execution_attempts") or [])
    seen = {
        (a.get("approved_plan_sha256"), a.get("executed_at"), a.get("finding_id"))
        for a in existing
        if isinstance(a, dict)
    }
    for a in record.get("execution_attempts") or []:
        sig = (a.get("approved_plan_sha256"), a.get("executed_at"), a.get("finding_id"))
        if sig not in seen:
            existing.append(a)
            seen.add(sig)
    job["execution_attempts"] = existing

    if record.get("reviewed_plan"):
        plans = dict(job.get("reviewed_terraform_plans") or {})
        ref = dict(record["reviewed_plan"])
        # Normalize path fields
        if ref.get("recovery_plan_path") and not ref.get("plan_path"):
            ref["plan_path"] = ref["recovery_plan_path"]
            ref["saved_plan_path"] = ref["recovery_plan_path"]
        if record.get("finding_execution"):
            fe = record["finding_execution"]
            ref.setdefault("plan_path", fe.get("recovery_plan_path"))
            ref.setdefault("saved_plan_path", fe.get("recovery_plan_path"))
            if fe.get("recovery_plan_sha256"):
                ref["plan_sha256"] = fe["recovery_plan_sha256"]
                ref["saved_plan_sha256"] = fe["recovery_plan_sha256"]
        ref["plan_kind"] = ref.get("plan_kind") or "recovery"
        ref["lifecycle_key"] = record.get("lifecycle_key")
        plans[control_id] = ref
        job["reviewed_terraform_plans"] = plans

    if record.get("prerequisite_decision"):
        dec = dict(job.get("prerequisite_decisions") or {})
        dec[control_id] = dict(record["prerequisite_decision"])
        job["prerequisite_decisions"] = dec

    # Approval: never restore authorized approval for recovery — keep invalidated / pending
    appr = record.get("approval") or {}
    job["approval_status"] = str(appr.get("status") or "APPROVAL_INVALIDATED")
    if job["approval_status"] in {"APPROVED_FOR_EXECUTION", "approved"}:
        # Safety: recovery must not silently reuse old approval
        job["approval_status"] = "APPROVAL_INVALIDATED"
    job["execution_authorized"] = False
    job["execution_performed"] = True if record.get("execution_attempts") or record.get("finding_execution") else job.get(
        "execution_performed", False
    )
    if record.get("remediation_state") in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}:
        job["execution_performed"] = True
        job["apply_status"] = "partial_failed"
        job["manager_decision"] = None
        decisions = dict(job.get("finding_decisions") or {})
        decisions[control_id] = "pending_recovery"
        job["finding_decisions"] = decisions
        if job.get("status") == "approved":
            job["status"] = "pending_approval"

    binding = dict(job.get("approval_binding") or {})
    binding.update(
        {
            "status": "APPROVAL_INVALIDATED",
            "integrity": "INVALIDATED",
            "valid": False,
            "execution_authorized": False,
            "manager_decision": None,
            "invalidation_reasons": list(
                appr.get("invalidation_reasons") or [INVALIDATION_PARTIAL]
            ),
            "reason": INVALIDATION_PARTIAL,
            "lifecycle_key": record.get("lifecycle_key"),
            "restored_from_ledger": True,
        }
    )
    if appr.get("invalidated_saved_plan_sha256"):
        binding["invalidated_saved_plan_sha256"] = appr["invalidated_saved_plan_sha256"]
    job["approval_binding"] = binding

    job["remediation_lifecycle"] = {
        "lifecycle_key": record.get("lifecycle_key"),
        "remediation_state": record.get("remediation_state"),
        "finding_state": record.get("finding_state"),
        "prerequisite_resources": record.get("prerequisite_resources"),
        "restored_from_ledger": True,
    }
    return job


def reconcile_job_with_ledger(
    workspace: Path | str,
    job: dict[str, Any],
    *,
    control_ids: list[str] | None = None,
    account_id: str | None = None,
    region: str | None = None,
    run_discovery: bool = True,
    persist: bool = True,
) -> dict[str, Any]:
    """
    Attach active remediation lifecycles to a (possibly new) scan job.
    Does not copy blindly from a prior job ID — loads the environment/control ledger.
    """
    workspace = Path(workspace)
    controls = list(control_ids or [])
    if not controls:
        # Discover from ledger index + common cloud findings in summary
        idx_path = ledger_dir(workspace) / "index.json"
        if idx_path.is_file():
            idx = json.loads(idx_path.read_text(encoding="utf-8-sig"))
            for k, meta in (idx.get("by_lifecycle_key") or {}).items():
                cid = (meta or {}).get("control_id")
                if cid:
                    controls.append(str(cid))
        for fid in (job.get("finding_decisions") or {}):
            controls.append(str(fid))
        for top in ((job.get("summary") or {}).get("top_findings") or []):
            if isinstance(top, dict) and top.get("id"):
                controls.append(str(top["id"]))
            elif isinstance(top, str):
                controls.append(top)
    controls = sorted(set(c for c in controls if c))

    applied = []
    for cid in controls:
        key = key_for_control(job, cid, account_id=account_id, region=region)
        rec = load_record(workspace, key) if key else None
        if not rec:
            # Job may lack account/region (fresh scan). Match active ledger by control_id.
            idx_path = ledger_dir(workspace) / "index.json"
            if idx_path.is_file():
                idx = json.loads(idx_path.read_text(encoding="utf-8-sig"))
                for lk, meta in (idx.get("by_lifecycle_key") or {}).items():
                    if str((meta or {}).get("control_id") or "").upper() != str(cid).upper():
                        continue
                    cand = load_record(workspace, lk)
                    if not cand:
                        continue
                    if cand.get("remediation_state") in {
                        STATUS_PARTIAL_EXECUTION,
                        STATUS_RECOVERY_REQUIRED,
                        STATUS_FAILED,
                    }:
                        # Optional env filters when caller supplied them
                        if account_id and str(cand.get("account_id")) != str(account_id):
                            continue
                        if region and str(cand.get("region")).lower() != str(region).lower():
                            continue
                        rec = cand
                        break
        if not rec and (account_id and region):
            key = lifecycle_key(
                provider=infer_provider(job, {"id": cid}),
                account_id=account_id,
                region=region,
                control_id=cid,
            )
            rec = load_record(workspace, key)
        if not rec:
            continue
        if rec.get("remediation_state") in {STATUS_NOT_STARTED, STATUS_SUCCEEDED}:
            # Still project prerequisite decision if present, but no recovery UI needed
            if rec.get("prerequisite_decision"):
                dec = dict(job.get("prerequisite_decisions") or {})
                dec.setdefault(cid, dict(rec["prerequisite_decision"]))
                job["prerequisite_decisions"] = dec
            continue

        # Refresh discovery for active recovery
        if run_discovery and rec.get("provider") == "aws":
            trusted = list((rec.get("finding_execution") or {}).get("succeeded_resources") or [])
            disc = discover_aws_config_prerequisites(
                account_id=str(rec.get("account_id")),
                region=str(rec.get("region")),
                profile=str(job.get("execution_profile") or "sentinel-remediation"),
            )
            # If DIRECT proves removed, allow state change
            role_s = (disc.get("role") or {}).get("status")
            bucket_s = (disc.get("bucket") or {}).get("status")
            if role_s == "MISSING" or bucket_s == "MISSING":
                rec = merge_prerequisite_evidence(rec, disc, trusted_succeeded=trusted)
                # Legitimate regression — prerequisites may need re-create
                rec["remediation_state"] = STATUS_RECOVERY_REQUIRED
                rec["prerequisite_regression"] = {
                    "role": role_s,
                    "bucket": bucket_s,
                    "at": now(),
                }
                save_record(workspace, rec)
            else:
                rec = merge_prerequisite_evidence(rec, disc, trusted_succeeded=trusted)
                save_record(workspace, rec)

        apply_record_to_job(job, rec, cid)
        if rec.get("remediation_state") in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}:
            _apply_dedicated_artifacts(workspace, job, cid, rec)
        # Track this job on the ledger
        jobs = list(rec.get("source_jobs") or [])
        jid = str(job.get("job_id") or "")
        if jid and jid not in jobs:
            jobs.append(jid)
            rec["source_jobs"] = jobs
            rec["active_job_id"] = jid
            save_record(workspace, rec)
        applied.append(cid)

    job["ledger_reconciled_controls"] = applied
    job["updated_at"] = now()
    if persist and job.get("job_id"):
        path = workspace / "jobs" / f"{job['job_id']}.json"
        path.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    return job


def assurance_overlay_from_record(record: dict[str, Any] | None) -> dict[str, Any]:
    """Fields to merge into a Change Assurance / Manager Mode report."""
    if not record:
        return {}
    fe = record.get("finding_execution") or {}
    pr = record.get("prerequisite_resources") or {}
    plan = record.get("reviewed_plan") or {}
    summary = plan.get("summary") or fe.get("recovery_plan_summary") or {}
    missing_labels = []
    existence = []
    for addr, row in pr.items():
        status = str((row or {}).get("status") or "UNKNOWN")
        label = {
            "aws_iam_service_linked_role.config": "AWS Config IAM role",
            "aws_s3_bucket.config": "S3 delivery bucket (Config)",
        }.get(addr, addr)
        existence.append(
            {
                "address": addr,
                "label": label,
                "status": status,
                "evidence_quality": (row or {}).get("evidence_quality"),
                "evidence_source": (row or {}).get("evidence_source"),
                "identity": (row or {}).get("identity"),
            }
        )
        if status == "MISSING":
            missing_labels.append(label)

    rem_state = str(record.get("remediation_state") or "")
    overlay = {
        "lifecycle_key": record.get("lifecycle_key"),
        "finding_state": record.get("finding_state") or "OPEN",
        "remediation_lifecycle_state": rem_state,
        "finding_execution": fe,
        "prerequisite_existence": existence,
        "missing_prerequisite_labels": missing_labels,
        "prerequisite_resources": pr,
        "remediation_status": (
            "RECOVERY_REQUIRED"
            if rem_state in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}
            else None
        ),
        "execution_status_label": fe.get("execution_status") or (
            EXECUTION_LABEL_PARTIAL
            if rem_state in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}
            else None
        ),
        "recovery_plan_summary": summary,
        "recovery_plan_path": fe.get("recovery_plan_path") or plan.get("plan_path") or plan.get("saved_plan_path"),
        "recovery_plan_sha256": fe.get("recovery_plan_sha256")
        or plan.get("plan_sha256")
        or plan.get("saved_plan_sha256"),
        "prior_approval_valid": False
        if rem_state in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}
        else None,
        "approval_invalidation_reason": INVALIDATION_PARTIAL
        if rem_state in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}
        else None,
    }
    # When role+bucket exist, clear "missing" prerequisite narrative
    if rem_state in {STATUS_PARTIAL_EXECUTION, STATUS_RECOVERY_REQUIRED}:
        if not missing_labels:
            overlay["remediation_prerequisites"] = []
            overlay["relevant_placeholders"] = []
            overlay["suppress_placeholder_prerequisites"] = True
            overlay["prerequisite_manager_decision"] = "CREATE DEDICATED RESOURCES"
            if (record.get("prerequisite_decision") or {}).get("choice"):
                overlay["prerequisite_decision"] = record.get("prerequisite_decision")
    return overlay
