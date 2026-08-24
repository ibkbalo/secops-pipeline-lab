# change_assurance/prerequisite_resolution.py
# Generic prerequisite lifecycle: detect → manager decide → resolve → regenerate → rescan.
# Advisory only — never applies to AWS / never auto-executes.

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Callable

VERSION = "0.1.0"

CHOICE_UNDECIDED = "UNDECIDED"
CHOICE_REUSE = "REUSE_EXISTING"
CHOICE_CREATE_DEDICATED = "CREATE_DEDICATED"

ResolverFn = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]

# finding_id / control family → resolver
_RESOLVERS: dict[str, ResolverFn] = {}


def register_resolver(control_key: str, fn: ResolverFn) -> None:
    _RESOLVERS[str(control_key).upper()] = fn


def normalize_choice(raw: str | None) -> str:
    t = str(raw or "").strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "CREATE": CHOICE_CREATE_DEDICATED,
        "CREATE_DEDICATED": CHOICE_CREATE_DEDICATED,
        "CREATE_DEDICATED_RESOURCES": CHOICE_CREATE_DEDICATED,
        "DEDICATED": CHOICE_CREATE_DEDICATED,
        "REUSE": CHOICE_REUSE,
        "REUSE_EXISTING": CHOICE_REUSE,
        "REUSE_APPROVED": CHOICE_REUSE,
    }
    return aliases.get(t, t if t in {CHOICE_CREATE_DEDICATED, CHOICE_REUSE, CHOICE_UNDECIDED} else CHOICE_UNDECIDED)


def get_decision(job: dict[str, Any] | None, finding_id: str | None) -> dict[str, Any] | None:
    fid = str(finding_id or "").strip()
    if not job or not fid:
        return None
    store = job.get("prerequisite_decisions") or {}
    if not isinstance(store, dict):
        return None
    row = store.get(fid) or store.get(fid.upper())
    return dict(row) if isinstance(row, dict) else None


def record_decision(
    job: dict[str, Any],
    finding_id: str,
    choice: str,
    *,
    note: str | None = None,
    actor: str = "manager",
) -> dict[str, Any]:
    """Persist an explicit manager prerequisite decision on the job (metadata only)."""
    fid = str(finding_id or "").strip()
    choice_n = normalize_choice(choice)
    from change_assurance.models import now

    entry = {
        "finding_id": fid,
        "choice": choice_n,
        "actor": actor,
        "recorded_at": now(),
        "note": note or "",
        "inferred": False,
        "auto_apply": False,
        "execution_performed": False,
    }
    store = dict(job.get("prerequisite_decisions") or {})
    store[fid] = entry
    job["prerequisite_decisions"] = store
    return entry


# Register cloud resolvers lazily (avoid circular import at module load)
def ensure_resolvers_registered() -> None:
    if "CLOUD-LOG-002" in _RESOLVERS:
        return
    from change_assurance.domains.cloud.config_prerequisites import resolve_aws_config_dedicated

    register_resolver("CLOUD-LOG-002", resolve_aws_config_dedicated)
    register_resolver("AWS_CONFIG_RECORDER", resolve_aws_config_dedicated)
    register_resolver("AWS-014", resolve_aws_config_dedicated)


def resolve_for_finding(
    finding: dict[str, Any],
    decision: dict[str, Any] | None,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Domain/control resolver for a manager decision.
    Returns None when undecided or no resolver.
    """
    ensure_resolvers_registered()
    ctx = dict(context or {})
    fid = str(finding.get("id") or "").strip().upper()
    choice = normalize_choice((decision or {}).get("choice"))
    if choice == CHOICE_UNDECIDED:
        return None
    # Prefer exact finding id, then title-family keys
    for key in (fid, "AWS_CONFIG_RECORDER", "CLOUD-LOG-002"):
        fn = _RESOLVERS.get(key)
        if fn:
            out = fn(finding, {**(decision or {}), "choice": choice, **ctx})
            if out:
                out.setdefault("finding_id", fid)
                out.setdefault("choice", choice)
                out.setdefault("auto_apply_forbidden", True)
                out.setdefault("execution_performed", False)
                return out
    return None


def _load_job(workspace: Path, job_id: str) -> dict[str, Any]:
    path = workspace / "jobs" / f"{job_id}.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _save_job(workspace: Path, job: dict[str, Any]) -> Path:
    path = workspace / "jobs" / f"{job['job_id']}.json"
    path.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    return path


def _update_kit_member(kit_path: Path, rel: str, body: str) -> None:
    """Replace or add a member inside a kit zip (or directory)."""
    rel_n = str(rel).replace("\\", "/").lstrip("./")
    if kit_path.is_dir():
        dest = kit_path / rel_n
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        return
    if not (kit_path.is_file() and kit_path.suffix.lower() == ".zip"):
        raise FileNotFoundError(f"kit not found: {kit_path}")
    tmp = kit_path.with_suffix(".zip.tmp")
    with zipfile.ZipFile(kit_path, "r") as zin, zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        written = False
        for info in zin.infolist():
            name = info.filename.replace("\\", "/")
            if name == rel_n or name.endswith("/" + rel_n):
                zout.writestr(rel_n, body.encode("utf-8"))
                written = True
            else:
                zout.writestr(info, zin.read(info.filename))
        if not written:
            zout.writestr(rel_n, body.encode("utf-8"))
    tmp.replace(kit_path)


def _patch_manifest_item(kit_path: Path, finding_id: str, files: list[str], meta: dict[str, Any]) -> None:
    if kit_path.is_dir():
        man_path = kit_path / "manifest.json"
        man = json.loads(man_path.read_text(encoding="utf-8-sig")) if man_path.is_file() else {"items": []}
    else:
        with zipfile.ZipFile(kit_path, "r") as zf:
            raw = next((n for n in zf.namelist() if n.replace("\\", "/").endswith("manifest.json")), None)
            man = json.loads(zf.read(raw).decode("utf-8")) if raw else {"items": []}
    items = list(man.get("items") or [])
    updated = False
    for item in items:
        if str(item.get("check_id") or "") == finding_id:
            item["files"] = files
            item["prerequisite_resolution"] = meta
            item["status"] = "mapped"
            item["approval_ready"] = False  # still needs validate/plan/manager approve
            item["needs_review"] = True
            updated = True
            break
    if not updated:
        items.append(
            {
                "check_id": finding_id,
                "status": "mapped",
                "files": files,
                "prerequisite_resolution": meta,
                "approval_ready": False,
                "needs_review": True,
            }
        )
    man["items"] = items
    body = json.dumps(man, indent=2)
    if kit_path.is_dir():
        (kit_path / "manifest.json").write_text(body, encoding="utf-8")
    else:
        _update_kit_member(kit_path, "manifest.json", body)


def apply_decision_and_regenerate(
    workspace: Path | str,
    job_id: str,
    finding_id: str,
    choice: str,
    *,
    note: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Record manager decision, write resolved artifacts to the bound kit (dir+zip),
    verify persisted bytes, then return summary. Does NOT apply to AWS.

    Success requires on-disk verification — never from in-memory Terraform alone.
    """
    from change_assurance.artifact_persistence import (
        CONFIG_DEDICATED_SIGNATURES,
        FORBIDDEN_AFTER_DEDICATED,
        ArtifactPersistenceError,
        kit_dir_and_zip,
        patch_manifest_artifact,
        write_and_verify,
    )
    from change_assurance.models import now
    from predeploy.terraform_plan_analysis import analyze_kit_terraform

    workspace = Path(workspace)
    job = _load_job(workspace, job_id)
    decision = record_decision(job, finding_id, choice, note=note)
    finding = None
    for f in findings or []:
        if str(f.get("id") or "") == finding_id:
            finding = f
            break
    if finding is None:
        scan_path = Path(str(job.get("scan_report_path") or ""))
        if scan_path.is_file():
            report = json.loads(scan_path.read_text(encoding="utf-8-sig"))
            for f in report.get("findings") or []:
                if isinstance(f, dict) and str(f.get("id") or "") == finding_id:
                    finding = f
                    break
    if finding is None:
        finding = {"id": finding_id, "title": finding_id}

    region = (
        str((finding.get("resource") or {}).get("region") or "")
        or str(job.get("region") or "")
        or "us-east-1"
    )
    resolved = resolve_for_finding(
        finding,
        decision,
        context={"region": region, "job": job, "version": VERSION},
    )
    if not resolved or not resolved.get("terraform"):
        _save_job(workspace, job)
        return {
            "status": "decision_recorded",
            "decision": decision,
            "resolved": False,
            "reason": "No resolver terraform for this choice",
            "auto_apply_forbidden": True,
            "execution_performed": False,
        }

    kit_path = Path(str(job.get("kit_path") or ""))
    if not kit_path.exists():
        raise FileNotFoundError(f"job kit_path missing: {kit_path}")

    # Prefer writing through the directory companion so Face/filesystem searches see it
    d, z = kit_dir_and_zip(kit_path)
    write_root = d if d is not None else kit_path
    if d is None and kit_path.suffix.lower() == ".zip":
        # Ensure unzipped companion exists for filesystem truth
        d = kit_path.with_suffix("")
        d.mkdir(parents=True, exist_ok=True)
        write_root = d
        # seed from zip once
        with zipfile.ZipFile(kit_path, "r") as zf:
            zf.extractall(d)
        job["kit_path"] = str(kit_path.resolve())  # keep zip as primary bind; dir synced

    tf_rel = f"terraform/{finding_id}.tf"
    yml_rel = f"runbooks/{finding_id}.yml"
    files_written: list[str] = []
    persistence: dict[str, Any] = {}

    try:
        tf_meta = write_and_verify(
            write_root if write_root.suffix.lower() != ".zip" else kit_path,
            tf_rel,
            str(resolved["terraform"]),
            required_signatures=CONFIG_DEDICATED_SIGNATURES
            if decision["choice"] == CHOICE_CREATE_DEDICATED
            else None,
            forbid_tokens=FORBIDDEN_AFTER_DEDICATED
            if decision["choice"] == CHOICE_CREATE_DEDICATED
            else None,
            require_no_placeholders=decision["choice"] == CHOICE_CREATE_DEDICATED,
            protect_resolved=True,
        )
        # Also sync explicit zip when write_root was directory
        if d is not None and (z is not None or kit_path.suffix.lower() == ".zip"):
            zip_path = z or kit_path
            write_and_verify(
                zip_path,
                tf_rel,
                str(resolved["terraform"]),
                required_signatures=CONFIG_DEDICATED_SIGNATURES
                if decision["choice"] == CHOICE_CREATE_DEDICATED
                else None,
                forbid_tokens=FORBIDDEN_AFTER_DEDICATED
                if decision["choice"] == CHOICE_CREATE_DEDICATED
                else None,
                require_no_placeholders=decision["choice"] == CHOICE_CREATE_DEDICATED,
                protect_resolved=True,
            )
        files_written.append(tf_rel)
        persistence = tf_meta

        if resolved.get("runbook"):
            write_and_verify(
                d or kit_path,
                yml_rel,
                str(resolved["runbook"]),
                require_no_placeholders=False,
                protect_resolved=False,
            )
            if d is not None and (z is not None or kit_path.suffix.lower() == ".zip"):
                write_and_verify(
                    z or kit_path,
                    yml_rel,
                    str(resolved["runbook"]),
                    require_no_placeholders=False,
                    protect_resolved=False,
                )
            files_written.append(yml_rel)
    except ArtifactPersistenceError as exc:
        meta_fail = {
            "choice": decision["choice"],
            "status": "PREREQUISITES_REQUIRED",
            "error_code": exc.code,
            "error": str(exc),
            "auto_apply_forbidden": True,
            "execution_performed": False,
            "persistence_verified": False,
        }
        job["prerequisite_resolutions"] = dict(job.get("prerequisite_resolutions") or {})
        job["prerequisite_resolutions"][finding_id] = meta_fail
        _save_job(workspace, job)
        return {
            "status": "failed",
            "decision": decision,
            "resolved": False,
            "error_code": exc.code,
            "error": str(exc),
            "details": exc.details,
            "prerequisite_status": "PREREQUISITES_REQUIRED",
            "execution_ready": False,
            "execution_performed": False,
            "auto_apply_forbidden": True,
        }

    abs_tf = persistence.get("absolute_path")
    sha = persistence.get("sha256")
    meta = {
        "choice": decision["choice"],
        "status": "PREREQUISITES_RESOLVED",
        "resolver": resolved.get("resolver"),
        "resources": resolved.get("expected_resources") or [],
        "do_not_touch": resolved.get("do_not_touch") or [],
        "required_remediation_role_permissions": resolved.get("required_remediation_role_permissions")
        or [],
        "cost_note": resolved.get("cost_note"),
        "auto_apply_forbidden": True,
        "execution_performed": False,
        "persistence_verified": True,
        "artifact_path": abs_tf,
        "artifact_sha256": sha,
        "artifact_generated_at": now(),
        "kit_path": str(Path(job.get("kit_path")).resolve()),
        "kit_generation_id": Path(str(job.get("kit_path"))).stem,
    }
    patch_manifest_artifact(
        d or kit_path,
        finding_id,
        files=files_written,
        sha256=str(sha),
        absolute_path=str(abs_tf),
        extra={"prerequisite_resolution": meta},
    )
    if d is not None and (z is not None or kit_path.suffix.lower() == ".zip"):
        patch_manifest_artifact(
            z or kit_path,
            finding_id,
            files=files_written,
            sha256=str(sha),
            absolute_path=str(abs_tf),
            extra={"prerequisite_resolution": meta},
        )

    job["prerequisite_resolutions"] = dict(job.get("prerequisite_resolutions") or {})
    job["prerequisite_resolutions"][finding_id] = meta
    job["kit_generation_id"] = meta["kit_generation_id"]
    _save_job(workspace, job)

    # Placeholder readiness ONLY from persisted kit members
    analysis = analyze_kit_terraform(d or kit_path, [finding_id], try_cli=False)
    disk_placeholders = analysis.get("placeholders") or []
    if disk_placeholders:
        meta["status"] = "PREREQUISITES_REQUIRED"
        meta["persistence_verified"] = False
        meta["error_code"] = "ARTIFACT_PERSISTENCE_MISMATCH"
        job["prerequisite_resolutions"][finding_id] = meta
        _save_job(workspace, job)
        return {
            "status": "failed",
            "decision": decision,
            "resolved": False,
            "error_code": "ARTIFACT_PERSISTENCE_MISMATCH",
            "error": "Persisted kit still reports placeholders after write",
            "placeholders": disk_placeholders,
            "artifact_path": abs_tf,
            "artifact_sha256": sha,
            "prerequisite_status": "PREREQUISITES_REQUIRED",
            "execution_ready": False,
            "execution_performed": False,
            "auto_apply_forbidden": True,
        }

    return {
        "status": "resolved",
        "decision": decision,
        "resolved": True,
        "kit_path": str(Path(job["kit_path"]).resolve()),
        "kit_generation_id": meta["kit_generation_id"],
        "files_written": files_written,
        "prerequisite_status": meta["status"],
        "placeholders": [],
        "placeholder_unresolved": False,
        "expected_resources": meta["resources"],
        "required_remediation_role_permissions": meta["required_remediation_role_permissions"],
        "do_not_touch": meta["do_not_touch"],
        "cost_note": meta.get("cost_note"),
        "artifact_path": abs_tf,
        "artifact_sha256": sha,
        "artifact_generated_at": meta["artifact_generated_at"],
        "persistence_verified": True,
        "execution_ready": False,
        "execution_performed": False,
        "auto_apply_forbidden": True,
    }


def rehydrate_resolved_artifacts_into_kit(
    workspace: Path | str,
    job: dict[str, Any],
    *,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    After a legacy kit regeneration rebinds job.kit_path, re-apply CREATE_DEDICATED
    resolutions into the NEW kit and verify disk. Prevents false RESOLVED metadata.
    """
    workspace = Path(workspace)
    results = {}
    decisions = job.get("prerequisite_decisions") or {}
    if not isinstance(decisions, dict) or not decisions:
        return {"rehydrated": [], "skipped": True}
    job_id = str(job.get("job_id") or "")
    for fid, dec in decisions.items():
        if normalize_choice((dec or {}).get("choice")) != CHOICE_CREATE_DEDICATED:
            continue
        results[fid] = apply_decision_and_regenerate(
            workspace,
            job_id,
            str(fid),
            CHOICE_CREATE_DEDICATED,
            note=str((dec or {}).get("note") or "rehydrate into rebound kit"),
            findings=findings,
        )
    return {"rehydrated": list(results.keys()), "results": results}


# end of module — resolvers register lazily via ensure_resolvers_registered()
