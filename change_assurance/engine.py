# change_assurance/engine.py
# Shared Change Assurance Engine — domain adapters + artifact handlers.

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from change_assurance import approval_integrity, recommendations
from change_assurance.artifacts.generic import handler_for_type
from change_assurance.domains.cloud.adapter import CloudSecurityAdapter
from change_assurance.domains.devsecops.adapter import DevSecOpsAdapter, infer_devsecops_artifact_type
from change_assurance.domains.stub import (
    ai_security_adapter,
    security_engineering_adapter,
)
from change_assurance.models import (
    domain_for_role,
    empty_assurance_report,
    new_change_artifact,
    now,
    stable_hash,
)
from change_assurance.secret_redaction import redact_text

VERSION = "0.2.0-p3"


def assurance_cache_incomplete(report: dict[str, Any] | None) -> bool:
    """
    True when a cached assurance/impact artifact predates evidence-quality
    or per-finding artifact scoping and must not be served as live proof.
    """
    if not isinstance(report, dict) or not report:
        return True
    assessment = report.get("evidence_assessment")
    evidence = report.get("evidence") or []
    legacy = report.get("legacy_impact") if isinstance(report.get("legacy_impact"), dict) else {}
    if not assessment:
        assessment = legacy.get("evidence_assessment")
    if not evidence:
        evidence = legacy.get("evidence") or (legacy.get("discovery") or {}).get("evidence") or []
    if not assessment:
        return True
    if evidence and not any(isinstance(e, dict) and e.get("quality") for e in evidence):
        return True
    # Pre–placeholder-scoping caches lack artifact_scope and may REJECT from whole-kit REPLACE_*
    if report.get("domain") == "cloud_security" or str(report.get("role") or "") == "cloud" or legacy.get("role") == "cloud":
        if not report.get("artifact_scope") and not legacy.get("artifact_scope"):
            return True
        tf = legacy.get("terraform") if isinstance(legacy.get("terraform"), dict) else {}
        flags = tf.get("flags") if isinstance(tf.get("flags"), dict) else {}
        # Cached whole-kit placeholder reject without scoped relevant_artifacts → regenerate
        if flags.get("placeholder_unresolved") and not (
            report.get("relevant_artifacts") or legacy.get("relevant_artifacts")
        ):
            return True
    return False


def get_adapter(domain: str):
    if domain == "cloud_security":
        return CloudSecurityAdapter()
    if domain == "security_engineering":
        return security_engineering_adapter()
    if domain == "devsecops":
        return DevSecOpsAdapter()
    if domain == "ai_security":
        return ai_security_adapter()
    return security_engineering_adapter()  # safe unknown → review stub


def _focus_findings(findings: list[dict]) -> list[dict]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def key(f: dict) -> tuple:
        fid = str(f.get("id") or "")
        return (rank.get(str(f.get("severity") or "info").lower(), 9), 1 if fid.startswith("CLOUD-DFT") else 0, fid)

    return sorted([f for f in findings if isinstance(f, dict)], key=key)[:5]


def _infer_artifact_type(role: str, kit_path: str | None, finding: dict, files: list[str] | None = None, preview: str = "") -> str:
    if role == "cloud" or str(finding.get("id") or "").startswith("CLOUD-"):
        return "terraform"
    if role == "devsecops":
        return infer_devsecops_artifact_type(finding, files or [], preview)
    if role == "ai-security":
        return "ai_agent_policy"
    if role == "security-engineer":
        return "manual_procedure"
    if kit_path and str(kit_path).endswith(".zip"):
        return "terraform"
    return "configuration_change"


def _kit_preview(kit_path: str | None, finding_id: str | None) -> tuple[list[str], str]:
    if not kit_path:
        return [], ""
    p = Path(kit_path)
    files: list[str] = []
    preview = ""
    try:
        from predeploy.terraform_plan_analysis import resolve_finding_kit_artifacts

        scope = resolve_finding_kit_artifacts(p, finding_id)
        scoped_paths = list(scope.get("paths") or [])
        if p.is_file() and p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p, "r") as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                # Prefer finding-linked artifacts for preview/source_files
                if scoped_paths:
                    files = scoped_paths[:40]
                    preferred = next(
                        (n for n in scoped_paths if n.lower().endswith((".tf", ".yml", ".yaml", ".conf"))),
                        scoped_paths[0],
                    )
                    match = next(
                        (n for n in names if n.replace("\\", "/") == preferred or n.replace("\\", "/").endswith(preferred)),
                        None,
                    )
                    if match:
                        preview = zf.read(match).decode("utf-8", errors="replace")[:4000]
                else:
                    files = [n.replace("\\", "/") for n in names[:40]]
                    preferred = None
                    for n in names:
                        if finding_id and finding_id in n and n.endswith((".tf", ".yml", ".yaml", ".ps1", ".py", ".md")):
                            preferred = n
                            break
                    if preferred:
                        preview = zf.read(preferred).decode("utf-8", errors="replace")[:4000]
        elif p.is_dir():
            if scoped_paths:
                files = scoped_paths[:40]
                for rel in scoped_paths:
                    cand = p / rel
                    if cand.is_file() and cand.suffix.lower() in {".tf", ".yml", ".yaml", ".conf"}:
                        preview = cand.read_text(encoding="utf-8", errors="replace")[:4000]
                        break
            else:
                files = [str(x.relative_to(p)).replace("\\", "/") for x in p.rglob("*") if x.is_file()][:40]
    except Exception:
        return files, preview
    return files, preview


def assure_job(
    job: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    *,
    profile: str | None = None,
    region: str | None = None,
    try_terraform_cli: bool = False,
) -> dict[str, Any]:
    """
    Run shared change assurance for a Brain job.
    Never executes remediations. Recommendation != authorization.
    """
    findings = findings or []
    role = str(job.get("role") or "")
    domain = domain_for_role(role)
    report = empty_assurance_report(job_id=job.get("job_id"), domain=domain, role=role)
    adapter = get_adapter(domain)
    report["capabilities"].append(adapter.capability_status())

    focus = _focus_findings(findings)
    primary = focus[0] if focus else {"id": "UNKNOWN", "title": "No findings", "severity": "info"}
    finding_id = str(primary.get("id") or "UNKNOWN")
    report["primary_finding_id"] = finding_id
    report["focus_finding_ids"] = [str(f.get("id")) for f in focus if f.get("id")]
    report["finding_severity"] = primary.get("severity")

    context = {
        "job": job,
        "profile": profile,
        "region": region,
        "kit_path": job.get("kit_path"),
        "finding_id": finding_id,
        "try_terraform_cli": try_terraform_cli,
    }

    verified = adapter.verify_finding(primary, context)
    context["discovery"] = verified.get("discovery") or context.get("repo_discovery")
    report["finding_status"] = verified.get("finding_status") or "UNKNOWN"
    report["evidence"] = adapter.gather_evidence(primary, context)
    report["evidence_assessment"] = verified.get("evidence_assessment") or (
        (context.get("discovery") or {}).get("evidence_assessment")
    )
    report["evidence_quality"] = (report.get("evidence_assessment") or {}).get("evidence_quality")
    # Internal validation (not Manager Mode UI) — confirm registry match for live debugging
    _ea = report.get("evidence_assessment") or {}
    report["evidence_registry_match"] = _ea.get("registry_match") or {
        "finding_id": finding_id,
        "matched_evidence_spec": _ea.get("control_key"),
        "collector": (_ea.get("preferred_sources") or [None])[0]
        if isinstance(_ea.get("preferred_sources"), list)
        else _ea.get("evidence_source"),
        "required_fields": _ea.get("required_fields"),
        "preferred_source": _ea.get("evidence_source") or _ea.get("preferred_sources"),
    }

    files, preview = _kit_preview(job.get("kit_path"), finding_id)
    # Prefer richer kit texts for DevSecOps when ZIP/dir present
    kit_texts = context.get("kit_texts") or {}
    if kit_texts and not preview:
        # Pick most relevant file for finding
        preferred = None
        for name in kit_texts:
            if finding_id and finding_id in name:
                preferred = name
                break
        if not preferred:
            preferred = next(iter(kit_texts), None)
        if preferred:
            preview = kit_texts[preferred]
            if preferred not in files:
                files = [preferred] + list(files)
    preview, _secret_hits = redact_text(preview)
    art_type = _infer_artifact_type(role, job.get("kit_path"), primary, files, preview)
    repo_disc = context.get("repo_discovery") or context.get("discovery") or {}
    repo_fp = repo_disc.get("repo_fingerprint") or {
        "repository": repo_disc.get("repository"),
        "branch": repo_disc.get("branch"),
        "commit_sha": repo_disc.get("commit_sha"),
    }
    target_env = str(
        (context.get("discovery") or {}).get("account_id")
        or job.get("target_environment")
        or ("local-repo" if domain == "devsecops" else job.get("role") or "local")
    )
    artifact = new_change_artifact(
        finding_id=finding_id,
        domain=domain,
        artifact_type=art_type,
        target_environment=target_env,
        source_files=files,
        content_preview=preview,
        meta={
            "kit_path": job.get("kit_path"),
            "job_id": job.get("job_id"),
            "repo_fingerprint": repo_fp,
            "validation_mode": context.get("validation_mode") or ("STATIC_ONLY" if domain == "devsecops" else None),
        },
    )

    handler = handler_for_type(art_type)
    validation = handler.validate(artifact, context)
    artifact["validation"] = validation
    changes = handler.analyze_changes(artifact, context)
    artifact["proposed_changes"] = changes.get("actions") or changes.get("proposed_changes") or []
    if changes.get("git_diff_hash"):
        artifact.setdefault("meta", {})["git_diff_hash"] = changes.get("git_diff_hash")
    if changes.get("diff_files"):
        artifact["diff_files"] = changes.get("diff_files")
    if changes.get("dependencies"):
        artifact["dependency_updates"] = changes.get("dependencies")
    destructive = handler.detect_destructive_actions(artifact, context)
    artifact["destructive"] = destructive
    artifact["rollback"] = handler.build_rollback_plan(artifact, context)
    artifact["artifact_hash"] = handler.calculate_hash(artifact)

    change_ctx = {
        "flags": changes.get("flags") or {},
        "plan": changes.get("plan") or {},
        "diff_files": changes.get("diff_files") or [],
        "dependencies": changes.get("dependencies") or [],
    }
    deps = adapter.discover_dependencies(change_ctx, context)
    context["deps"] = deps
    impact = adapter.analyze_impact(change_ctx, {**context, "impact": None})
    risk = adapter.calculate_risk(change_ctx, {**context, "impact": impact})
    scope = adapter.classify_scope(change_ctx, context)
    questions = adapter.generate_manager_questions(primary, change_ctx, context)
    verification = adapter.build_verification_plan(primary, change_ctx, context)
    artifact["verification"] = verification
    artifact["dependencies"] = deps

    cross_hooks = []
    if domain == "devsecops" and hasattr(adapter, "cross_agent_review_hooks"):
        cross_hooks = adapter.cross_agent_review_hooks(change_ctx, context)  # type: ignore[attr-defined]

    report["artifacts"] = [artifact]
    report["dependencies"] = deps
    report["blast_radius"] = impact.get("blast_radius") or {"level": "UNKNOWN", "scope": scope}
    report["blast_radius"]["scope"] = scope
    report["remediation_risk"] = risk
    report["manager_questions"] = questions
    report["manager_context_required"] = bool(questions) or (
        adapter.capability_status().get("status") not in {"AVAILABLE"}
    )
    report["verification"] = verification
    report["rollback"] = artifact.get("rollback") or {}
    report["validation_status"] = validation.get("status") or "VALIDATION_UNAVAILABLE"
    report["validation_mode"] = context.get("validation_mode") or artifact.get("meta", {}).get("validation_mode")
    report["repo_fingerprint"] = repo_fp
    report["live_state_fingerprint"] = repo_disc.get("fingerprint") or (
        stable_hash(repo_fp) if repo_fp else None
    )
    report["target_identity"] = (repo_fp or {}).get("commit_sha") if isinstance(repo_fp, dict) else None
    report["cross_agent_review"] = cross_hooks
    report["finding_decisions"] = {}  # filled by manager per finding

    # Partial capability for unsupported DevSecOps finding types
    partial = verified.get("capability") == "CAPABILITY_PARTIAL"
    if partial and report["finding_status"] == "UNKNOWN":
        report["capabilities"].append({"status": "CAPABILITY_PARTIAL", "detail": "Unsupported finding type"})

    cap_unavail = adapter.capability_status().get("status") == "CAPABILITY_UNAVAILABLE"
    artifact_scope = validation.get("artifact_scope") or (validation.get("analysis") or {}).get("artifact_scope") or {}
    mapping_uncertain = bool(
        artifact_scope.get("uncertain") or artifact_scope.get("reason") == "ARTIFACT_MAPPING_UNCERTAIN"
    )
    placeholders = False
    if not mapping_uncertain:
        placeholders = bool((changes.get("flags") or {}).get("placeholder_unresolved")) or any(
            "REPLACE_" in str(e) for e in (validation.get("errors") or [])
        )
    # Whole-job safety: sibling kit placeholders must not silently disappear
    sibling_placeholders: list[dict[str, str]] = []
    try:
        from predeploy.terraform_plan_analysis import scan_kit_placeholders

        relevant = list(artifact_scope.get("paths") or validation.get("relevant_artifacts") or [])
        all_hits = scan_kit_placeholders(job.get("kit_path"))
        sibling_placeholders = [
            h
            for h in all_hits
            if not any(
                str(h.get("file") or "").endswith(str(r)) or str(h.get("file")) == str(r) for r in relevant
            )
        ]
    except Exception:
        sibling_placeholders = []

    secret_reject = any("SECRET_REDACTED" in str(e) for e in (validation.get("errors") or []))
    hard_reject = secret_reject or bool((changes.get("flags") or {}).get("secret_copied")) or bool(
        (changes.get("flags") or {}).get("write_all") and (changes.get("flags") or {}).get("pull_request_target")
    )
    rec = recommendations.recommend(
        finding_status=str(report["finding_status"]),
        validation_status=str(report["validation_status"]),
        blast_level=str((report["blast_radius"] or {}).get("level") or "UNKNOWN"),
        remediation_risk=str((risk or {}).get("level") or "UNKNOWN"),
        destructive=bool(destructive.get("destructive")),
        placeholders=placeholders,
        manager_questions=questions,
        protected_asset_hit=False,
        capability_unavailable=cap_unavail or partial,
        force_reject=hard_reject,
        artifact_mapping_uncertain=mapping_uncertain,
    )
    if sibling_placeholders and rec.get("recommendation") == "RECOMMEND_APPROVE":
        # Finding may be an approve candidate, but whole-job must not be fully green
        rec = dict(rec)
        rec["recommendation"] = "RECOMMEND_REVIEW"
        rec["deployment_ready"] = False
        rec["reasons"] = list(rec.get("reasons") or []) + [
            "JOB_HAS_UNRESOLVED_SIBLING_ARTIFACTS — other findings in this kit still have REPLACE_* placeholders"
        ]
    report["recommendation"] = rec["recommendation"]
    report["deployment_ready"] = bool(rec.get("deployment_ready")) and not sibling_placeholders
    report["recommendation_reasons"] = rec.get("reasons") or []
    report["relevant_artifacts"] = validation.get("relevant_artifacts") or artifact_scope.get("paths") or files
    report["relevant_placeholders"] = validation.get("placeholders") or changes.get("placeholders") or []
    report["sibling_placeholder_artifacts"] = sibling_placeholders[:20]
    report["job_fully_approvable"] = (
        bool(rec.get("deployment_ready")) and not sibling_placeholders and not placeholders
    )
    report["artifact_scope"] = artifact_scope
    report["manager_approval_required"] = True
    report["auto_apply_forbidden"] = True
    report["execution_authorized"] = False
    report["execution_performed"] = False

    report["approval_binding"] = approval_integrity.build_approval_binding(
        job_id=str(job.get("job_id") or ""),
        finding_id=finding_id,
        artifacts=report["artifacts"],
        target_environment=artifact.get("target_environment"),
        recommendation=report["recommendation"],
        assurance_report=report,
        target_identity=report.get("target_identity"),
    )
    # Pending bind — not manager authorization
    report["approval_binding"]["status"] = "PENDING_MANAGER_DECISION"
    report["approval_integrity"] = {
        "integrity": "PENDING",
        "status": "PENDING_MANAGER_DECISION",
        "valid": False,
        "reason": "Awaiting manager decision — AI recommendation is not authorization",
    }

    # Shared assurance questions snapshot (honest UNKNOWN where needed)
    report["assurance_answers"] = {
        "finding_still_present": verified.get("still_present"),
        "evidence_count": len(report["evidence"]),
        "what_changes": artifact.get("proposed_changes"),
        "affected_targets": deps,
        "dependencies": deps,
        "blast_radius": report["blast_radius"],
        "remediation_risk": risk,
        "reversible": report["rollback"].get("available"),
        "rollback_procedure": report["rollback"].get("procedure"),
        "verification_plan": verification,
        "manager_context_required": report["manager_context_required"],
        "artifact_complete": not placeholders,
        "unresolved_placeholders": placeholders,
        "relevant_artifacts": report.get("relevant_artifacts"),
        "sibling_placeholder_artifacts": sibling_placeholders[:10],
        "job_fully_approvable": report.get("job_fully_approvable"),
        "validator_status": report["validation_status"],
        "change_matches_finding": "UNKNOWN" if domain != "cloud_security" else True,
        "validation_mode": report.get("validation_mode"),
        "cross_agent_review": cross_hooks,
        "execution_authorized": False,
        "execution_performed": False,
        "evidence_quality": report.get("evidence_quality"),
        "evidence_assessment": report.get("evidence_assessment"),
    }

    report["report_text"] = _render_text(report, primary)
    # Legacy shape for Face/predeploy consumers
    report["legacy_impact"] = _to_legacy_impact(report, job)
    return report


def _render_text(report: dict, primary: dict) -> str:
    lines = [
        "CHANGE ASSURANCE REPORT",
        f"Domain: {report.get('domain')}",
        f"Agent role: {report.get('role')}",
        f"Finding: {report.get('primary_finding_id')} — {primary.get('title')}",
        f"Finding severity: {report.get('finding_severity')}",
        f"Finding status: {report.get('finding_status')}",
        f"Validation mode: {report.get('validation_mode') or 'n/a'}",
        f"Validation: {report.get('validation_status')}",
        f"Blast radius: {(report.get('blast_radius') or {}).get('level')} scope={(report.get('blast_radius') or {}).get('scope')}",
        f"Remediation risk: {(report.get('remediation_risk') or {}).get('level')}",
        f"Recommendation: {report.get('recommendation')}",
        "Manager approval required: YES",
        "Auto-apply: FORBIDDEN",
        f"Manager context required: {report.get('manager_context_required')}",
        f"Approval integrity: {(report.get('approval_integrity') or {}).get('integrity') or 'PENDING'}",
    ]
    rp = report.get("repo_fingerprint") or {}
    if rp:
        lines.append(f"Repository: {rp.get('repository')} branch={rp.get('branch')} commit={rp.get('commit_sha')}")
    for q in report.get("manager_questions") or []:
        lines.append(f"- {q}")
    for reason in report.get("recommendation_reasons") or []:
        lines.append(f"Reason: {reason}")
    return "\n".join(lines)


def _to_legacy_impact(report: dict, job: dict) -> dict[str, Any]:
    """Backward-compatible predeploy impact document."""
    art = (report.get("artifacts") or [{}])[0]
    validation = art.get("validation") or {}
    analysis = validation.get("analysis") or {}
    return {
        "version": report.get("version"),
        "type": "pre_deployment_impact_analysis",
        "created_at": report.get("created_at"),
        "job_id": job.get("job_id"),
        "role": job.get("role"),
        "primary_finding_id": report.get("primary_finding_id"),
        "focus_finding_ids": report.get("focus_finding_ids"),
        "finding_status": report.get("finding_status"),
        "scope": str((report.get("blast_radius") or {}).get("scope") or "resource").lower().replace("_", "-"),
        "discovery": {
            "summary": {"finding_status": report.get("finding_status")},
            "evidence": report.get("evidence") or [],
            "evidence_assessment": report.get("evidence_assessment"),
            "kind": report.get("domain"),
            "potentially_affected_workloads": "see change_assurance",
        },
        "terraform": {
            "validate": validation if art.get("artifact_type") == "terraform" else {"status": report.get("validation_status")},
            "plan": (analysis.get("plan") if analysis else {"status": report.get("validation_status"), "summary": {}, "destructive_actions": "NONE"}),
            "flags": (analysis.get("flags") if analysis else {}),
            "placeholders": analysis.get("placeholders") if analysis else [],
            "resources": analysis.get("resources") if analysis else [],
            "files": art.get("source_files") or [],
        },
        "blast_radius": report.get("blast_radius"),
        "readiness": {
            "recommendation": report.get("recommendation"),
            "deployment_ready": report.get("deployment_ready"),
            "reasons": report.get("recommendation_reasons"),
            "manager_approval_required": True,
        },
        "recommendation": report.get("recommendation"),
        "deployment_ready": report.get("deployment_ready"),
        "manager_approval_required": True,
        "auto_apply_forbidden": True,
        "verification": report.get("verification"),
        "report_text": report.get("report_text"),
        "confidence": "medium",
        "change_assurance": True,
        "validation_mode": report.get("validation_mode"),
        "repo_fingerprint": report.get("repo_fingerprint"),
        "approval_integrity": report.get("approval_integrity"),
        "cross_agent_review": report.get("cross_agent_review"),
            "evidence": report.get("evidence"),
            "evidence_assessment": report.get("evidence_assessment"),
            "evidence_quality": report.get("evidence_quality"),
            "evidence_registry_match": report.get("evidence_registry_match"),
            "relevant_artifacts": report.get("relevant_artifacts"),
            "relevant_placeholders": report.get("relevant_placeholders"),
            "sibling_placeholder_artifacts": report.get("sibling_placeholder_artifacts"),
            "job_fully_approvable": report.get("job_fully_approvable"),
            "artifact_scope": report.get("artifact_scope"),
        }


def persist_assurance(workspace: Path | str, report: dict[str, Any]) -> Path:
    workspace = Path(workspace)
    out = workspace / "assurance"
    out.mkdir(parents=True, exist_ok=True)
    # Also keep legacy impact path in sync
    impact_dir = workspace / "impact"
    impact_dir.mkdir(parents=True, exist_ok=True)
    job_id = str(report.get("job_id") or "unknown")
    path = out / f"{job_id}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = out / f"{job_id}.md"
    md.write_text(report.get("report_text") or "", encoding="utf-8")
    legacy = report.get("legacy_impact") or _to_legacy_impact(report, {"job_id": job_id, "role": report.get("role")})
    legacy_path = impact_dir / f"{job_id}.json"
    legacy_md = impact_dir / f"{job_id}.md"
    legacy["paths"] = {"json": str(legacy_path), "markdown": str(legacy_md)}
    legacy_path.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
    legacy_md.write_text(legacy.get("report_text") or report.get("report_text") or "", encoding="utf-8")
    report.setdefault("paths", {})
    report["paths"].update({"json": str(path), "markdown": str(md), "legacy_impact_json": str(legacy_path)})
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def load_or_assure(
    workspace: Path | str,
    job: dict[str, Any],
    findings: list[dict] | None = None,
    *,
    refresh: bool = False,
    try_terraform_cli: bool = False,
) -> dict[str, Any]:
    workspace = Path(workspace)
    job_id = str(job.get("job_id") or "")
    cached = workspace / "assurance" / f"{job_id}.json"
    report: dict[str, Any] | None = None
    if cached.is_file() and not refresh:
        try:
            report = json.loads(cached.read_text(encoding="utf-8-sig"))
            if assurance_cache_incomplete(report):
                report = None  # pre-EQ / incomplete cache — must re-collect
        except Exception:
            report = None
    if report is None:
        # Fall back to legacy impact cache (only if it already has evidence-quality)
        legacy = workspace / "impact" / f"{job_id}.json"
        if legacy.is_file() and not refresh:
            try:
                old = json.loads(legacy.read_text(encoding="utf-8-sig"))
                wrapped = empty_assurance_report(
                    job_id=job_id,
                    domain=domain_for_role(job.get("role")),
                    role=job.get("role"),
                )
                wrapped["legacy_impact"] = old
                wrapped["recommendation"] = old.get("recommendation") or "RECOMMEND_REVIEW"
                wrapped["finding_status"] = old.get("finding_status")
                wrapped["blast_radius"] = old.get("blast_radius") or wrapped["blast_radius"]
                wrapped["report_text"] = old.get("report_text") or ""
                wrapped["deployment_ready"] = old.get("deployment_ready")
                wrapped["evidence"] = old.get("evidence") or (old.get("discovery") or {}).get("evidence") or []
                wrapped["evidence_assessment"] = old.get("evidence_assessment")
                wrapped["evidence_quality"] = old.get("evidence_quality")
                if not assurance_cache_incomplete(wrapped):
                    report = wrapped
            except Exception:
                report = None
    if report is None or refresh:
        # Explicit refresh: drop stale on-disk artifacts so we never re-read them mid-flight
        if refresh:
            for p in (
                workspace / "assurance" / f"{job_id}.json",
                workspace / "assurance" / f"{job_id}.md",
                workspace / "impact" / f"{job_id}.json",
                workspace / "impact" / f"{job_id}.md",
            ):
                try:
                    if p.is_file():
                        p.unlink()
                except Exception:
                    pass
        report = assure_job(job, findings, try_terraform_cli=try_terraform_cli)
        persist_assurance(workspace, report)

    # Always re-check approval integrity against current artifacts + sealed binding
    sealed = approval_integrity.load_binding(workspace, job_id) or job.get("approval_binding")
    if sealed and sealed.get("status") == "APPROVED_FOR_EXECUTION":
        integrity = approval_integrity.validate_approval_binding(
            sealed,
            artifacts=report.get("artifacts") or [],
            target_environment=(report.get("artifacts") or [{}])[0].get("target_environment")
            if report.get("artifacts")
            else None,
            assurance_report=report,
            target_identity=report.get("target_identity"),
        )
        report["approval_integrity"] = integrity
        report["sealed_approval_binding"] = sealed
        if not integrity.get("valid"):
            report["approval_status"] = integrity.get("status")
            # Do not silently regenerate approval — mark invalidated on job if present
            if integrity.get("status") in {"APPROVAL_INVALIDATED", "REVALIDATION_REQUIRED"}:
                report["execution_authorized"] = False
        else:
            report["approval_status"] = "APPROVED_FOR_EXECUTION"
            report["execution_authorized"] = True
            report["execution_performed"] = False
    else:
        report.setdefault(
            "approval_integrity",
            {
                "integrity": "PENDING",
                "status": "PENDING_MANAGER_DECISION",
                "valid": False,
                "reason": "No sealed manager approval",
            },
        )
        report["execution_authorized"] = False
        report["execution_performed"] = False
    return report
