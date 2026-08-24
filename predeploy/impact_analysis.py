# predeploy/impact_analysis.py
# Backward-compatible wrapper around change_assurance engine.
# Legacy callers (Face, tests) keep working; Cloud remains mature path.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERSION = "0.2.0-ca"


def analyze_job(
    job: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    *,
    profile: str | None = None,
    region: str | None = None,
    try_terraform_cli: bool = False,
) -> dict[str, Any]:
    from change_assurance.engine import assure_job

    report = assure_job(
        job,
        findings,
        profile=profile,
        region=region,
        try_terraform_cli=try_terraform_cli,
    )
    legacy = report.get("legacy_impact") or {}
    # Ensure required legacy keys
    legacy.setdefault("type", "pre_deployment_impact_analysis")
    legacy.setdefault("recommendation", report.get("recommendation"))
    legacy.setdefault("manager_approval_required", True)
    legacy.setdefault("auto_apply_forbidden", True)
    legacy["change_assurance_report"] = {
        "domain": report.get("domain"),
        "recommendation": report.get("recommendation"),
        "validation_status": report.get("validation_status"),
        "manager_context_required": report.get("manager_context_required"),
        "approval_binding": report.get("approval_binding"),
    }
    return legacy


def persist_analysis(workspace: Path | str, doc: dict[str, Any]) -> Path:
    """Persist legacy impact doc; also write assurance if full report attached."""
    workspace = Path(workspace)
    from change_assurance.engine import persist_assurance

    # If caller passed a full assurance report, persist that.
    if doc.get("type") == "change_assurance_report":
        return persist_assurance(workspace, doc)

    out_dir = workspace / "impact"
    out_dir.mkdir(parents=True, exist_ok=True)
    job_id = str(doc.get("job_id") or "unknown")
    path = out_dir / f"{job_id}.json"
    md = out_dir / f"{job_id}.md"
    doc.setdefault("paths", {})["json"] = str(path)
    doc["paths"]["markdown"] = str(md)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    md.write_text(doc.get("report_text") or "", encoding="utf-8")
    return path


def load_or_analyze(
    workspace: Path | str,
    job: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    *,
    refresh: bool = False,
    try_terraform_cli: bool = False,
    focus_finding_id: str | None = None,
) -> dict[str, Any]:
    from change_assurance.engine import load_or_assure, persist_assurance

    report = load_or_assure(
        workspace,
        job,
        findings,
        refresh=refresh,
        try_terraform_cli=try_terraform_cli,
        focus_finding_id=focus_finding_id,
    )
    if report.get("type") == "change_assurance_report" and refresh:
        persist_assurance(workspace, report)
    legacy = report.get("legacy_impact")
    if legacy:
        # Always rebind nested change_assurance from the live report (never leave a bool/stale nest)
        legacy["change_assurance"] = {
            "domain": report.get("domain"),
            "recommendation": report.get("recommendation"),
            "recommendation_reasons": report.get("recommendation_reasons"),
            "manager_context_required": report.get("manager_context_required"),
            "manager_questions": report.get("manager_questions"),
            "validation_status": report.get("validation_status"),
            "validation_mode": report.get("validation_mode"),
            "remediation_risk": report.get("remediation_risk"),
            "repo_fingerprint": report.get("repo_fingerprint"),
            "approval_integrity": report.get("approval_integrity"),
            "approval_status": report.get("approval_status"),
            "sealed_approval_binding": report.get("sealed_approval_binding"),
            "cross_agent_review": report.get("cross_agent_review"),
            "finding_decisions": report.get("finding_decisions") or job.get("finding_decisions"),
            "manager_decision": job.get("manager_decision"),
            "primary_finding_id": report.get("primary_finding_id"),
            "finding_status": report.get("finding_status"),
            "blast_radius": report.get("blast_radius"),
            "artifacts": [
                {
                    "artifact_id": a.get("artifact_id"),
                    "artifact_type": a.get("artifact_type"),
                    "artifact_hash": a.get("artifact_hash"),
                    "source_files": a.get("source_files"),
                    "diff_files": a.get("diff_files"),
                    "dependency_updates": a.get("dependency_updates"),
                    "meta": a.get("meta"),
                }
                for a in (report.get("artifacts") or [])
            ],
            "approval_binding": report.get("approval_binding"),
            "dependencies": report.get("dependencies"),
            "verification": report.get("verification"),
            "evidence": report.get("evidence"),
            "evidence_assessment": report.get("evidence_assessment"),
            "evidence_quality": report.get("evidence_quality"),
            "evidence_registry_match": report.get("evidence_registry_match"),
            "relevant_artifacts": report.get("relevant_artifacts"),
            "relevant_placeholders": report.get("relevant_placeholders"),
            "remediation_prerequisites": report.get("remediation_prerequisites"),
            "prerequisite_manager_decision": report.get("prerequisite_manager_decision"),
            "prerequisite_decision": report.get("prerequisite_decision"),
            "prerequisite_resolution": report.get("prerequisite_resolution"),
            "remediation_status": report.get("remediation_status"),
            "execution_ready": report.get("execution_ready"),
            "cost_note": report.get("cost_note"),
            "do_not_touch": report.get("do_not_touch"),
            "required_remediation_role_permissions": report.get("required_remediation_role_permissions"),
            "sibling_placeholder_artifacts": report.get("sibling_placeholder_artifacts"),
            "job_fully_approvable": report.get("job_fully_approvable"),
            "artifact_scope": report.get("artifact_scope"),
            "analysis_logic_version": report.get("analysis_logic_version"),
            "cross_control_impact": report.get("cross_control_impact"),
            "predicted_secondary_findings": report.get("predicted_secondary_findings"),
            "remediation_fully_hardened": report.get("remediation_fully_hardened"),
            "reviewed_plan": report.get("reviewed_plan"),
            "finding_execution": report.get("finding_execution"),
            "remediation_lifecycle_state": report.get("remediation_lifecycle_state"),
            "prerequisite_existence": report.get("prerequisite_existence"),
            "suppress_placeholder_prerequisites": report.get("suppress_placeholder_prerequisites"),
            "execution_status_label": report.get("execution_status_label"),
        }
        # Keep top-level mirrors in sync for Manager Mode consumers
        for key in (
            "primary_finding_id",
            "finding_status",
            "evidence",
            "evidence_assessment",
            "evidence_quality",
            "relevant_artifacts",
            "relevant_placeholders",
            "remediation_prerequisites",
            "prerequisite_manager_decision",
            "prerequisite_decision",
            "prerequisite_resolution",
            "remediation_status",
            "execution_ready",
            "cost_note",
            "do_not_touch",
            "required_remediation_role_permissions",
            "verification",
            "analysis_logic_version",
            "artifact_scope",
            "recommendation",
            "deployment_ready",
            "cross_control_impact",
            "predicted_secondary_findings",
            "remediation_fully_hardened",
            "reviewed_plan",
            "finding_execution",
            "remediation_lifecycle_state",
            "prerequisite_existence",
            "suppress_placeholder_prerequisites",
            "execution_status_label",
        ):
            if report.get(key) is not None:
                legacy[key] = report.get(key)
        return legacy
    # Legacy-only cache wrap
    return analyze_job(job, findings, try_terraform_cli=try_terraform_cli)
