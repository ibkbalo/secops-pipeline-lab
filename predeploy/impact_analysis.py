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
) -> dict[str, Any]:
    from change_assurance.engine import load_or_assure, persist_assurance

    report = load_or_assure(
        workspace,
        job,
        findings,
        refresh=refresh,
        try_terraform_cli=try_terraform_cli,
    )
    if report.get("type") == "change_assurance_report" and refresh:
        persist_assurance(workspace, report)
    legacy = report.get("legacy_impact")
    if legacy:
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
        }
        return legacy
    # Legacy-only cache wrap
    return analyze_job(job, findings, try_terraform_cli=try_terraform_cli)
