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

VERSION = "0.2.1-refresh"
# Bump when evidence/artifact/verification presentation logic changes — forces old-job rebind.
ANALYSIS_LOGIC_VERSION = "2026-08-20-plan-aware-v1"


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


def _evidence_api_calls(report: dict[str, Any]) -> list[str]:
    rows = list(report.get("evidence") or [])
    legacy = report.get("legacy_impact") if isinstance(report.get("legacy_impact"), dict) else {}
    if not rows:
        rows = list(legacy.get("evidence") or (legacy.get("discovery") or {}).get("evidence") or [])
    out: list[str] = []
    for e in rows:
        if not isinstance(e, dict):
            continue
        out.append(str(e.get("api_call") or e.get("source") or "").lower())
    return out


def assurance_bundle_stale_for_finding(
    report: dict[str, Any] | None,
    finding: dict[str, Any] | None,
    *,
    kit_path: str | None = None,
    focus_finding_id: str | None = None,
    job: dict[str, Any] | None = None,
) -> str | None:
    """
    Return a reason string when a persisted assurance/impact bundle must not be
    presented for this finding (wrong finding, missing preferred evidence,
    stale artifact generation, outdated analysis logic, missing reviewed plan).
    """
    if not isinstance(report, dict) or not report:
        return "missing_report"
    finding = finding or {}
    fid = str(focus_finding_id or finding.get("id") or "").strip()
    primary = str(report.get("primary_finding_id") or "").strip()
    if fid and primary and fid != primary:
        return f"primary_mismatch:{primary}!={fid}"
    if str(report.get("analysis_logic_version") or "") != ANALYSIS_LOGIC_VERSION:
        return "analysis_logic_version"

    # Reviewed Terraform plan bound on job but cache lacks plan-aware block → stale
    try:
        from change_assurance.plan_ingestion import resolve_reviewed_plan_ref

        ref = resolve_reviewed_plan_ref(job, fid) if job else None
        if ref:
            reviewed = report.get("reviewed_plan") or (
                (report.get("legacy_impact") or {}).get("reviewed_plan")
                if isinstance(report.get("legacy_impact"), dict)
                else None
            )
            if not isinstance(reviewed, dict) or not (reviewed.get("summary") or reviewed.get("resources_to_create")):
                return "missing_reviewed_plan_for_bound_finding"
            # Legacy stub strings must never win when a reviewed plan exists
            legacy = report.get("legacy_impact") if isinstance(report.get("legacy_impact"), dict) else {}
            workloads = str(
                ((legacy.get("discovery") or {}).get("potentially_affected_workloads"))
                or ((report.get("discovery") or {}).get("potentially_affected_workloads") if isinstance(report.get("discovery"), dict) else "")
                or ""
            )
            if "see change_assurance" in workloads.lower():
                return "legacy_see_change_assurance_with_reviewed_plan"
            deps = report.get("dependencies") or legacy.get("dependencies") or []
            if any(isinstance(d, dict) and str(d.get("type") or "").lower() == "none_detected" for d in deps):
                return "legacy_none_detected_with_reviewed_plan"
    except Exception:
        pass

    # Preferred evidence source for this control must be present when a registry spec matches
    try:
        from change_assurance.domains.cloud.evidence_registry import cloud_specs
        from change_assurance.evidence_quality import match_spec

        spec = match_spec(cloud_specs(), finding_id=fid or None, title=str(finding.get("title") or ""))
        if spec and spec.preferred_sources:
            apis = _evidence_api_calls(report)
            if apis and not any(
                any(pref.lower() in api for api in apis) for pref in spec.preferred_sources
            ):
                return f"missing_preferred_evidence:{spec.preferred_sources[0]}"
            # Cross-service proof in cache (e.g. CloudTrail proving Config) is always stale
            try:
                from change_assurance.evidence_quality import evidence_control_mismatch_reason

                for api in apis:
                    mismatch = evidence_control_mismatch_reason(spec, api)
                    if mismatch and any(
                        q == "DIRECT"
                        for q in (
                            str(e.get("quality") or "").upper()
                            for e in (
                                (report.get("evidence_assessment") or {}).get("labeled_evidence")
                                or report.get("evidence")
                                or []
                            )
                            if isinstance(e, dict)
                            and str(e.get("api_call") or e.get("source") or "").lower() == api
                        )
                    ):
                        return f"cross_service_evidence:{api}"
            except Exception:
                pass
    except Exception:
        pass

    # Artifact rebind: kit has terraform/{id}.tf but bundle still points at configs/{id}.conf
    if fid and kit_path:
        try:
            from predeploy.terraform_plan_analysis import (
                PLACEHOLDER_RE,
                resolve_finding_kit_artifacts,
                _read_kit_member_text,
            )

            scope = resolve_finding_kit_artifacts(kit_path, fid)
            tf_paths = [p for p in (scope.get("tf_paths") or []) if fid in p]
            relevant = list(
                report.get("relevant_artifacts")
                or ((report.get("legacy_impact") or {}).get("relevant_artifacts") if isinstance(report.get("legacy_impact"), dict) else None)
                or ((report.get("artifacts") or [{}])[0].get("source_files") if report.get("artifacts") else None)
                or []
            )
            relevant_l = [str(x).replace("\\", "/").lower() for x in relevant]
            if tf_paths and relevant_l:
                has_tf = any(any(t.lower() in r or r.endswith(t.lower().split("/")[-1]) for r in relevant_l) for t in tf_paths)
                has_conf_only = any(
                    (fid.lower() in r and r.endswith(".conf") and "/configs/" in r) for r in relevant_l
                ) and not has_tf
                if has_conf_only:
                    return "stale_conf_artifact_vs_tf"
            # TF has REPLACE_* but cache claims no placeholders → false NONE readiness
            cached_ph = (
                report.get("relevant_placeholders")
                or ((report.get("legacy_impact") or {}).get("relevant_placeholders") if isinstance(report.get("legacy_impact"), dict) else None)
                or []
            )
            if tf_paths and not cached_ph:
                for tp in tf_paths:
                    body = _read_kit_member_text(Path(kit_path), tp) if kit_path else None
                    if body and PLACEHOLDER_RE.search(body):
                        return "stale_missing_placeholder_scan"
        except Exception:
            pass

    # Verification plan must be control-specific when we have one
    try:
        from predeploy.post_deployment_verification import verification_plan_for_finding

        expected = verification_plan_for_finding(fid, finding.get("title") if finding else None)
        cached = report.get("verification") or (
            (report.get("legacy_impact") or {}).get("verification")
            if isinstance(report.get("legacy_impact"), dict)
            else None
        ) or {}
        exp_steps = " ".join(str(s) for s in (expected.get("steps") or [])).lower()
        got_steps = " ".join(str(s) for s in (cached.get("steps") or [])).lower()
        if exp_steps and "list_analyzers" in exp_steps and "list_analyzers" not in got_steps:
            return "stale_verification_plan"
        if exp_steps and "hands pack" in got_steps and "hands pack" not in exp_steps:
            return "stale_generic_verification"
    except Exception:
        pass

    return None


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
    focus_finding_id: str | None = None,
) -> dict[str, Any]:
    """
    Run shared change assurance for a Brain job.
    Never executes remediations. Recommendation != authorization.
    When focus_finding_id is set, that finding is the analysis primary (Manager Mode refresh).
    """
    findings = findings or []
    role = str(job.get("role") or "")
    domain = domain_for_role(role)
    report = empty_assurance_report(job_id=job.get("job_id"), domain=domain, role=role)
    report["analysis_logic_version"] = ANALYSIS_LOGIC_VERSION
    adapter = get_adapter(domain)
    report["capabilities"].append(adapter.capability_status())

    focus = _focus_findings(findings)
    primary = focus[0] if focus else {"id": "UNKNOWN", "title": "No findings", "severity": "info"}
    want = str(focus_finding_id or "").strip()
    if want:
        for f in findings:
            if str(f.get("id") or "") == want:
                primary = f
                break
    finding_id = str(primary.get("id") or "UNKNOWN")
    report["primary_finding_id"] = finding_id
    focus_ids = [str(f.get("id")) for f in focus if f.get("id")]
    if finding_id and finding_id not in focus_ids:
        focus_ids = [finding_id] + focus_ids
    report["focus_finding_ids"] = focus_ids
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
        "reviewed_plan": changes.get("reviewed_plan")
        or (changes.get("plan") or {}).get("reviewed_plan"),
        "diff_files": changes.get("diff_files") or [],
        "dependencies": changes.get("dependencies") or [],
    }
    deps = adapter.discover_dependencies(change_ctx, context)
    context["deps"] = deps
    impact = adapter.analyze_impact(change_ctx, {**context, "impact": None})
    risk = adapter.calculate_risk(change_ctx, {**context, "impact": impact})
    scope = adapter.classify_scope(change_ctx, context)
    reviewed_plan = change_ctx.get("reviewed_plan")
    if isinstance(reviewed_plan, dict) and reviewed_plan.get("region"):
        scope = f"REGIONAL:{reviewed_plan.get('region')}"
    questions = adapter.generate_manager_questions(primary, change_ctx, context)
    verification = adapter.build_verification_plan(primary, change_ctx, context)
    artifact["verification"] = verification
    artifact["dependencies"] = deps
    if isinstance(reviewed_plan, dict):
        report["reviewed_plan"] = {
            k: reviewed_plan.get(k)
            for k in (
                "finding_id",
                "source_artifact_path",
                "source_artifact_sha256",
                "saved_plan_path",
                "saved_plan_sha256",
                "plan_content_hash",
                "plan_generated_at",
                "account_id",
                "region",
                "execution_role",
                "execution_identity",
                "execution_profile",
                "summary",
                "destructive_actions",
                "resources_to_create",
                "resources_modified",
                "resources_destroyed",
                "resource_addresses",
                "cloudtrail_bucket_touched",
                "dependencies",
                "apply_time_considerations",
                "manager_affect",
                "risk",
                "binding_check",
                "invalidated",
                "invalidation_reasons",
                "execution_performed",
                "apply_forbidden",
                "status",
                "mode",
            )
        }
        if reviewed_plan.get("execution_identity"):
            report["target_identity"] = reviewed_plan.get("execution_identity")
        report["execution_role"] = reviewed_plan.get("execution_role")
        report["execution_identity"] = reviewed_plan.get("execution_identity")
        report["plan_review_status"] = (
            "PLAN_INVALIDATED"
            if reviewed_plan.get("invalidated")
            else "PLAN_REVIEWED"
        )
        report["artifact_validation_status"] = validation.get("status")
        # Align blast reasons with plan risk rationale
        if reviewed_plan.get("risk"):
            risk = dict(reviewed_plan["risk"])
            blast = dict(impact.get("blast_radius") or {})
            blast["level"] = risk.get("level") or blast.get("level")
            blast["reasons"] = list(risk.get("reasons") or blast.get("reasons") or [])
            blast["rationale"] = risk.get("rationale")
            if reviewed_plan.get("region"):
                blast["scope"] = f"REGIONAL:{reviewed_plan.get('region')}"
            impact["blast_radius"] = blast
            impact["workloads"] = (reviewed_plan.get("manager_affect") or {}).get(
                "potentially_affected"
            ) or impact.get("workloads")
        # Cross-control pre-deploy conflict analysis (S3 adapter first; generic registry)
        try:
            from change_assurance.control_conflicts import analyze_proposed_change

            src_tf = ""
            src_path = reviewed_plan.get("source_artifact_path") or artifact.get("path")
            if src_path:
                try:
                    from pathlib import Path as _P

                    p = _P(str(src_path))
                    if p.is_file():
                        src_tf = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    src_tf = ""
            if not src_tf:
                for body in (artifact.get("content"), (artifact.get("meta") or {}).get("body")):
                    if isinstance(body, str) and "resource" in body:
                        src_tf = body
                        break
            fe = (job.get("finding_execution") or {}).get(str(finding_id or "")) or {}
            existing = list(fe.get("succeeded_resources") or [])
            xctrl = analyze_proposed_change(
                reviewed_plan=reviewed_plan,
                source_terraform=src_tf,
                context={
                    "finding_id": finding_id,
                    "existing_resources": existing,
                    "expected_bucket_name": (
                        f"sentinel-aws-config-{job.get('aws_account_id')}-{job.get('region')}"
                        if job.get("aws_account_id") and job.get("region")
                        else None
                    ),
                    "bucket_tags": {
                        "SentinelPurpose": "aws-config-delivery",
                        "DoNotReuseForTrail": "true",
                    }
                    if str(finding_id or "").upper() in {"CLOUD-LOG-002", "AWS-014"}
                    else {},
                },
            )
            report["cross_control_impact"] = xctrl
            report["predicted_secondary_findings"] = xctrl.get("predicted_secondary_findings") or []
            report["remediation_fully_hardened"] = bool(xctrl.get("remediation_fully_hardened"))
            if xctrl.get("has_blocking_conflicts"):
                report["recommendation"] = "RECOMMEND_REVIEW"
                report["deployment_ready"] = False
                report["recommendation_reasons"] = list(report.get("recommendation_reasons") or []) + [
                    "CROSS_CONTROL_CONFLICTS_PREDICTED — proposed resources would fail other Sentinel controls"
                ]
        except Exception as xctrl_exc:
            report["cross_control_impact"] = {
                "error": str(xctrl_exc)[:300],
                "predicted_secondary_findings": [],
                "remediation_fully_hardened": False,
            }

    cross_hooks = []
    if domain == "devsecops" and hasattr(adapter, "cross_agent_review_hooks"):
        cross_hooks = adapter.cross_agent_review_hooks(change_ctx, context)  # type: ignore[attr-defined]

    report["artifacts"] = [artifact]
    report["dependencies"] = deps
    report["blast_radius"] = impact.get("blast_radius") or {"level": "UNKNOWN", "scope": scope}
    # Prefer plan-derived regional scope over generic scope labels
    if isinstance(reviewed_plan, dict) and reviewed_plan.get("region"):
        report["blast_radius"]["scope"] = f"REGIONAL:{reviewed_plan.get('region')}"
    else:
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
    # Prefer Terraform intended execution identity over repo commit when present
    if not report.get("target_identity"):
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
    report["remediation_status"] = rec.get("remediation_status") or (
        "PREREQUISITES_REQUIRED"
        if placeholders
        else ("READY" if report["deployment_ready"] else "NOT_READY")
    )
    report["execution_ready"] = bool(rec.get("execution_ready", report["deployment_ready"])) and not placeholders
    report["relevant_artifacts"] = validation.get("relevant_artifacts") or artifact_scope.get("paths") or files
    report["relevant_placeholders"] = validation.get("placeholders") or changes.get("placeholders") or []
    try:
        from change_assurance.prerequisites import manager_decision_prompt, prerequisites_from_placeholders
        from change_assurance.prerequisite_resolution import (
            CHOICE_CREATE_DEDICATED,
            get_decision,
            normalize_choice,
        )

        report["relevant_placeholders"] = validation.get("placeholders") or changes.get("placeholders") or []
        report["remediation_prerequisites"] = prerequisites_from_placeholders(report["relevant_placeholders"])
        decision = get_decision(job, finding_id)
        report["prerequisite_decision"] = decision
        resolutions = (job.get("prerequisite_resolutions") or {}).get(str(finding_id or "")) or {}
        report["prerequisite_resolution"] = resolutions or None
        if decision and normalize_choice(decision.get("choice")) == CHOICE_CREATE_DEDICATED and not placeholders:
            # Disk is source of truth — never trust metadata alone
            try:
                from change_assurance.artifact_persistence import (
                    CONFIG_DEDICATED_SIGNATURES,
                    FORBIDDEN_AFTER_DEDICATED,
                    verify_persisted_member,
                )

                kit = Path(str(job.get("kit_path") or ""))
                verify_persisted_member(
                    kit,
                    f"terraform/{finding_id}.tf",
                    required_signatures=CONFIG_DEDICATED_SIGNATURES,
                    forbid_tokens=FORBIDDEN_AFTER_DEDICATED,
                    require_no_placeholders=True,
                )
                report["prerequisite_manager_decision"] = "CREATE DEDICATED RESOURCES"
                report["remediation_status"] = "PREREQUISITES_RESOLVED"
            except Exception as persist_exc:
                report["prerequisite_manager_decision"] = manager_decision_prompt(
                    report["remediation_prerequisites"]
                )
                report["remediation_status"] = "PREREQUISITES_REQUIRED"
                report["recommendation"] = "REMEDIATION_PREREQUISITES_REQUIRED"
                report["deployment_ready"] = False
                report["execution_ready"] = False
                report["recommendation_reasons"] = list(report.get("recommendation_reasons") or []) + [
                    f"ARTIFACT_PERSISTENCE_MISMATCH: {persist_exc}"
                ]
                placeholders = True
        else:
            report["prerequisite_manager_decision"] = manager_decision_prompt(report["remediation_prerequisites"])
            if placeholders:
                report["remediation_status"] = "PREREQUISITES_REQUIRED"
        # Cost / prepare context from resolution metadata
        if resolutions:
            report["cost_note"] = resolutions.get("cost_note")
            report["required_remediation_role_permissions"] = resolutions.get(
                "required_remediation_role_permissions"
            )
            report["do_not_touch"] = resolutions.get("do_not_touch")
    except Exception:
        report["remediation_prerequisites"] = []
        report["prerequisite_manager_decision"] = None
        report["prerequisite_decision"] = None
    report["sibling_placeholder_artifacts"] = sibling_placeholders[:20]
    report["job_fully_approvable"] = (
        bool(rec.get("deployment_ready")) and not sibling_placeholders and not placeholders
    )
    report["artifact_scope"] = artifact_scope
    report["manager_approval_required"] = True
    report["auto_apply_forbidden"] = True
    report["execution_authorized"] = False
    report["execution_performed"] = False

    # Cross-job remediation lifecycle overlay (persistent ledger)
    # Do NOT mutate the job's reviewed plan here — reconcile happens at job create / Face load.
    try:
        from change_assurance.remediation_ledger import (
            STATUS_PARTIAL_EXECUTION,
            STATUS_RECOVERY_REQUIRED,
            assurance_overlay_from_record,
            key_for_control,
            load_record,
        )

        workspace = Path(str(job.get("_workspace") or "") or Path(__file__).resolve().parents[1] / "brain_workspace")
        if finding_id:
            key = key_for_control(job, str(finding_id))
            rec = load_record(workspace, key) if key else None
            if not rec and (job.get("remediation_lifecycle") or {}).get("lifecycle_key"):
                rec = load_record(workspace, str(job["remediation_lifecycle"]["lifecycle_key"]))
            # Prefer job-local projected lifecycle (already reconciled) over raw ledger file
            overlay = {}
            if (job.get("finding_execution") or {}).get(str(finding_id)) or job.get("remediation_lifecycle"):
                from change_assurance.remediation_ledger import (
                    EXECUTION_LABEL_PARTIAL,
                    INVALIDATION_PARTIAL,
                )

                fe = (job.get("finding_execution") or {}).get(str(finding_id)) or {}
                lifecycle = job.get("remediation_lifecycle") or {}
                pr = lifecycle.get("prerequisite_resources") or {}
                label_map = {
                    "aws_iam_service_linked_role.config": "AWS Config IAM role",
                    "aws_s3_bucket.config": "S3 delivery bucket (Config)",
                }
                existence = [
                    {
                        "address": addr,
                        "label": label_map.get(addr, addr),
                        "status": (row or {}).get("status"),
                        "evidence_quality": (row or {}).get("evidence_quality"),
                        "evidence_source": (row or {}).get("evidence_source"),
                        "identity": (row or {}).get("identity"),
                    }
                    for addr, row in pr.items()
                    if isinstance(row, dict)
                ]
                rem_state = str(
                    fe.get("status") or lifecycle.get("remediation_state") or STATUS_RECOVERY_REQUIRED
                )
                overlay = {
                    "lifecycle_key": lifecycle.get("lifecycle_key") or (rec or {}).get("lifecycle_key"),
                    "finding_execution": fe,
                    "remediation_lifecycle_state": rem_state,
                    "execution_status_label": fe.get("execution_status") or EXECUTION_LABEL_PARTIAL,
                    "recovery_plan_summary": fe.get("recovery_plan_summary") or {},
                    "recovery_plan_path": fe.get("recovery_plan_path"),
                    "recovery_plan_sha256": fe.get("recovery_plan_sha256"),
                    "prior_approval_valid": False,
                    "approval_invalidation_reason": INVALIDATION_PARTIAL,
                    "suppress_placeholder_prerequisites": True,
                    "prerequisite_manager_decision": "CREATE DEDICATED RESOURCES",
                    "remediation_prerequisites": [],
                    "relevant_placeholders": [],
                    "missing_prerequisite_labels": [],
                    "prerequisite_existence": existence,
                    "prerequisite_decision": (job.get("prerequisite_decisions") or {}).get(str(finding_id)),
                }
            elif rec and rec.get("remediation_state") in {
                STATUS_PARTIAL_EXECUTION,
                STATUS_RECOVERY_REQUIRED,
            }:
                # Ledger hit for same env/control — surface status without rewriting reviewed plans
                overlay = assurance_overlay_from_record(rec)
            if overlay:
                report["lifecycle_key"] = overlay.get("lifecycle_key")
                report["remediation_lifecycle_state"] = overlay.get("remediation_lifecycle_state")
                report["finding_execution"] = {
                    str(finding_id): overlay.get("finding_execution")
                }
                report["prerequisite_existence"] = overlay.get("prerequisite_existence")
                report["execution_status_label"] = overlay.get("execution_status_label")
                if overlay.get("suppress_placeholder_prerequisites"):
                    report["relevant_placeholders"] = []
                    report["remediation_prerequisites"] = []
                    report["missing_prerequisite_labels"] = []
                    placeholders = False
                    report["prerequisite_manager_decision"] = overlay.get(
                        "prerequisite_manager_decision"
                    ) or "CREATE DEDICATED RESOURCES"
                    if overlay.get("prerequisite_decision"):
                        report["prerequisite_decision"] = overlay["prerequisite_decision"]
                    if overlay.get("remediation_lifecycle_state") in {
                        STATUS_PARTIAL_EXECUTION,
                        STATUS_RECOVERY_REQUIRED,
                    }:
                        report["remediation_status"] = "RECOVERY_REQUIRED"
                        report["recommendation"] = "RECOMMEND_REVIEW"
                        report["execution_performed"] = True
                # Only attach recovery plan summary when job already bound a recovery plan
                # (do not clobber a different reviewed plan_json used in unit tests).
                plan_ref = ((job.get("reviewed_terraform_plans") or {}).get(str(finding_id)) or {})
                if overlay.get("recovery_plan_summary") and plan_ref.get("plan_kind") == "recovery":
                    report.setdefault("reviewed_plan", {})
                    if not isinstance(report.get("reviewed_plan"), dict):
                        report["reviewed_plan"] = {}
                    report["reviewed_plan"]["summary"] = overlay["recovery_plan_summary"]
                    report["reviewed_plan"]["saved_plan_path"] = overlay.get("recovery_plan_path")
                    report["reviewed_plan"]["saved_plan_sha256"] = overlay.get("recovery_plan_sha256")
                    report["reviewed_plan"]["plan_kind"] = "recovery"
    except Exception:
        pass

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
    ca_nested = {
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
        "finding_decisions": report.get("finding_decisions"),
        "primary_finding_id": report.get("primary_finding_id"),
        "finding_status": report.get("finding_status"),
        "blast_radius": report.get("blast_radius"),
        "artifacts": report.get("artifacts") or [],
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
        "reviewed_plan": report.get("reviewed_plan"),
        "plan_review_status": report.get("plan_review_status"),
        "artifact_validation_status": report.get("artifact_validation_status"),
        "cross_control_impact": report.get("cross_control_impact"),
        "predicted_secondary_findings": report.get("predicted_secondary_findings"),
        "remediation_fully_hardened": report.get("remediation_fully_hardened"),
        "finding_execution": report.get("finding_execution"),
        "remediation_lifecycle_state": report.get("remediation_lifecycle_state"),
        "prerequisite_existence": report.get("prerequisite_existence"),
        "suppress_placeholder_prerequisites": report.get("suppress_placeholder_prerequisites"),
        "execution_status_label": report.get("execution_status_label"),
    }
    return {
        "version": report.get("version"),
        "type": "pre_deployment_impact_analysis",
        "created_at": report.get("created_at"),
        "job_id": job.get("job_id"),
        "role": job.get("role"),
        "primary_finding_id": report.get("primary_finding_id"),
        "focus_finding_ids": report.get("focus_finding_ids"),
        "finding_status": report.get("finding_status"),
        "analysis_logic_version": report.get("analysis_logic_version"),
        "scope": str((report.get("blast_radius") or {}).get("scope") or "resource").lower().replace("_", "-"),
        "discovery": {
            "summary": {"finding_status": report.get("finding_status")},
            "evidence": report.get("evidence") or [],
            "evidence_assessment": report.get("evidence_assessment"),
            "kind": report.get("domain"),
            "potentially_affected_workloads": (
                ((report.get("reviewed_plan") or {}).get("manager_affect") or {}).get("potentially_affected")
                or (report.get("discovery_workloads") if report.get("discovery_workloads") else None)
                or (
                    "Creates AWS Config recording infrastructure in-region; does not modify "
                    "existing CloudTrail buckets or application workloads."
                    if str(report.get("primary_finding_id") or "").upper() in {"CLOUD-LOG-002", "AWS-016"}
                    else None
                )
                or "Review plan-scoped resources below before authorizing."
            ),
        },
        "terraform": {
            "validate": validation if art.get("artifact_type") == "terraform" else {"status": report.get("validation_status")},
            "plan": (
                {
                    **((analysis.get("plan") if analysis else None) or {}),
                    **(
                        {
                            "summary": (report.get("reviewed_plan") or {}).get("summary"),
                            "status": "REVIEWED_PLAN",
                            "reviewed_plan": report.get("reviewed_plan"),
                        }
                        if report.get("reviewed_plan")
                        else {}
                    ),
                }
                if art.get("artifact_type") == "terraform"
                else {"status": report.get("validation_status"), "summary": {}, "destructive_actions": "NONE"}
            ),
            "flags": (analysis.get("flags") if analysis else {}),
            "placeholders": analysis.get("placeholders") if analysis else [],
            "resources": analysis.get("resources") if analysis else [],
            "files": art.get("source_files") or [],
        },
        "reviewed_plan": report.get("reviewed_plan"),
        "plan_review_status": report.get("plan_review_status"),
        "dependencies": report.get("dependencies"),
        "remediation_risk": report.get("remediation_risk"),
        "region": ((report.get("reviewed_plan") or {}).get("region")),
        "blast_radius": report.get("blast_radius"),
        "cross_control_impact": report.get("cross_control_impact"),
        "predicted_secondary_findings": report.get("predicted_secondary_findings"),
        "remediation_fully_hardened": report.get("remediation_fully_hardened"),
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
        "change_assurance": ca_nested,
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
        "remediation_prerequisites": report.get("remediation_prerequisites"),
        "prerequisite_manager_decision": report.get("prerequisite_manager_decision"),
        "remediation_status": report.get("remediation_status"),
        "execution_ready": report.get("execution_ready"),
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
    focus_finding_id: str | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace)
    job_id = str(job.get("job_id") or "")
    findings = findings or []
    want = str(focus_finding_id or "").strip()
    focus_finding: dict[str, Any] | None = None
    if want:
        focus_finding = next((f for f in findings if str(f.get("id") or "") == want), None)
    if focus_finding is None and findings:
        focus_finding = _focus_findings(findings)[0] if findings else None
        want = str((focus_finding or {}).get("id") or "")

    cached = workspace / "assurance" / f"{job_id}.json"
    # Optional per-finding cache (refresh/rebinding for old multi-finding jobs)
    by_finding = workspace / "assurance" / "by_finding" / job_id / f"{want}.json" if want else None
    report: dict[str, Any] | None = None

    def _try_load(path: Path | None) -> dict[str, Any] | None:
        if not path or not path.is_file():
            return None
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return None
        if assurance_cache_incomplete(doc):
            return None
        stale = assurance_bundle_stale_for_finding(
            doc,
            focus_finding,
            kit_path=str(job.get("kit_path") or "") or None,
            focus_finding_id=want or None,
            job=job,
        )
        if stale:
            return None
        return doc

    if not refresh:
        report = _try_load(by_finding) or _try_load(cached)
    if report is None and not refresh:
        # Fall back to legacy impact cache (only if it already has evidence-quality)
        legacy = workspace / "impact" / f"{job_id}.json"
        if legacy.is_file():
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
                wrapped["primary_finding_id"] = old.get("primary_finding_id")
                wrapped["blast_radius"] = old.get("blast_radius") or wrapped["blast_radius"]
                wrapped["report_text"] = old.get("report_text") or ""
                wrapped["deployment_ready"] = old.get("deployment_ready")
                wrapped["evidence"] = old.get("evidence") or (old.get("discovery") or {}).get("evidence") or []
                wrapped["evidence_assessment"] = old.get("evidence_assessment")
                wrapped["evidence_quality"] = old.get("evidence_quality")
                wrapped["relevant_artifacts"] = old.get("relevant_artifacts")
                wrapped["verification"] = old.get("verification")
                wrapped["analysis_logic_version"] = old.get("analysis_logic_version")
                wrapped["artifact_scope"] = old.get("artifact_scope")
                if (
                    not assurance_cache_incomplete(wrapped)
                    and not assurance_bundle_stale_for_finding(
                        wrapped,
                        focus_finding,
                        kit_path=str(job.get("kit_path") or "") or None,
                        focus_finding_id=want or None,
                        job=job,
                    )
                ):
                    report = wrapped
            except Exception:
                report = None
    if report is None or refresh:
        # Explicit refresh: snapshot then drop stale on-disk artifacts (audit-friendly)
        if refresh:
            _snapshot_assurance_before_refresh(workspace, job_id)
            for p in (
                workspace / "assurance" / f"{job_id}.json",
                workspace / "assurance" / f"{job_id}.md",
                workspace / "impact" / f"{job_id}.json",
                workspace / "impact" / f"{job_id}.md",
                by_finding,
            ):
                try:
                    if p and Path(p).is_file():
                        Path(p).unlink()
                except Exception:
                    pass
        report = assure_job(
            job,
            findings,
            try_terraform_cli=try_terraform_cli,
            focus_finding_id=want or None,
        )
        persist_assurance(workspace, report)
        _persist_finding_assurance(workspace, job_id, want, report)

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


def _snapshot_assurance_before_refresh(workspace: Path, job_id: str) -> None:
    """Preserve prior assurance JSON for audit; does not touch Casebook records."""
    if not job_id:
        return
    src = workspace / "assurance" / f"{job_id}.json"
    if not src.is_file():
        return
    try:
        from change_assurance.models import now as _now

        stamp = str(_now()).replace(":", "").replace("-", "")
    except Exception:
        stamp = "snap"
    dest_dir = workspace / "assurance" / "snapshots" / job_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        dest = dest_dir / f"{stamp}.json"
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


def _persist_finding_assurance(
    workspace: Path,
    job_id: str,
    finding_id: str | None,
    report: dict[str, Any],
) -> None:
    fid = str(finding_id or report.get("primary_finding_id") or "").strip()
    if not job_id or not fid:
        return
    out = workspace / "assurance" / "by_finding" / job_id
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{fid}.json"
    try:
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception:
        pass
