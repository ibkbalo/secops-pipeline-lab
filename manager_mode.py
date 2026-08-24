# manager_mode.py
# Face presentation layer — plain-English Manager Mode.
# Does NOT change Change Assurance safety, hashes, adapters, or execution rules.
# Recommendation != authorization. Approval != deployment.

from __future__ import annotations

from pathlib import Path
from typing import Any

VERSION = "0.2.0-mx1"

AGENT_TITLES = {
    "cloud": "Cloud Security Engineer",
    "devsecops": "DevSecOps Engineer",
    "security-engineer": "Senior Security Engineer",
    "ai-security": "AI Security Engineer",
}

REC_LABELS = {
    "RECOMMEND_APPROVE": "APPROVE",
    "RECOMMEND_REVIEW": "REVIEW WITH MANAGER",
    "RECOMMEND_REJECT": "DO NOT APPLY",
    "REMEDIATION_PREREQUISITES_REQUIRED": "PREREQUISITES REQUIRED",
    "NO_ACTION_REQUIRED": "NO ACTION NEEDED",
    "approve": "APPROVE",
    "review": "REVIEW WITH MANAGER",
    "reject": "DO NOT APPLY",
    "investigate": "REVIEW WITH MANAGER",
}

INTEGRITY_PLAIN = {
    "ARTIFACT_CHANGED": "The proposed fix changed after you approved it. Please review the updated change before approving again.",
    "PLAN_CHANGED": "The change plan changed after you approved it. Please review again.",
    "DIFF_CHANGED": "The code diff changed after this remediation was reviewed.",
    "COMMIT_CHANGED": "The source code changed after this remediation was reviewed.",
    "ENVIRONMENT_CHANGED": "The target environment changed after approval.",
    "TARGET_CHANGED": "The target system or identity changed after approval.",
    "ASSURANCE_REPORT_CHANGED": "The impact analysis changed after approval. Please re-review.",
    "LIVE_STATE_CHANGED": "The live environment may have drifted since approval. Revalidation is needed.",
    "DEPENDENCY_CHANGED": "Related dependencies changed after approval.",
    "RECOMMENDATION_CHANGED": "The AI recommendation changed after approval. Please re-review.",
    "PARTIAL_EXECUTION_CHANGED_STATE": (
        "Terraform execution partially succeeded and then failed, so live infrastructure "
        "changed. The previous approval is no longer valid — review the recovery plan."
    ),
    "SOURCE_ARTIFACT_CHANGED": "The Terraform source artifact changed after approval.",
    "SOURCE_ARTIFACT_CHANGED_AFTER_CROSS_CONTROL_ANALYSIS": (
        "The Terraform source was regenerated after cross-control analysis (e.g. S3 versioning). "
        "The prior recovery plan is stale — a new plan must be generated and reviewed."
    ),
    "ACCOUNT_MISMATCH": "The AWS account for this plan no longer matches the approved target.",
    "REGION_MISMATCH": "The AWS region for this plan no longer matches the approved target.",
    "EXECUTION_ROLE_CHANGED": "The intended execution role changed after approval.",
}

LEARNING_HINTS: dict[str, dict[str, str]] = {
    "CLOUD-STO": {
        "technology": "Amazon S3 stores files (objects) in the cloud.",
        "concept": "Preventive control — Block Public Access",
        "learning": (
            "AWS S3 Block Public Access prevents buckets from accidentally becoming "
            "internet-accessible, even if a later policy mistake tries to open them."
        ),
        "before_approve": (
            "Confirm whether any application intentionally needs directly public S3 access. "
            "If not, enabling account-level protections is usually safe."
        ),
        "why_engineer": (
            "Cloud Security Engineers treat accidental public storage as a top exposure risk "
            "because a single misconfiguration can leak data at scale."
        ),
    },
    "CLOUD-LOG": {
        "technology": "AWS CloudTrail records API activity across your account.",
        "concept": "Detective control — audit logging",
        "learning": "Without reliable logging, you cannot investigate who changed what — or prove compliance.",
        "before_approve": "Confirm logging destinations and retention meet your retention policy.",
        "why_engineer": "Without CloudTrail, incident response and forensics are severely limited.",
    },
    "CLOUD-IAM-013": {
        "technology": "AWS IAM Access Analyzer evaluates resource policies for external access.",
        "concept": "Detective control — external access analysis",
        "learning": (
            "Without an ACTIVE ACCOUNT analyzer in the Region, external-access paths are not "
            "continuously analyzed. Absence of an analyzer does not by itself prove a breach."
        ),
        "before_approve": (
            "Confirm the intended Region and that this creates a monitoring/analyzer resource — "
            "it does not change existing IAM permissions or resource policies."
        ),
        "why_engineer": (
            "Cloud Security Engineers enable Access Analyzer so unexpected cross-account or "
            "public grants are visible before they become incidents."
        ),
    },
    "CLOUD-IAM": {
        "technology": "AWS IAM controls who can do what in your cloud account.",
        "concept": "Least privilege",
        "learning": "Overly broad permissions increase blast radius if credentials are abused.",
        "before_approve": "Confirm break-glass and production roles will still work after the change.",
        "why_engineer": "Identity mistakes often enable the largest cloud breaches.",
    },
    "DEVSEC-SCA": {
        "technology": "Software dependencies (libraries your app imports).",
        "concept": "Supply-chain / dependency risk",
        "learning": "Vulnerable packages can introduce known exploits into your application.",
        "before_approve": "Ask whether the upgraded package is used in production and if APIs changed.",
        "why_engineer": "DevSecOps Engineers track dependency CVEs because attackers scan for known vulnerable versions.",
    },
    "DEVSEC-CICD": {
        "technology": "CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).",
        "concept": "Pipeline privilege",
        "learning": "Over-privileged pipelines can deploy, push secrets, or modify production unintentionally.",
        "before_approve": "Confirm the permission is required for deployment and who can trigger the workflow.",
        "why_engineer": "CI/CD is a high-value attack path — it often holds production credentials.",
    },
    "DEVSEC-DOCKER": {
        "technology": "Docker container images",
        "concept": "Container hardening",
        "learning": "Images running as root or copying secrets increase compromise impact.",
        "before_approve": "Confirm the app does not require root and secrets are injected at runtime, not baked in.",
        "why_engineer": "Container misconfiguration turns a single image into a portable risk.",
    },
    "DEVSEC-K8S": {
        "technology": "Kubernetes workloads and policies",
        "concept": "Workload / cluster privilege",
        "learning": "Privileged pods and broad RBAC can escalate from one workload to the whole cluster.",
        "before_approve": "Confirm which namespaces and service accounts are affected.",
        "why_engineer": "Cluster-scoped mistakes can impact every application on the platform.",
    },
    "DEVSEC-SEC": {
        "technology": "Source code and configuration secrets",
        "concept": "Secret hygiene",
        "learning": "Hardcoded credentials in repos are durable and often copied into logs and images.",
        "before_approve": "Confirm rotation plan and that the secret will not remain in git history.",
        "why_engineer": "Leaked secrets are one of the fastest paths to account takeover.",
    },
    "AISEC": {
        "technology": "AI agents, models, and tool connectors",
        "concept": "AI tool / data access control",
        "learning": "AI systems with write tools or broad retrieval can act beyond intended scope.",
        "before_approve": "Confirm the tool is required for an approved business workflow.",
        "why_engineer": "AI Security Engineers reduce the chance that model actions cause real-world harm.",
    },
    "PERIM": {
        "technology": "Enterprise security controls (identity, network, perimeter)",
        "concept": "Defense-in-depth",
        "learning": "Security Engineering closes gaps attackers commonly use for initial access or privilege abuse.",
        "before_approve": "Confirm the control will not lock out required users or services.",
        "why_engineer": "Senior Security Engineers balance risk reduction against operational continuity.",
    },
}


def agent_title(role: str | None) -> str:
    return AGENT_TITLES.get(str(role or "").strip().lower(), str(role or "Security Agent"))


def _artifact_contains_versioning(job: dict[str, Any] | None, finding: dict[str, Any] | None) -> bool:
    """True when the persisted dedicated TF for this finding includes S3 versioning."""
    try:
        fid = str((finding or {}).get("id") or "")
        res = ((job or {}).get("prerequisite_resolutions") or {}).get(fid) or {}
        path = Path(str(res.get("artifact_path") or ""))
        if not path.is_file():
            # Fall back to kit companion
            kit = Path(str((job or {}).get("kit_path") or ""))
            cand = (kit.with_suffix("") if kit.suffix.lower() == ".zip" else kit) / "terraform" / f"{fid}.tf"
            path = cand if cand.is_file() else path
        if not path.is_file():
            return False
        body = path.read_text(encoding="utf-8", errors="ignore")
        return 'resource "aws_s3_bucket_versioning"' in body and "Enabled" in body
    except Exception:
        return False


def translate_recommendation(raw: str | None) -> str:
    if not raw:
        return "REVIEW WITH MANAGER"
    key = str(raw).strip()
    if key in REC_LABELS:
        return REC_LABELS[key]
    upper = key.upper()
    if upper in REC_LABELS:
        return REC_LABELS[upper]
    if upper.startswith("RECOMMEND_"):
        return REC_LABELS.get(upper, upper.replace("RECOMMEND_", "").replace("_", " "))
    return key.upper().replace("_", " ")


def manager_decision_label(job: dict[str, Any] | None, finding: dict[str, Any] | None = None) -> str:
    job = job or {}
    fid = str((finding or {}).get("id") or "")
    decisions = job.get("finding_decisions") or {}
    if fid and str(decisions.get(fid) or "").lower() in {"pending_recovery", "pending"}:
        return "PENDING"
    if job.get("approval_status") == "APPROVAL_INVALIDATED" and fid:
        if str(decisions.get(fid) or "").lower() in {"pending_recovery", "pending", ""}:
            return "PENDING"
        # Do not show APPROVED when approval was invalidated after partial execution
        if (job.get("finding_execution") or {}).get(fid):
            return "PENDING"
    status = str(job.get("status") or "")
    decision = str(job.get("manager_decision") or "")
    if status == "pending_approval" or not decision:
        return "PENDING"
    if decision in {"approved", "approve"} or status == "approved":
        return "APPROVED"
    if decision in {"rejected", "reject"} or status == "rejected":
        return "REJECTED"
    if status == "partially_approved" or decision == "partial":
        return "PARTIAL — NOT FULLY APPROVED"
    return decision.upper() or status.upper() or "PENDING"


def execution_label(job: dict[str, Any] | None, impact: dict[str, Any] | None = None) -> str:
    job = job or {}
    # Prefer per-finding recovery / partial-execution state from impact or job
    fe = None
    if isinstance(impact, dict):
        fe = impact.get("finding_execution") or (impact.get("change_assurance") or {}).get(
            "finding_execution"
        )
    fid = None
    if isinstance(impact, dict):
        fid = impact.get("primary_finding_id") or (impact.get("change_assurance") or {}).get(
            "primary_finding_id"
        )
    if isinstance(fe, dict) and fid and isinstance(fe.get(str(fid)), dict):
        fe = fe.get(str(fid))
    elif isinstance(fe, dict) and fe.get("execution_status"):
        pass
    elif job and fid:
        fe = (job.get("finding_execution") or {}).get(str(fid))
    if isinstance(fe, dict) and fe.get("execution_status"):
        return str(fe["execution_status"])
    if job.get("apply_status") in {"partial_failed", "partial"}:
        return "PARTIAL EXECUTION — RECOVERY REQUIRED"
    if job.get("execution_performed") is True and job.get("approval_status") == "APPROVAL_INVALIDATED":
        return "PARTIAL EXECUTION — RECOVERY REQUIRED"
    if job.get("execution_performed") is True:
        return "PERFORMED"
    # Safety: even if authorized, Face Manager Mode always stresses not performed unless explicitly set
    return "NOT PERFORMED"


def integrity_plain_english(integrity: dict[str, Any] | None) -> dict[str, Any]:
    integrity = integrity or {}
    status = str(integrity.get("status") or integrity.get("integrity") or "PENDING")
    reasons = list(integrity.get("reasons") or [])
    if not reasons and integrity.get("reason"):
        # may be semicolon-joined
        reasons = [r.strip() for r in str(integrity.get("reason")).split(";") if r.strip()]

    if status in {"BINDING_VALID", "VALID"} or integrity.get("valid") is True:
        return {
            "headline": "APPROVAL STILL VALID",
            "message": "The approved change has not changed since you reviewed it.",
            "needs_review": False,
            "technical_reasons": reasons,
            "status": status,
        }
    if status in {"APPROVAL_INVALIDATED", "INVALIDATED"} or integrity.get("integrity") == "INVALIDATED":
        plain_bits = [INTEGRITY_PLAIN.get(r, r) for r in reasons] or [
            "The proposed fix changed after you approved it. Please review again."
        ]
        return {
            "headline": "APPROVAL NEEDS REVIEW",
            "message": plain_bits[0],
            "needs_review": True,
            "technical_reasons": reasons,
            "status": status,
        }
    if status in {"REVALIDATION_REQUIRED"} or integrity.get("integrity") == "REVALIDATION_REQUIRED":
        plain_bits = [INTEGRITY_PLAIN.get(r, r) for r in reasons] or [
            "Something meaningful may have changed. Please revalidation is required before relying on this approval."
        ]
        return {
            "headline": "REVALIDATION REQUIRED",
            "message": plain_bits[0],
            "needs_review": True,
            "technical_reasons": reasons,
            "status": status,
        }
    return {
        "headline": "AWAITING YOUR DECISION",
        "message": "No manager authorization has been sealed for this change yet.",
        "needs_review": False,
        "technical_reasons": reasons,
        "status": status or "PENDING",
    }


def _plain_title(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or "Security issue").strip()
    # Strip leading control IDs if embedded
    fid = str(finding.get("id") or "")
    if fid and title.upper().startswith(fid.upper()):
        title = title[len(fid) :].lstrip(" :-—")
    return title or "Security issue"


def _evidence_proof_block(impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> dict[str, Any] | None:
    assessment = (ca or {}).get("evidence_assessment") or (impact or {}).get("evidence_assessment") or {}
    # Prefer assessment; if missing, synthesize from labeled/raw evidence (DIRECT over INDIRECT)
    raw_evidence = (
        (assessment.get("labeled_evidence") if assessment else None)
        or (ca or {}).get("evidence")
        or (impact or {}).get("evidence")
        or ((impact or {}).get("discovery") or {}).get("evidence")
        or []
    )
    if not assessment and not raw_evidence:
        return None

    def _src(e: dict) -> str:
        return str(e.get("api_call") or e.get("source") or "")

    direct_items = [
        e
        for e in (assessment.get("labeled_evidence") or raw_evidence or [])
        if str(e.get("quality") or "").upper() == "DIRECT"
    ][:3]
    if not direct_items and raw_evidence:
        # Prefer password-policy / preferred live APIs over account summary
        preferred_order = (
            "describe_configuration_recorder",
            "configservice",
            "list_analyzers",
            "accessanalyzer",
            "password_policy",
            "get_public_access_block",
            "describe_trails",
            "describe_security_groups",
            "get_account_summary",
        )
        ranked = sorted(
            [e for e in raw_evidence if isinstance(e, dict)],
            key=lambda e: next(
                (i for i, token in enumerate(preferred_order) if token in _src(e).lower()),
                99,
            ),
        )
        if ranked and "get_account_summary" not in _src(ranked[0]).lower():
            direct_items = ranked[:1]

    indirect_items = [
        e
        for e in (assessment.get("labeled_evidence") or raw_evidence or [])
        if str(e.get("quality") or "").upper() == "INDIRECT"
        or (
            not e.get("quality")
            and "get_account_summary" in _src(e).lower()
            and e not in direct_items
        )
    ][:3]

    summary = (assessment or {}).get("manager_summary") or {}
    quality = assessment.get("evidence_quality") or (
        "DIRECT" if direct_items else ("INDIRECT" if indirect_items else "")
    )
    status = assessment.get("finding_status") or (impact or {}).get("finding_status") or ""
    observed = summary.get("observed") if summary.get("observed") is not None else assessment.get("observed")
    expected = summary.get("expected") if summary.get("expected") is not None else assessment.get("expected")
    result = summary.get("result") or assessment.get("result")
    source = summary.get("evidence_source") or assessment.get("evidence_source")
    label = summary.get("human_label") or assessment.get("human_label") or "Control property"

    if observed is None and direct_items:
        observed = direct_items[0].get("observed_value")
    if expected is None and direct_items:
        expected = direct_items[0].get("expected_value")
    if not source and direct_items:
        source = _src(direct_items[0])

    # Prefer human-readable observed when collectors provide it
    if isinstance(observed, dict) and observed.get("human_observed"):
        observed_fmt = str(observed.get("human_observed"))
    else:
        observed_fmt = None

    def _fmt(val: Any) -> str:
        if val is None:
            return "—"
        if isinstance(val, dict):
            if val.get("human_observed"):
                return str(val.get("human_observed"))
            if len(val) == 1:
                k, v = next(iter(val.items()))
                return f"{k}: {v}"
            return ", ".join(f"{k}: {v}" for k, v in val.items())
        return str(val)

    source_labels = {
        "accessanalyzer.list_analyzers": "AWS IAM Access Analyzer",
        "iam.get_account_password_policy": "AWS IAM password policy",
        "iam.get_account_summary": "AWS IAM account summary",
    }
    source_display = source_labels.get(str(source or ""), source or "—")

    insufficient = quality in {"INSUFFICIENT", "UNAVAILABLE"} or status == "UNVERIFIED"
    return {
        "insufficient": insufficient,
        "headline": summary.get("headline")
        or ("EVIDENCE INSUFFICIENT" if insufficient else "EVIDENCE"),
        "message": summary.get("message")
        or (
            "The current evidence does not directly prove this security finding."
            if insufficient
            else assessment.get("reason")
        ),
        "quality": quality,
        "finding_status": status,
        "observed_label": label,
        "observed": observed_fmt if observed_fmt is not None else _fmt(observed),
        "expected": _fmt(expected),
        "result": result or "—",
        "evidence_source": source_display,
        "evidence_source_raw": source or "—",
        "direct_items": direct_items,
        "indirect_items": indirect_items,
    }


def _what_found(finding: dict[str, Any], role: str) -> str:
    desc = str(finding.get("description") or "").strip()
    if desc:
        # Prefer first 2 sentences, plain
        parts = desc.replace("\n", " ").split(". ")
        text = ". ".join(parts[:2]).strip()
        if text and not text.endswith("."):
            text += "."
        return text
    return f"The {agent_title(role)} reported: {_plain_title(finding)}."


def _why_matters(finding: dict[str, Any], impact: dict[str, Any] | None) -> str:
    sev = str(finding.get("severity") or "info").lower()
    status = str((impact or {}).get("finding_status") or "")
    # Never claim active exposure unless evidence says so
    exposure_claim = False
    disc = (impact or {}).get("discovery") or {}
    summary = disc.get("summary") or {}
    if int(summary.get("public_buckets") or 0) > 0:
        exposure_claim = True
        return (
            "Evidence indicates one or more resources may currently allow public access. "
            "This elevates urgency — confirm exposure scope and remediate carefully."
        )
    base = {
        "critical": "This creates significant security risk if left unresolved.",
        "high": "This creates meaningful security risk if left unresolved.",
        "medium": "This creates moderate security risk over time.",
        "low": "This is a lower-priority hardening gap, but still worth closing.",
        "info": "This is informational context for your security posture.",
    }.get(sev, "This creates security risk if left unresolved.")
    caution = (
        " This creates risk — it does not by itself prove your data is currently exposed."
        if not exposure_claim
        else ""
    )
    if status == "ALREADY_REMEDIATED":
        return "Live checks suggest this control may already be fixed. Confirm before spending more effort."
    # Finding-specific hints
    fid = str(finding.get("id") or "").upper()
    if "STO" in fid or "S3" in fid or "public" in str(finding.get("title") or "").lower():
        return (
            "If storage is accidentally configured as public, sensitive files could become "
            "accessible from the internet." + caution
        )
    if "CICD" in fid or "pipeline" in str(finding.get("title") or "").lower():
        return (
            "Over-privileged pipelines can change production systems or expose credentials "
            "if a workflow is abused." + caution
        )
    if "SECRET" in fid or "hardcoded" in str(finding.get("title") or "").lower():
        return "Secrets in source or images can be copied, logged, or reused by attackers." + caution
    if "DOCKER" in fid or "container" in str(finding.get("title") or "").lower():
        return "Weak container settings increase the impact if the container is compromised." + caution
    if "K8S" in fid or "kubernetes" in str(finding.get("title") or "").lower():
        return "Privileged Kubernetes settings can expand a compromise beyond a single workload." + caution
    return base + caution


def _what_change(finding: dict[str, Any], impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> str:
    title_l = str(finding.get("title") or "").lower()
    region = (
        str(((finding.get("resource") or {}).get("region") or "")).strip()
        or str(((impact or {}).get("region") or "")).strip()
        or str((((impact or {}).get("discovery") or {}).get("region") or "")).strip()
        or "us-east-1"
    )
    if "access analyzer" in title_l:
        return f"Create an account-level IAM Access Analyzer in {region}."
    steps = (finding.get("remediation") or {}).get("steps") or []
    if steps:
        # Outcome-first: use first step as plain outcome when short
        first = str(steps[0]).strip()
        if len(first) < 180:
            return first
        return first[:177] + "…"
    art = ((ca or {}).get("artifacts") or [{}])[0] if ca else {}
    atype = str(art.get("artifact_type") or "")
    deps = art.get("dependency_updates") or []
    if deps:
        d0 = deps[0]
        old_v = d0.get("old_version") or "?"
        new_v = d0.get("new_version") or "?"
        return f"Update dependency {d0.get('package')} from {old_v} to {new_v}."
    if atype == "terraform":
        return "Apply the proposed cloud configuration change that closes this control gap."
    if atype in {"github_actions", "cicd_config"}:
        return "Tighten CI/CD permissions or workflow settings so the pipeline follows least privilege."
    if atype == "dockerfile":
        return "Harden the container image configuration (user, secrets, and base image practices)."
    if atype in {"kubernetes", "helm"}:
        return "Adjust the Kubernetes manifest so workloads run with safer privileges and policies."
    if atype in {"source_code_patch", "dependency_update"}:
        return "Apply the proposed code or dependency fix that addresses this finding."
    title = _plain_title(finding)
    return f"Remediate: {title}."


def _affect_summary(impact: dict[str, Any] | None, ca: dict[str, Any] | None, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    blast = (impact or {}).get("blast_radius") or (ca or {}).get("blast_radius") or {}
    scope = str(blast.get("scope") or (impact or {}).get("scope") or "UNKNOWN").replace("_", " ").title()
    level = str(blast.get("level") or "UNKNOWN")
    title_l = str((finding or {}).get("title") or "").lower()
    reviewed = (
        (ca or {}).get("reviewed_plan")
        or (impact or {}).get("reviewed_plan")
        or ((impact or {}).get("terraform") or {}).get("plan", {}).get("reviewed_plan")
    )
    if isinstance(reviewed, dict) and reviewed.get("manager_affect"):
        ma = reviewed["manager_affect"]
        risk = reviewed.get("risk") or (ca or {}).get("remediation_risk") or {}
        return {
            "scope": ma.get("scope") or scope,
            "blast_level": (risk.get("level") if isinstance(risk, dict) else level) or level,
            "level": (risk.get("level") if isinstance(risk, dict) else level) or level,
            "potentially_affected": ma.get("potentially_affected") or ma.get("summary_line"),
            "expected_downtime": ma.get("expected_downtime") or "None expected for existing workloads.",
            "known_dependencies": ma.get("known_dependencies") or [],
            "unknowns": ma.get("unknowns") or [],
            "potential_issue": (risk.get("rationale") if isinstance(risk, dict) else None)
            or ma.get("summary_line"),
            "summary_line": ma.get("summary_line") or ma.get("potentially_affected"),
            "plan_create": ma.get("plan_create"),
            "plan_modify": ma.get("plan_modify"),
            "plan_destroy": ma.get("plan_destroy"),
            "resources_to_create": ma.get("resources_to_create") or [],
            "resources_modified": ma.get("resources_modified") or ["NONE"],
            "resources_destroyed": ma.get("resources_destroyed") or ["NONE"],
            "cloudtrail_bucket": ma.get("cloudtrail_bucket") or "NOT TOUCHED",
            "risk_rationale": (risk.get("rationale") if isinstance(risk, dict) else None),
            "detail_lines": ma.get("detail_lines") or [],
            "plan_reviewed": True,
            "cross_control_impact": (ca or {}).get("cross_control_impact")
            or (impact or {}).get("cross_control_impact"),
            "predicted_secondary_findings": (ca or {}).get("predicted_secondary_findings")
            or (impact or {}).get("predicted_secondary_findings")
            or [],
            "remediation_fully_hardened": (ca or {}).get("remediation_fully_hardened")
            if (ca or {}).get("remediation_fully_hardened") is not None
            else (impact or {}).get("remediation_fully_hardened"),
        }

    workloads = (impact or {}).get("discovery", {}).get("potentially_affected_workloads") if impact else None
    if "access analyzer" in title_l:
        workloads = (
            "Creates a monitoring/analyzer resource. It does not modify existing IAM "
            "permissions or resource policies."
        )
        region = str(
            (impact or {}).get("region")
            or ((finding or {}).get("resource") or {}).get("region")
            or ""
        ).strip()
        scope = f"Regional ({region})" if region else "Regional"
    if not workloads or str(workloads).strip().lower() in {"see change_assurance", "unknown"}:
        if "config recorder" in title_l or "aws config" in title_l:
            workloads = (
                "Creates AWS Config recording infrastructure in-region. "
                "Does not modify existing CloudTrail buckets or application workloads."
            )
        else:
            workloads = "Not fully mapped — treat as unknown until confirmed."
    deps = (ca or {}).get("dependencies") or (impact or {}).get("dependencies") or []
    dep_names = []
    for d in deps[:8]:
        if isinstance(d, dict) and (d.get("id") or d.get("type")):
            label = str(d.get("id") or d.get("type"))
            if label.lower() in {"none_detected", "none"}:
                continue
            dep_names.append(label)
    unknowns = []
    if level in {"UNKNOWN", ""}:
        unknowns.append("Blast radius could not be fully determined.")
    if any(isinstance(d, dict) and str(d.get("confidence") or "").upper() == "LOW" for d in deps):
        unknowns.append("Some downstream dependencies are uncertain.")
    downtime = "No planned downtime indicated by analysis (still verify with owners)."
    if "access analyzer" in title_l:
        downtime = "None expected for Access Analyzer enablement."
    elif "config recorder" in title_l or "aws config" in title_l:
        downtime = "None expected for existing workloads."
    elif level in {"HIGH", "CRITICAL"}:
        downtime = "Possible service impact — coordinate with owners before applying."
    reasons = blast.get("reasons") or []
    risk_obj = (ca or {}).get("remediation_risk") or (impact or {}).get("remediation_risk") or {}
    rationale = None
    if isinstance(risk_obj, dict):
        rationale = risk_obj.get("rationale") or ((risk_obj.get("reasons") or [None])[0])
    if "access analyzer" in title_l:
        potential = (
            "Creates a monitoring/analyzer resource. It does not modify existing IAM "
            "permissions or resource policies."
        )
    elif rationale:
        potential = str(rationale)
    elif reasons:
        potential = str(reasons[0])
    elif "public" in str(workloads).lower():
        potential = "Applications relying on intentionally public access may be affected."
    else:
        potential = "Review dependencies below before authorizing."
    return {
        "scope": scope,
        "blast_level": level,
        "level": level,
        "potentially_affected": workloads if isinstance(workloads, str) else str(workloads),
        "expected_downtime": downtime,
        "known_dependencies": dep_names or ["No public/website workload dependencies identified"],
        "unknowns": unknowns or ["None flagged"],
        "potential_issue": potential,
        "summary_line": potential if "access analyzer" in title_l else f"Scope: {scope}. {potential}",
        "risk_rationale": rationale,
        "plan_reviewed": False,
    }


def _current_plan_context(
    job: dict[str, Any] | None,
    finding: dict[str, Any] | None,
    impact: dict[str, Any] | None,
    ca: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve CURRENT reviewed/recovery plan addresses + already-created resources."""
    from change_assurance.plan_manager_context import (
        all_plan_addresses,
        flags_from_plan_addresses,
        plan_action_addresses,
        split_prepare_resources,
    )

    job = job or {}
    fid = str((finding or {}).get("id") or "")
    fe = ((job.get("finding_execution") or {}).get(fid) or {}) if fid else {}
    reviewed = (
        (ca or {}).get("reviewed_plan")
        or (impact or {}).get("reviewed_plan")
        or ((job.get("reviewed_terraform_plans") or {}).get(fid) if fid else None)
        or {}
    )
    if not isinstance(reviewed, dict):
        reviewed = {}
    # Prefer recovery resources bound on finding_execution
    creates = list(fe.get("recovery_resources") or [])
    if not creates:
        groups = plan_action_addresses(reviewed)
        creates = list(groups.get("create") or [])
    if not creates:
        creates = all_plan_addresses(reviewed)
    already = list(fe.get("succeeded_resources") or [])
    resolution = (ca or {}).get("prerequisite_resolution") or (impact or {}).get(
        "prerequisite_resolution"
    ) or {}
    split = split_prepare_resources(
        resolution_resources=list((resolution or {}).get("resources") or []),
        already_created=already,
        current_creates=creates if creates else None,
    )
    addrs = list(creates) or all_plan_addresses(reviewed)
    flags = flags_from_plan_addresses(addrs, base_flags={})
    return {
        "finding_id": fid,
        "reviewed_plan": reviewed,
        "plan_addresses": addrs,
        "flags": flags,
        "already_created": split["already_created"],
        "will_create": split["will_create"],
        "prepare": split["prepare"],
        "finding_execution": fe,
        "lifecycle_recovery": str(
            fe.get("status")
            or (ca or {}).get("remediation_lifecycle_state")
            or (impact or {}).get("remediation_lifecycle_state")
            or ""
        ).upper()
        in {"PARTIAL_EXECUTION", "RECOVERY_REQUIRED"}
        or str((ca or {}).get("remediation_status") or "").upper() == "RECOVERY_REQUIRED",
    }


def _plan_aware_manager_questions(
    job: dict[str, Any] | None,
    finding: dict[str, Any] | None,
    impact: dict[str, Any] | None,
    ca: dict[str, Any] | None,
) -> list[str]:
    """Prefer CURRENT plan-derived questions; filter stale IAM/break-glass copy."""
    from change_assurance.plan_manager_context import (
        filter_stale_manager_questions,
        manager_questions_for_plan,
    )

    ctx = _current_plan_context(job, finding, impact, ca)
    raw = list((ca or {}).get("manager_questions") or (impact or {}).get("manager_questions") or [])
    # When a reviewed/recovery plan is bound, regenerate from plan actions
    if ctx["plan_addresses"] or ctx["lifecycle_recovery"]:
        regenerated = manager_questions_for_plan(
            finding,
            flags=ctx["flags"],
            plan_addresses=ctx["plan_addresses"],
            discovery=(impact or {}).get("discovery") or (ca or {}).get("discovery") or {},
            evidence_assessment=(ca or {}).get("evidence_assessment")
            or (impact or {}).get("evidence_assessment"),
        )
        if regenerated:
            return [str(q).replace("MANAGER CONTEXT REQUIRED:", "").strip() for q in regenerated]
    filtered = filter_stale_manager_questions(
        raw,
        plan_addresses=ctx["plan_addresses"],
        flags=ctx["flags"],
    )
    return [str(q).replace("MANAGER CONTEXT REQUIRED:", "").strip() for q in filtered]


def _why_recommend(
    finding: dict[str, Any],
    impact: dict[str, Any] | None,
    ca: dict[str, Any] | None,
    *,
    job: dict[str, Any] | None = None,
) -> str:
    rec = str((impact or {}).get("recommendation") or (ca or {}).get("recommendation") or "RECOMMEND_REVIEW")
    status = str((impact or {}).get("finding_status") or "")
    reasons = list((ca or {}).get("recommendation_reasons") or (impact or {}).get("readiness", {}).get("reasons") or [])
    questions = _plan_aware_manager_questions(job, finding, impact, ca) if job is not None else (
        (ca or {}).get("manager_questions") or []
    )
    val = str((ca or {}).get("validation_status") or ((impact or {}).get("terraform") or {}).get("validate", {}).get("status") or "")
    risk = ((ca or {}).get("remediation_risk") or (impact or {}).get("remediation_risk") or {})
    risk_level = risk.get("level") if isinstance(risk, dict) else risk

    if status == "ALREADY_REMEDIATED" or rec == "NO_ACTION_REQUIRED":
        return "Live checks suggest the issue may already be fixed, so no further change is needed right now."

    ready = _artifact_readiness_block(impact, ca, job=job, finding=finding)
    if ready.get("remediation_status") == "RECOVERY_REQUIRED":
        return (
            "Human context is required because a recovery plan is pending review after partial "
            "execution — confirm remaining creates, Config scope/delivery, and cost before approval."
        )
    if ready.get("remediation_status") == "PREREQUISITES_RESOLVED":
        return (
            "Manager selected CREATE DEDICATED RESOURCES. Sentinel prepared complete AWS Config "
            "Terraform (service-linked role, dedicated bucket/policy, recorder, delivery channel, "
            "enablement) with no REPLACE_* placeholders. This does not apply anything — "
            "validate, plan, approve, then human-triggered apply are still required."
        )
    if rec == "REMEDIATION_PREREQUISITES_REQUIRED" or ready.get("has_placeholders"):
        missing = ready.get("missing_prerequisite_labels") or ready.get("unresolved_placeholders") or []
        miss_txt = ", ".join(str(x) for x in missing[:4] if str(x) != "NONE")
        return (
            "Remediation prerequisites are required before this change is execution-ready"
            + (f": {miss_txt}." if miss_txt else ".")
            + " Manager must choose reuse of approved resources or dedicated creation — "
            "Sentinel will not invent or auto-create them."
        )

    if questions or (ca or {}).get("manager_context_required"):
        q = str(questions[0]).replace("MANAGER CONTEXT REQUIRED:", "").strip() if questions else (
            "required business context is missing"
        )
        return f"Human context is required because the system cannot decide alone: {q}"

    if rec == "RECOMMEND_REJECT":
        # Never blame this finding on unrelated kit placeholders
        if ready.get("has_placeholders"):
            detail = "unresolved placeholders in this finding's remediation artifacts"
        elif any("placeholder" in str(r).lower() for r in reasons) and not ready.get("has_placeholders"):
            detail = reasons[0] if reasons and "placeholder" not in str(reasons[0]).lower() else (
                "validation failed or a dangerous pattern was detected"
            )
            # Strip stale whole-kit placeholder reject copy
            if "placeholder" in str(detail).lower():
                detail = "validation failed or a dangerous pattern was detected"
        else:
            detail = reasons[0] if reasons else "validation failed or a dangerous pattern was detected"
        return f"The AI recommends not applying this change because {detail}."

    if rec == "RECOMMEND_APPROVE":
        bits = []
        if status == "CONFIRMED":
            bits.append("the finding was confirmed")
        if val == "PASS":
            bits.append("the proposed change passed validation")
        bits.append("no automatic apply will occur")
        if str(risk_level) == "LOW":
            bits.append("change risk is low")
        return "The AI recommends approval because " + ", ".join(bits) + "."

    # REVIEW
    detail = reasons[0] if reasons else "more judgment is needed on impact or unknowns"
    return f"The AI recommends manager review because {detail}."


def _after_change(finding: dict[str, Any], impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> str:
    title_l = str(finding.get("title") or "").lower()
    region = (
        str(((finding.get("resource") or {}).get("region") or "")).strip()
        or str(((impact or {}).get("region") or "")).strip()
        or "us-east-1"
    )
    if "access analyzer" in title_l:
        return (
            f"Re-query IAM Access Analyzer in {region} and confirm an ACTIVE ACCOUNT "
            "analyzer exists, then re-scan so CLOUD-IAM-013 no longer fails."
        )
    plan = (ca or {}).get("verification") or (impact or {}).get("verification") or {}
    steps = plan.get("steps") or []
    fid = finding.get("id") or "this finding"
    if steps:
        # Prefer human-friendly subset
        friendly = [s for s in steps if not str(s).startswith("Do NOT")][:3]
        if friendly:
            return "After the change: " + " ".join(str(s).rstrip(".") + "." for s in friendly)
    return (
        f"After the change, re-scan with the same agent and confirm {fid} no longer fails. "
        "Deployment success alone must not close the finding."
    )


def _artifact_readiness_block(
    impact: dict[str, Any] | None,
    ca: dict[str, Any] | None,
    *,
    job: dict[str, Any] | None = None,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Manager-facing relevant artifacts + placeholders for the finding under review."""
    relevant = list(
        (ca or {}).get("relevant_artifacts")
        or (impact or {}).get("relevant_artifacts")
        or []
    )
    # ONLY finding-scoped placeholders — never fall back to whole-kit terraform.placeholders
    placeholders = list(
        (ca or {}).get("relevant_placeholders")
        or (impact or {}).get("relevant_placeholders")
        or []
    )
    sibling = list(
        (ca or {}).get("sibling_placeholder_artifacts")
        or (impact or {}).get("sibling_placeholder_artifacts")
        or []
    )
    scope = (ca or {}).get("artifact_scope") or (impact or {}).get("artifact_scope") or {}
    # If scoped analysis exists, ignore any unscoped legacy terraform placeholder list
    tf = (impact or {}).get("terraform") or {}
    if not placeholders and not scope and not relevant:
        # Legacy cache without scoping — do not surface whole-kit REPLACE_* as this finding's failure
        placeholders = []
    elif not placeholders and relevant:
        # Keep empty: relevant artifacts were checked; NONE is correct
        placeholders = []
    unresolved = []
    for p in placeholders:
        if isinstance(p, dict):
            token = p.get("token") or ""
            path = p.get("file") or ""
            unresolved.append(f"{token} in {path}" if path else str(token))
        else:
            unresolved.append(str(p))
    # Prefer scoped paths; if missing, try terraform analysis files when scoped
    if not relevant:
        # no whole-kit listing
        relevant = list(scope.get("paths") or [])

    prerequisites = list(
        (ca or {}).get("remediation_prerequisites")
        or (impact or {}).get("remediation_prerequisites")
        or []
    )
    if not prerequisites and placeholders:
        try:
            from change_assurance.prerequisites import prerequisites_from_placeholders

            prerequisites = prerequisites_from_placeholders(placeholders)
        except Exception:
            prerequisites = []

    remediation_status = str(
        (ca or {}).get("remediation_status") or (impact or {}).get("remediation_status") or ""
    ).upper()
    if not remediation_status:
        remediation_status = "PREREQUISITES_REQUIRED" if placeholders else "NOT_READY"

    # Persistent remediation lifecycle overrides (cross-job continuity)
    lifecycle = {}
    # job is optional — callers may pass via impact["_job"] when available
    job_ref = job or ((impact or {}).get("_job") if isinstance(impact, dict) else None)
    if isinstance(job_ref, dict):
        lifecycle = job_ref.get("remediation_lifecycle") or {}
    lifecycle_state = str(
        (ca or {}).get("remediation_lifecycle_state")
        or (impact or {}).get("remediation_lifecycle_state")
        or lifecycle.get("remediation_state")
        or ""
    ).upper()
    existence = list(
        (ca or {}).get("prerequisite_existence")
        or (impact or {}).get("prerequisite_existence")
        or []
    )
    if not existence and isinstance(lifecycle.get("prerequisite_resources"), dict):
        label_map = {
            "aws_iam_service_linked_role.config": "AWS Config IAM role",
            "aws_s3_bucket.config": "S3 delivery bucket (Config)",
        }
        for addr, row in (lifecycle.get("prerequisite_resources") or {}).items():
            if not isinstance(row, dict):
                continue
            existence.append(
                {
                    "address": addr,
                    "label": label_map.get(addr, addr),
                    "status": row.get("status"),
                    "evidence_quality": row.get("evidence_quality"),
                    "evidence_source": row.get("evidence_source"),
                    "identity": row.get("identity"),
                }
            )
    if (ca or {}).get("suppress_placeholder_prerequisites") or lifecycle_state in {
        "PARTIAL_EXECUTION",
        "RECOVERY_REQUIRED",
    }:
        placeholders = []
        unresolved = ["NONE"]
        prerequisites = []
        if remediation_status == "PREREQUISITES_REQUIRED":
            remediation_status = "RECOVERY_REQUIRED"
        if not remediation_status or remediation_status == "NOT_READY":
            remediation_status = "RECOVERY_REQUIRED"

    prereq_decision = (ca or {}).get("prerequisite_decision") or (impact or {}).get("prerequisite_decision")
    resolution = (ca or {}).get("prerequisite_resolution") or (impact or {}).get("prerequisite_resolution") or {}
    decision = (ca or {}).get("prerequisite_manager_decision") or (impact or {}).get(
        "prerequisite_manager_decision"
    )
    if remediation_status in {"PREREQUISITES_RESOLVED", "RECOVERY_REQUIRED"} or (
        isinstance(prereq_decision, dict)
        and str(prereq_decision.get("choice") or "").upper() in {"CREATE_DEDICATED", "CREATE_DEDICATED_RESOURCES"}
        and not placeholders
    ):
        decision = decision or "CREATE DEDICATED RESOURCES"
        if remediation_status == "PREREQUISITES_REQUIRED":
            remediation_status = "PREREQUISITES_RESOLVED"
    elif not decision and prerequisites:
        try:
            from change_assurance.prerequisites import manager_decision_prompt

            decision = manager_decision_prompt(prerequisites)
        except Exception:
            decision = "Resolve missing prerequisites before treating this change as execution-ready."

    plan_ctx = _current_plan_context(
        job_ref if isinstance(job_ref, dict) else None, finding, impact, ca
    )
    prepare = list(plan_ctx.get("prepare") or [])
    already_created = list(plan_ctx.get("already_created") or [])
    will_create = list(plan_ctx.get("will_create") or [])
    if not prepare and not already_created and remediation_status in {
        "PREREQUISITES_RESOLVED",
        "RECOVERY_REQUIRED",
    }:
        from change_assurance.plan_manager_context import split_prepare_resources

        split = split_prepare_resources(
            resolution_resources=list((resolution or {}).get("resources") or []),
            already_created=already_created,
            current_creates=None,
        )
        prepare = split["prepare"]
        will_create = split["will_create"]
        already_created = split["already_created"] or already_created
    if (
        not prepare
        and not will_create
        and remediation_status == "PREREQUISITES_RESOLVED"
        and not already_created
    ):
        prepare = [
            "AWS Config service-linked role",
            "dedicated encrypted/private S3 delivery bucket",
            "Config bucket policy",
            "configuration recorder",
            "delivery channel",
            "recorder enablement",
        ]
        will_create = list(prepare)

    missing_labels = [
        str(p.get("label") or p.get("token")) for p in prerequisites if isinstance(p, dict)
    ]
    # Prefer existence evidence — never list EXISTS resources as Missing
    if existence:
        missing_labels = [
            str(e.get("label"))
            for e in existence
            if str(e.get("status") or "").upper() == "MISSING"
        ]

    return {
        "relevant_artifacts": relevant or ["—"],
        "unresolved_placeholders": unresolved or ["NONE"],
        "has_placeholders": bool(placeholders),
        "sibling_placeholders": [
            f"{s.get('token')} in {s.get('file')}" for s in sibling[:5] if isinstance(s, dict)
        ],
        "mapping": scope.get("mapping") or "",
        "job_fully_approvable": (ca or {}).get("job_fully_approvable"),
        "prerequisites": prerequisites,
        "missing_prerequisite_labels": missing_labels,
        "prerequisite_existence": existence,
        "remediation_status": remediation_status,
        "remediation_lifecycle_state": lifecycle_state or None,
        "execution_ready": bool((ca or {}).get("execution_ready") or (impact or {}).get("execution_ready"))
        and not placeholders
        and remediation_status not in {"PREREQUISITES_REQUIRED"},
        "manager_decision_prompt": decision,
        "prerequisite_decision": prereq_decision,
        "prerequisite_choice": (
            (prereq_decision or {}).get("choice") if isinstance(prereq_decision, dict) else None
        ),
        "prepare": prepare,
        "already_created": already_created,
        "will_create": will_create,
        "cost_note": (ca or {}).get("cost_note")
        or (impact or {}).get("cost_note")
        or (resolution or {}).get("cost_note"),
        "do_not_touch": (ca or {}).get("do_not_touch")
        or (impact or {}).get("do_not_touch")
        or (resolution or {}).get("do_not_touch")
        or [],
        "required_remediation_role_permissions": (ca or {}).get("required_remediation_role_permissions")
        or (impact or {}).get("required_remediation_role_permissions")
        or (resolution or {}).get("required_remediation_role_permissions")
        or [],
        "what_will_change": (
            (
                "Create the remaining AWS Config infrastructure in the current recovery plan "
                "(already-created resources are not recreated)."
                if remediation_status == "RECOVERY_REQUIRED" and already_created
                else "Create the supporting AWS Config infrastructure required to begin recording "
                "configuration changes in the finding Region."
            )
            if remediation_status in {"PREREQUISITES_RESOLVED", "RECOVERY_REQUIRED"}
            else None
        ),
        "what_will_not_change": (ca or {}).get("do_not_touch")
        or (resolution or {}).get("do_not_touch")
        or [],
        # Persisted-artifact binding (source of truth for stale-kit diagnosis)
        "kit_generation_id": (resolution or {}).get("kit_generation_id")
        or (ca or {}).get("kit_generation_id")
        or (impact or {}).get("kit_generation_id"),
        "artifact_path": (resolution or {}).get("artifact_path")
        or (ca or {}).get("artifact_path"),
        "artifact_sha256": (resolution or {}).get("artifact_sha256")
        or (ca or {}).get("artifact_sha256"),
        "artifact_generated_at": (resolution or {}).get("artifact_generated_at")
        or (ca or {}).get("artifact_generated_at"),
        "persistence_verified": bool((resolution or {}).get("persistence_verified")),
        "kit_path": (resolution or {}).get("kit_path") or (ca or {}).get("kit_path"),
    }


def _ai_checks(finding: dict[str, Any], impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> list[dict[str, Any]]:
    status = str((impact or {}).get("finding_status") or "UNKNOWN")
    val = str((ca or {}).get("validation_status") or ((impact or {}).get("terraform") or {}).get("validate", {}).get("status") or "UNKNOWN")
    art = ((ca or {}).get("artifacts") or [{}])[0] if ca else {}
    destructive = art.get("destructive") or {}
    is_destr = bool(destructive.get("destructive")) if isinstance(destructive, dict) else False
    disc = (impact or {}).get("discovery") or {}
    summary = disc.get("summary") or {}
    public_n = int(summary.get("public_buckets") or 0)
    answers = (impact or {}).get("assurance_answers") or {}
    ready = _artifact_readiness_block(impact, ca)
    # change_assurance nested may not have assurance_answers; derive
    checks = [
        {
            "ok": status == "CONFIRMED",
            "label": "Finding confirmed" if status == "CONFIRMED" else f"Finding status: {status or 'UNKNOWN'}",
        },
        {
            "ok": status != "ALREADY_REMEDIATED",
            "label": "Already remediated — no change needed"
            if status == "ALREADY_REMEDIATED"
            else "Still appears open (not marked already fixed)",
        },
        {
            "ok": not is_destr,
            "label": "No destructive actions detected" if not is_destr else "Destructive actions may be present",
        },
        {
            "ok": val == "PASS",
            "label": f"Validation: {val or 'UNKNOWN'}",
        },
        {
            "ok": not ready["has_placeholders"],
            "label": (
                "Unresolved placeholders: NONE"
                if not ready["has_placeholders"]
                else "Unresolved placeholders: PRESENT — "
                + "; ".join(ready["unresolved_placeholders"][:3])
            ),
        },
        {
            "ok": ready.get("remediation_status") not in {"PREREQUISITES_REQUIRED"},
            "label": (
                f"Remediation status: {ready.get('remediation_status') or 'NOT_READY'}"
                + (
                    " — Missing: " + ", ".join(ready.get("missing_prerequisite_labels") or [])
                    if ready.get("missing_prerequisite_labels")
                    else ""
                )
            ),
        },
        {
            "ok": True,
            "label": "Relevant remediation artifacts: " + ", ".join(str(x) for x in ready["relevant_artifacts"][:4]),
        },
    ]
    if ready.get("manager_decision_prompt") and ready.get("has_placeholders"):
        checks.append(
            {
                "ok": False,
                "label": "What must the manager decide? " + str(ready["manager_decision_prompt"]),
            }
        )
    if ready.get("sibling_placeholders"):
        checks.append(
            {
                "ok": False,
                "label": "Other findings in this job still have placeholders (blocks whole-job approval)",
            }
        )
    if "STO" in str(finding.get("id") or "").upper() or summary:
        checks.append(
            {
                "ok": public_n == 0,
                "label": "No currently public buckets detected"
                if public_n == 0
                else f"{public_n} potentially public bucket(s) detected",
            }
        )
    match = answers.get("change_matches_finding")
    if match is True:
        checks.insert(1, {"ok": True, "label": "Proposed fix matches finding"})
    elif match == "UNKNOWN":
        checks.insert(1, {"ok": False, "label": "Fix-to-finding match not fully proven"})
    return checks


def _learning(finding: dict[str, Any], role: str) -> dict[str, str]:
    fid = str(finding.get("id") or "").upper()
    for prefix, hint in LEARNING_HINTS.items():
        if fid.startswith(prefix) or prefix in fid:
            return {
                "technology": hint["technology"],
                "concept": hint["concept"],
                "learning": hint["learning"],
                "before_approve": hint["before_approve"],
                "why_engineer": hint["why_engineer"],
            }
    # Role fallbacks
    role_fallback = {
        "cloud": "CLOUD-STO",
        "devsecops": "DEVSEC-SCA",
        "ai-security": "AISEC",
        "security-engineer": "PERIM",
    }.get(str(role or ""), "PERIM")
    hint = LEARNING_HINTS[role_fallback]
    return {
        "technology": hint["technology"],
        "concept": hint["concept"],
        "learning": hint["learning"],
        "before_approve": hint["before_approve"],
        "why_engineer": hint["why_engineer"],
    }


def _cross_agent_plain(ca: dict[str, Any] | None) -> list[str]:
    hooks = (ca or {}).get("cross_agent_review") or []
    out = []
    for h in hooks:
        if not isinstance(h, dict):
            continue
        agent = agent_title(h.get("requested_agent"))
        if h.get("review_status") in {"COMPLETED", "DONE"}:
            out.append(f"Reviewed by: {agent}")
        else:
            out.append(f"Additional review requested: {agent}")
    return out


def _as_ca_dict(impact: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize change_assurance nest — never treat a bool/legacy flag as a mapping."""
    raw = (impact or {}).get("change_assurance")
    if isinstance(raw, dict):
        return raw
    raw2 = (impact or {}).get("change_assurance_report")
    if isinstance(raw2, dict):
        return raw2
    # Top-level mirrors from legacy impact documents
    out: dict[str, Any] = {}
    for key in (
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
        "sibling_placeholder_artifacts",
        "artifact_scope",
        "verification",
        "recommendation",
        "manager_questions",
        "manager_context_required",
        "validation_status",
        "remediation_risk",
        "approval_integrity",
        "primary_finding_id",
        "finding_status",
        "analysis_logic_version",
        "deployment_ready",
    ):
        if impact and key in impact and impact.get(key) is not None:
            out[key] = impact.get(key)
    return out


def build_manager_card(
    finding: dict[str, Any],
    job: dict[str, Any],
    impact: dict[str, Any] | None = None,
    *,
    is_primary: bool = False,
) -> dict[str, Any]:
    # Enrich impact with job execution/recovery state for accurate Manager Mode
    if is_primary:
        impact = dict(impact or {})
        impact.setdefault("primary_finding_id", finding.get("id"))
        impact["_job"] = job
        if job.get("finding_execution"):
            impact["finding_execution"] = job.get("finding_execution")
            ca_nest = dict(impact.get("change_assurance") or {})
            ca_nest["finding_execution"] = job.get("finding_execution")
            impact["change_assurance"] = ca_nest
        if job.get("remediation_lifecycle"):
            impact["remediation_lifecycle_state"] = (
                job["remediation_lifecycle"].get("remediation_state")
            )
            ca_nest = dict(impact.get("change_assurance") or {})
            ca_nest["remediation_lifecycle_state"] = impact["remediation_lifecycle_state"]
            # Surface existence into CA so readiness block can render EXISTS
            pr = job["remediation_lifecycle"].get("prerequisite_resources") or {}
            if pr and not ca_nest.get("prerequisite_existence"):
                label_map = {
                    "aws_iam_service_linked_role.config": "AWS Config IAM role",
                    "aws_s3_bucket.config": "S3 delivery bucket (Config)",
                }
                ca_nest["prerequisite_existence"] = [
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
                ca_nest["suppress_placeholder_prerequisites"] = True
            impact["change_assurance"] = ca_nest
            impact["prerequisite_existence"] = ca_nest.get("prerequisite_existence")
            impact["suppress_placeholder_prerequisites"] = True
    ca = _as_ca_dict(impact) if is_primary else {}
    # Refuse to present another finding's assurance bundle as this finding's proof
    if is_primary and impact:
        bound = str(
            (impact or {}).get("primary_finding_id")
            or ca.get("primary_finding_id")
            or ""
        )
        if bound and finding.get("id") and str(finding.get("id")) != bound:
            impact = None
            ca = {}
    role = str(job.get("role") or "")
    sev = str(finding.get("severity") or "info").upper()
    risk = (ca.get("remediation_risk") if is_primary else None) or (impact or {}).get("remediation_risk") or {}
    if isinstance(risk, dict):
        change_risk = str(risk.get("level") or "UNKNOWN")
    else:
        change_risk = str(risk or "UNKNOWN")
    if not is_primary:
        # Per-finding list rows: use finding severity for security; change risk unknown unless primary
        change_risk = change_risk if change_risk != "UNKNOWN" else "UNKNOWN"

    raw_rec = None
    if is_primary:
        raw_rec = (impact or {}).get("recommendation") or ca.get("recommendation")
    raw_rec = raw_rec or "RECOMMEND_REVIEW"

    status = str((impact or {}).get("finding_status") or "") if is_primary else ""
    already = status == "ALREADY_REMEDIATED" or raw_rec == "NO_ACTION_REQUIRED"

    integ = ca.get("approval_integrity") or (impact or {}).get("approval_integrity") or {}
    # Job-level invalidated approval after partial execution takes precedence
    job_binding = job.get("approval_binding") if isinstance(job.get("approval_binding"), dict) else {}
    if is_primary and (
        job.get("approval_status") == "APPROVAL_INVALIDATED"
        or str(job_binding.get("status") or "") == "APPROVAL_INVALIDATED"
    ):
        integ = {
            "status": "APPROVAL_INVALIDATED",
            "integrity": "INVALIDATED",
            "valid": False,
            "reasons": list(
                job_binding.get("invalidation_reasons")
                or job_binding.get("reasons")
                or ["PARTIAL_EXECUTION_CHANGED_STATE"]
            ),
            "reason": job_binding.get("invalidation_detail")
            or job_binding.get("reason")
            or "PARTIAL_EXECUTION_CHANGED_STATE",
        }
    integ_plain = integrity_plain_english(integ) if is_primary else {
        "headline": "AWAITING YOUR DECISION",
        "message": "",
        "needs_review": False,
        "technical_reasons": [],
        "status": "PENDING",
    }

    questions = []
    if is_primary:
        plan_qs = _plan_aware_manager_questions(job, finding, impact, ca)
        ctx_required = bool(
            ca.get("manager_context_required") or (impact or {}).get("manager_context_required")
        )
        fe_row = (job.get("finding_execution") or {}).get(str(finding.get("id") or "")) or {}
        recovery = str(fe_row.get("status") or "").upper() in {
            "RECOVERY_REQUIRED",
            "PARTIAL_EXECUTION",
        } or str((ca or {}).get("remediation_status") or "").upper() == "RECOVERY_REQUIRED"
        if ctx_required or recovery or plan_qs:
            questions = plan_qs

    # Control-specific Manager teaching block (deterministic metadata — no LLM)
    understanding = None
    if is_primary:
        try:
            import manager_explanations as mx

            preview = ""
            arts = ca.get("artifacts") or (impact or {}).get("artifacts") or []
            if arts and isinstance(arts[0], dict):
                preview = str(arts[0].get("content_preview") or "")
                if not preview:
                    preview = " ".join(str(x) for x in (arts[0].get("source_files") or [])[:6])
            if not preview:
                preview = " ".join(
                    str(x)
                    for x in (
                        ca.get("relevant_artifacts")
                        or (impact or {}).get("relevant_artifacts")
                        or []
                    )[:6]
                )
            understanding = mx.build_understanding(
                finding,
                impact if is_primary else None,
                ca if is_primary else None,
                artifact_preview=preview,
            )
        except Exception as exc:
            understanding = {
                "available": False,
                "errors": [f"EXPLANATION_BUILD_FAILED: {exc}"],
                "safe_to_present": False,
            }

    # Prefer control-specific learning fields when understanding is available
    learning = _learning(finding, role)
    if understanding and understanding.get("available") and understanding.get("safe_to_present"):
        learning = {
            "technology": understanding.get("what_is_this") or learning.get("technology"),
            "concept": understanding.get("security_concept") or learning.get("concept"),
            "learning": understanding.get("why_care") or learning.get("learning"),
            "before_approve": "; ".join(understanding.get("manager_prechecks") or [])
            or learning.get("before_approve"),
            "why_engineer": understanding.get("realistic_example") or learning.get("why_engineer"),
        }

    # Prefer control-specific why/after/what_change when safe
    why_matters = _why_matters(finding, impact if is_primary else None)
    what_change = _what_change(finding, impact if is_primary else None, ca if is_primary else None)
    after_change = _after_change(finding, impact if is_primary else None, ca if is_primary else None)
    if understanding and understanding.get("safe_to_present"):
        if understanding.get("why_care"):
            why_matters = str(understanding["why_care"])
            if understanding.get("absence_does_not_prove"):
                why_matters = why_matters + " " + str(understanding["absence_does_not_prove"])
        if understanding.get("fix_will_do"):
            what_change = str(understanding["fix_will_do"])
        if understanding.get("how_we_verify"):
            after_change = str(understanding["how_we_verify"])
        if understanding.get("what_sentinel_found"):
            # Keep short summary for the first question; full block is separate
            pass

    what_found = _what_found(finding, role)
    if understanding and understanding.get("safe_to_present") and understanding.get("what_sentinel_found"):
        what_found = str(understanding["what_sentinel_found"])

    return {
        "finding_id": finding.get("id"),
        "plain_title": _plain_title(finding),
        "severity": sev,
        "security_severity": sev,
        "change_risk": change_risk,
        "change_risk_rationale": (
            (risk.get("rationale") if isinstance(risk, dict) else None)
            or ((risk.get("reasons") or [None])[0] if isinstance(risk, dict) else None)
        ),
        "agent": agent_title(role),
        "agent_role": role,
        "is_primary": is_primary,
        "already_remediated": already,
        "what_found": what_found,
        "why_matters": why_matters,
        "what_change": what_change,
        "affect": _affect_summary(impact if is_primary else None, ca if is_primary else None, finding),
        "why_recommend": _why_recommend(
            finding, impact if is_primary else None, ca if is_primary else None, job=job if is_primary else None
        ),
        "after_change": after_change,
        "evidence_proof": _evidence_proof_block(impact if is_primary else None, ca if is_primary else None)
        if is_primary
        else None,
        "understanding": understanding,
        "ai_checks": _ai_checks(finding, impact if is_primary else None, ca if is_primary else None) if is_primary else [],
        "artifact_readiness": (
            _artifact_readiness_block(impact, ca, job=job, finding=finding) if is_primary else None
        ),
        "recommendation_raw": raw_rec,
        "recommendation_label": translate_recommendation(raw_rec),
        "manager_decision": manager_decision_label(job, finding),
        "execution": execution_label(job, impact),
        "finding_execution": (
            ((job.get("finding_execution") or {}).get(str(finding.get("id") or "")) if is_primary else None)
        ),
        "source_artifact_sha256": (
            (
                ((job.get("reviewed_terraform_plans") or {}).get(str(finding.get("id") or "")) or {}).get(
                    "source_artifact_sha256"
                )
                or ((job.get("finding_execution") or {}).get(str(finding.get("id") or "")) or {}).get(
                    "source_artifact_sha256"
                )
            )
            if is_primary
            else None
        ),
        "cross_control_impact": (
            (ca.get("cross_control_impact") if is_primary else None)
            or ((impact or {}).get("cross_control_impact") if is_primary else None)
        ),
        "predicted_secondary_findings": (
            list(
                (ca.get("predicted_secondary_findings") if is_primary else None)
                or ((impact or {}).get("predicted_secondary_findings") if is_primary else None)
                or []
            )
        ),
        "cross_control_note": (
            (
                "S3 versioning addressed in proposed recovery plan"
                if is_primary
                and (
                    ((job.get("finding_execution") or {}).get(str(finding.get("id") or "")) or {}).get(
                        "cross_control_versioning_addressed"
                    )
                    or any(
                        "aws_s3_bucket_versioning"
                        in str(a)
                        for a in (
                            ((job.get("finding_execution") or {}).get(str(finding.get("id") or "")) or {}).get(
                                "recovery_resources"
                            )
                            or []
                        )
                    )
                )
                else (
                    "S3 versioning requirement addressed in newly generated Terraform"
                    if is_primary
                    and _artifact_contains_versioning(job, finding)
                    and (
                        ((job.get("finding_execution") or {}).get(str(finding.get("id") or "")) or {}).get(
                            "recovery_plan_status"
                        )
                        == "PLAN_REGENERATION_REQUIRED"
                        or ((job.get("reviewed_terraform_plans") or {}).get(str(finding.get("id") or "")) or {}).get(
                            "status"
                        )
                        == "PLAN_REGENERATION_REQUIRED"
                    )
                    else None
                )
            )
        ),
        "remediation_fully_hardened": (
            (ca.get("remediation_fully_hardened") if is_primary else None)
            if (ca.get("remediation_fully_hardened") is not None if is_primary else True)
            else ((impact or {}).get("remediation_fully_hardened") if is_primary else None)
        ),
        "approval_integrity": integ_plain,
        "manager_input_needed": bool(questions),
        "manager_questions": questions,
        "learning": learning,
        "cross_agent": _cross_agent_plain(ca) if is_primary else [],
        "banner": (
            "ALREADY FIXED"
            if already
            else f"{sev} SECURITY ISSUE"
        ),
        "needs_more_investigation": bool(
            is_primary
            and (
                status in {"UNVERIFIED", "ERROR", "UNKNOWN", ""}
                or str((ca.get("evidence_assessment") or {}).get("evidence_quality") or "").upper()
                in {"INSUFFICIENT", "ERROR", "UNAVAILABLE"}
            )
        ),
    }


def build_job_summary(job: dict[str, Any], findings: list[dict], impact: dict[str, Any] | None = None) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    total = len(findings)
    status = str((impact or {}).get("finding_status") or "")
    rec = str((impact or {}).get("recommendation") or "")
    already = 1 if status == "ALREADY_REMEDIATED" or rec == "NO_ACTION_REQUIRED" else 0
    # Categories we can honestly derive
    needs_decision = 1 if str(job.get("status")) == "pending_approval" and total else 0
    # For multi-finding jobs we don't fabricate per-finding decisions; use severity buckets as review guidance
    safe_to_review = counts["low"] + counts["info"]
    needs_investigation = counts["high"] + counts["medium"]
    if rec == "RECOMMEND_REVIEW":
        needs_investigation = max(needs_investigation, 1)
    return {
        "total": total,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "needs_your_decision": needs_decision if total else 0,
        "already_fixed": already,
        "safe_to_review": safe_to_review,
        "needs_more_investigation": needs_investigation,
        # Only include calculated fields — template should not invent more
    }


def build_manager_view(
    job: dict[str, Any],
    findings: list[dict[str, Any]],
    impact: dict[str, Any] | None = None,
    *,
    focus_finding_id: str | None = None,
) -> dict[str, Any]:
    """Build the Manager Mode payload for Face."""
    ca = _as_ca_dict(impact)
    primary_id = focus_finding_id or (impact or {}).get("primary_finding_id") or ca.get("primary_finding_id")
    primary = None
    if primary_id:
        for f in findings:
            if str(f.get("id")) == str(primary_id):
                primary = f
                break
    if primary is None and findings:
        primary = findings[0]
    if primary is None:
        primary = {
            "id": primary_id or "UNKNOWN",
            "title": job.get("title") or "Security review",
            "severity": "info",
            "description": "No findings loaded for this job.",
        }

    cards = []
    for f in findings:
        is_pri = str(f.get("id")) == str(primary.get("id"))
        cards.append(build_manager_card(f, job, impact, is_primary=is_pri))

    primary_card = build_manager_card(primary, job, impact, is_primary=True)

    return {
        "version": VERSION,
        "mode": "manager",
        "agent": agent_title(job.get("role")),
        "summary": build_job_summary(job, findings, impact),
        "primary": primary_card,
        "finding_rows": cards,
        "manager_decision": manager_decision_label(job, primary),
        "execution": execution_label(job, impact),
        "recommendation_label": primary_card["recommendation_label"],
        "recommendation_raw": primary_card["recommendation_raw"],
        "approval_integrity": primary_card["approval_integrity"],
    }
