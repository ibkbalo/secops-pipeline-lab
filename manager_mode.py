# manager_mode.py
# Face presentation layer — plain-English Manager Mode.
# Does NOT change Change Assurance safety, hashes, adapters, or execution rules.
# Recommendation != authorization. Approval != deployment.

from __future__ import annotations

from typing import Any

VERSION = "0.1.0-mm1"

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


def manager_decision_label(job: dict[str, Any] | None) -> str:
    job = job or {}
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
    if not workloads:
        workloads = "Not fully mapped — treat as unknown until confirmed."
    deps = (ca or {}).get("dependencies") or (impact or {}).get("dependencies") or []
    dep_names = []
    for d in deps[:5]:
        if isinstance(d, dict) and (d.get("id") or d.get("type")):
            dep_names.append(str(d.get("id") or d.get("type")))
    unknowns = []
    if level in {"UNKNOWN", ""}:
        unknowns.append("Blast radius could not be fully determined.")
    if any(isinstance(d, dict) and str(d.get("confidence") or "").upper() == "LOW" for d in deps):
        unknowns.append("Some downstream dependencies are uncertain.")
    downtime = "No planned downtime indicated by analysis (still verify with owners)."
    if "access analyzer" in title_l:
        downtime = "None expected for Access Analyzer enablement."
    elif level in {"HIGH", "CRITICAL"}:
        downtime = "Possible service impact — coordinate with owners before applying."
    reasons = blast.get("reasons") or []
    if "access analyzer" in title_l:
        potential = (
            "Creates a monitoring/analyzer resource. It does not modify existing IAM "
            "permissions or resource policies."
        )
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
        "known_dependencies": dep_names or ["None clearly identified"],
        "unknowns": unknowns or ["None flagged"],
        "potential_issue": potential,
        "summary_line": potential if "access analyzer" in title_l else f"Scope: {scope}. {potential}",
    }


def _why_recommend(
    finding: dict[str, Any],
    impact: dict[str, Any] | None,
    ca: dict[str, Any] | None,
) -> str:
    rec = str((impact or {}).get("recommendation") or (ca or {}).get("recommendation") or "RECOMMEND_REVIEW")
    status = str((impact or {}).get("finding_status") or "")
    reasons = list((ca or {}).get("recommendation_reasons") or (impact or {}).get("readiness", {}).get("reasons") or [])
    questions = (ca or {}).get("manager_questions") or []
    val = str((ca or {}).get("validation_status") or ((impact or {}).get("terraform") or {}).get("validate", {}).get("status") or "")
    risk = ((ca or {}).get("remediation_risk") or (impact or {}).get("remediation_risk") or {})
    risk_level = risk.get("level") if isinstance(risk, dict) else risk

    if status == "ALREADY_REMEDIATED" or rec == "NO_ACTION_REQUIRED":
        return "Live checks suggest the issue may already be fixed, so no further change is needed right now."

    if questions or (ca or {}).get("manager_context_required"):
        q = str(questions[0]).replace("MANAGER CONTEXT REQUIRED:", "").strip() if questions else (
            "required business context is missing"
        )
        return f"Human context is required because the system cannot decide alone: {q}"

    if rec == "RECOMMEND_REJECT":
        ready = _artifact_readiness_block(impact, ca)
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


def _artifact_readiness_block(impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> dict[str, Any]:
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
        analysis_files = ((tf.get("validate") or {}) if isinstance(tf, dict) else {})
        # no whole-kit listing
        relevant = list(scope.get("paths") or [])
    return {
        "relevant_artifacts": relevant or ["—"],
        "unresolved_placeholders": unresolved or ["NONE"],
        "has_placeholders": bool(placeholders),
        "sibling_placeholders": [
            f"{s.get('token')} in {s.get('file')}" for s in sibling[:5] if isinstance(s, dict)
        ],
        "mapping": scope.get("mapping") or "",
        "job_fully_approvable": (ca or {}).get("job_fully_approvable"),
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
                else "Unresolved placeholders: " + "; ".join(ready["unresolved_placeholders"][:3])
            ),
        },
        {
            "ok": True,
            "label": "Relevant remediation artifacts: " + ", ".join(str(x) for x in ready["relevant_artifacts"][:4]),
        },
    ]
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


def build_manager_card(
    finding: dict[str, Any],
    job: dict[str, Any],
    impact: dict[str, Any] | None = None,
    *,
    is_primary: bool = False,
) -> dict[str, Any]:
    ca = (impact or {}).get("change_assurance") or (impact or {}).get("change_assurance_report") or {}
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
    integ_plain = integrity_plain_english(integ) if is_primary else {
        "headline": "AWAITING YOUR DECISION",
        "message": "",
        "needs_review": False,
        "technical_reasons": [],
        "status": "PENDING",
    }

    questions = []
    if is_primary and (ca.get("manager_context_required") or (impact or {}).get("manager_context_required")):
        for q in ca.get("manager_questions") or []:
            questions.append(str(q).replace("MANAGER CONTEXT REQUIRED:", "").strip())

    return {
        "finding_id": finding.get("id"),
        "plain_title": _plain_title(finding),
        "severity": sev,
        "security_severity": sev,
        "change_risk": change_risk,
        "agent": agent_title(role),
        "agent_role": role,
        "is_primary": is_primary,
        "already_remediated": already,
        "what_found": _what_found(finding, role),
        "why_matters": _why_matters(finding, impact if is_primary else None),
        "what_change": _what_change(finding, impact if is_primary else None, ca if is_primary else None),
        "affect": _affect_summary(impact if is_primary else None, ca if is_primary else None, finding),
        "why_recommend": _why_recommend(finding, impact if is_primary else None, ca if is_primary else None),
        "after_change": _after_change(finding, impact if is_primary else None, ca if is_primary else None),
        "evidence_proof": _evidence_proof_block(impact if is_primary else None, ca if is_primary else None)
        if is_primary
        else None,
        "ai_checks": _ai_checks(finding, impact if is_primary else None, ca if is_primary else None) if is_primary else [],
        "artifact_readiness": _artifact_readiness_block(impact, ca) if is_primary else None,
        "recommendation_raw": raw_rec,
        "recommendation_label": translate_recommendation(raw_rec),
        "manager_decision": manager_decision_label(job),
        "execution": execution_label(job, impact),
        "approval_integrity": integ_plain,
        "manager_input_needed": bool(questions),
        "manager_questions": questions,
        "learning": _learning(finding, role),
        "cross_agent": _cross_agent_plain(ca) if is_primary else [],
        "banner": (
            "ALREADY FIXED"
            if already
            else f"{sev} SECURITY ISSUE"
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
    ca = (impact or {}).get("change_assurance") or (impact or {}).get("change_assurance_report") or {}
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
        "manager_decision": manager_decision_label(job),
        "execution": execution_label(job, impact),
        "recommendation_label": primary_card["recommendation_label"],
        "recommendation_raw": primary_card["recommendation_raw"],
        "approval_integrity": primary_card["approval_integrity"],
    }
