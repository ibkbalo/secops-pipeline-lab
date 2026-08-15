# change_assurance/domains/devsecops/adapter.py
# Real DevSecOps Change Assurance — local repo / kit artifacts, no SaaS required.

from __future__ import annotations

from typing import Any

from change_assurance.domains.base import DomainAdapter
from change_assurance.models import new_evidence, stable_hash
from change_assurance.repo_discovery import discover_repository, extract_kit_texts
from change_assurance.secret_redaction import redact_obj, redact_text

SUPPORTED_FINDING_HINTS = (
    "source",
    "code",
    "depend",
    "secret",
    "cicd",
    "ci/cd",
    "pipeline",
    "docker",
    "container",
    "kubernetes",
    "k8s",
    "helm",
    "github",
    "gitlab",
    "jenkins",
    "terraform",
    "iac",
    "branch",
    "deploy",
    "permission",
    "sast",
    "sca",
)


class DevSecOpsAdapter(DomainAdapter):
    domain = "devsecops"

    def capability_status(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": "AVAILABLE",
            "detail": "Local repository / kit static Change Assurance (STATIC_ONLY by default)",
            "validation_mode_default": "STATIC_ONLY",
            "auto_execute": False,
        }

    def verify_finding(self, finding: dict, context: dict) -> dict[str, Any]:
        fid = str(finding.get("id") or "")
        title = str(finding.get("title") or "").lower()
        desc = str(finding.get("description") or "").lower()
        blob = f"{fid} {title} {desc}"
        supported = any(h in blob.lower() for h in SUPPORTED_FINDING_HINTS) or fid.upper().startswith("DEVSEC")
        repo_path = (
            context.get("repo_path")
            or (context.get("job") or {}).get("repo_path")
            or (context.get("job") or {}).get("target")
            or context.get("kit_path")
        )
        discovery = discover_repository(repo_path)
        kit_texts = extract_kit_texts(context.get("kit_path") or (context.get("job") or {}).get("kit_path"))
        context["repo_discovery"] = discovery
        context["kit_texts"] = kit_texts
        context["validation_mode"] = context.get("validation_mode") or "STATIC_ONLY"

        if not supported and not kit_texts:
            return {
                "finding_status": "UNKNOWN",
                "still_present": None,
                "capability": "CAPABILITY_PARTIAL",
                "recommendation_hint": "RECOMMEND_REVIEW",
                "discovery": discovery,
                "note": "Unsupported finding type — partial analysis only",
            }
        # Static: treat open DevSecOps finding as CONFIRMED unless evidence says otherwise
        return {
            "finding_status": "CONFIRMED",
            "still_present": True,
            "capability": "AVAILABLE" if supported else "CAPABILITY_PARTIAL",
            "discovery": discovery,
            "kit_file_count": len(kit_texts),
        }

    def gather_evidence(self, finding: dict, context: dict) -> list[dict[str, Any]]:
        disc = context.get("repo_discovery") or {}
        kit_texts = context.get("kit_texts") or {}
        out = []
        out.append(
            new_evidence(
                finding_id=finding.get("id"),
                domain=self.domain,
                source_type="repo_fingerprint",
                source="repo_discovery",
                target=disc.get("repository"),
                observed_value=redact_obj(
                    {
                        "branch": disc.get("branch"),
                        "commit_sha": disc.get("commit_sha"),
                        "fingerprint": disc.get("fingerprint"),
                        "status": disc.get("status"),
                    }
                ),
                confidence="HIGH" if disc.get("commit_sha") else "MEDIUM",
            )
        )
        for path, text in list(kit_texts.items())[:12]:
            redacted, hits = redact_text(text)
            observed: dict[str, Any] = {"path": path, "bytes": len(text), "preview": redacted[:400]}
            if hits:
                observed["secrets"] = [
                    {"status": "SECRET_REDACTED", "secret_type": h.get("secret_type"), "source_file": path}
                    for h in hits
                ]
            out.append(
                new_evidence(
                    finding_id=finding.get("id"),
                    domain=self.domain,
                    source_type="static_analysis",
                    source="kit_or_repo_file",
                    target=path,
                    observed_value=observed,
                    confidence="MEDIUM",
                )
            )
        return out

    def discover_dependencies(self, change: dict, context: dict) -> list[dict[str, Any]]:
        flags = change.get("flags") or {}
        kit_texts = context.get("kit_texts") or {}
        deps: list[dict[str, Any]] = []
        # Build basic graph from evidence — no fabricated edges
        has_req = any(p.endswith("requirements.txt") or p.endswith("package.json") for p in kit_texts)
        has_docker = any("dockerfile" in p.lower() for p in kit_texts)
        has_k8s = any(
            any(k in p.lower() for k in ("deployment", "k8s", "helm", "chart.yaml")) for p in kit_texts
        )
        has_gha = any(".github/workflows" in p or p.endswith(".gitlab-ci.yml") for p in kit_texts)
        if has_req:
            deps.append({"type": "dependency_manifest", "id": "app_deps", "relation": "direct", "confidence": "HIGH"})
            deps.append(
                {
                    "type": "application",
                    "id": "python_or_node_app",
                    "relation": "consumes_manifest",
                    "confidence": "MEDIUM",
                }
            )
        if has_docker:
            deps.append(
                {
                    "type": "container_image",
                    "id": "dockerfile",
                    "relation": "builds_from_app" if has_req else "image_build",
                    "confidence": "MEDIUM" if has_req else "LOW",
                }
            )
        if has_k8s:
            deps.append(
                {
                    "type": "kubernetes_workload",
                    "id": "deployment",
                    "relation": "runs_image" if has_docker else "workload",
                    "confidence": "MEDIUM" if has_docker else "LOW",
                }
            )
        if has_gha:
            deps.append(
                {
                    "type": "pipeline",
                    "id": "ci_cd",
                    "relation": "builds_and_may_deploy",
                    "confidence": "MEDIUM",
                }
            )
            if has_docker:
                deps.append(
                    {
                        "type": "registry",
                        "id": "container_registry",
                        "relation": "pipeline_may_push",
                        "confidence": "LOW",
                    }
                )
        if flags.get("major_dependency") or flags.get("dependency_change"):
            deps.append(
                {
                    "type": "unknown_downstream",
                    "id": None,
                    "relation": "UNKNOWN",
                    "confidence": "LOW",
                    "note": "Downstream consumers not fully mapped",
                }
            )
        if not deps:
            deps.append({"type": "UNKNOWN", "id": None, "relation": "UNKNOWN", "confidence": "LOW"})
        return deps

    def classify_scope(self, change: dict, context: dict) -> str:
        flags = change.get("flags") or {}
        files = change.get("diff_files") or []
        if flags.get("k8s_rbac_change") or flags.get("cluster_role"):
            return "CLUSTER"
        if flags.get("production_deploy_risk") or flags.get("production_impact"):
            return "PRODUCTION"
        if flags.get("pipeline_permission_change"):
            return "PIPELINE"
        if flags.get("network_policy_change") and flags.get("production_impact"):
            return "PRODUCTION"
        if flags.get("dependency_change") and flags.get("major_dependency"):
            return "REPOSITORY"
        if len(files) == 1 and not flags.get("security_sensitive_code"):
            return "FILE"
        if flags.get("security_sensitive_code") or flags.get("auth_change"):
            return "SERVICE"
        disc = context.get("repo_discovery") or {}
        if disc.get("commit_sha"):
            return "REPOSITORY"
        return "UNKNOWN"

    def analyze_impact(self, change: dict, context: dict) -> dict[str, Any]:
        flags = change.get("flags") or {}
        scope = self.classify_scope(change, context)
        reasons: list[str] = []
        level = "LOW"
        if flags.get("write_all") or flags.get("privileged") or flags.get("secret_copied"):
            level = "CRITICAL"
            reasons.append("High-risk CI/container/secret change pattern")
        elif flags.get("pull_request_target") or flags.get("k8s_rbac_change") or flags.get("major_dependency"):
            level = "HIGH"
            reasons.append("Privileged workflow, RBAC, or major dependency change")
        elif flags.get("runs_as_root") or flags.get("production_deploy_risk") or flags.get("auth_change"):
            level = "HIGH"
            reasons.append("Privilege, production pipeline, or auth change")
        elif flags.get("network_policy_change") or flags.get("dependency_change") or flags.get("large_diff"):
            level = "MEDIUM"
            reasons.append("Network policy / dependency / large diff")
        elif scope in {"CLUSTER", "PRODUCTION", "ORGANIZATION"}:
            level = "HIGH"
            reasons.append(f"Scope={scope}")
        if any(d.get("confidence") == "LOW" and d.get("type") == "unknown_downstream" for d in context.get("deps") or []):
            if level == "LOW":
                level = "MEDIUM"
            reasons.append("Unknown downstream dependency")
        return {
            "blast_radius": {"level": level, "reasons": reasons or ["Limited static evidence"], "scope": scope},
            "workloads": "see dependency graph",
            "flags": flags,
        }

    def calculate_risk(self, change: dict, context: dict) -> dict[str, Any]:
        impact = context.get("impact") or self.analyze_impact(change, context)
        flags = change.get("flags") or {}
        reasons = list((impact.get("blast_radius") or {}).get("reasons") or [])
        level = (impact.get("blast_radius") or {}).get("level") or "UNKNOWN"
        # Independent factors that can raise remediation risk
        if flags.get("files_deleted"):
            reasons.append("Files deleted in patch")
            if level in {"LOW", "MEDIUM"}:
                level = "HIGH"
        if context.get("validation_mode") == "STATIC_ONLY":
            reasons.append("Validation mode STATIC_ONLY — dynamic tests not executed")
        if flags.get("secret_access") or flags.get("secret_copied"):
            level = "CRITICAL"
            reasons.append("Secret access or secret copied into image")
        return {"level": level, "reasons": reasons, "validation_mode": context.get("validation_mode") or "STATIC_ONLY"}

    def generate_manager_questions(self, finding: dict, change: dict, context: dict) -> list[str]:
        flags = change.get("flags") or {}
        qs: list[str] = []
        if flags.get("dependency_change") or flags.get("major_dependency"):
            qs.append("MANAGER CONTEXT REQUIRED: Is this dependency API relied upon by production code?")
        if flags.get("pipeline_permission_change") or flags.get("write_all"):
            qs.append("MANAGER CONTEXT REQUIRED: Is this CI/CD permission required for deployment?")
        if flags.get("production_deploy_risk"):
            qs.append("MANAGER CONTEXT REQUIRED: Does this workflow deploy to production?")
        if flags.get("k8s_rbac_change"):
            qs.append("MANAGER CONTEXT REQUIRED: Is this Kubernetes service account used by other workloads?")
        if flags.get("ports_exposed"):
            qs.append("MANAGER CONTEXT REQUIRED: Is this exposed port required by the application?")
        if flags.get("secret_access") or flags.get("secret_copied"):
            qs.append("MANAGER CONTEXT REQUIRED: Does this secret rotation require coordinated application restart?")
        deps = context.get("deps") or change.get("dependencies") or []
        if any(d.get("confidence") == "LOW" for d in deps):
            qs.append("MANAGER CONTEXT REQUIRED: Is this repository shared by multiple services?")
        # Unsupported / partial
        if (context.get("discovery") or {}).get("note") and "Unsupported" in str(
            (context.get("discovery") or {}).get("note")
        ):
            qs.append("MANAGER CONTEXT REQUIRED: Confirm expected remediation scope for this finding type.")
        return qs

    def build_verification_plan(self, finding: dict, change: dict, context: dict) -> dict[str, Any]:
        fid = str(finding.get("id") or "")
        flags = change.get("flags") or {}
        steps = [
            "Do NOT auto-merge, push, or deploy from Change Assurance",
            "Apply change only via authorized human workflow after APPROVED_FOR_EXECUTION",
        ]
        if flags.get("dependency_change"):
            steps.extend(
                [
                    "Re-run dependency scanner",
                    "Confirm vulnerable version absent",
                    "Run approved compatibility test (SAFE_LOCAL_VALIDATION policy only)",
                ]
            )
        elif flags.get("pipeline_permission_change") or flags.get("write_all"):
            steps.extend(
                [
                    "Re-inspect workflow permissions",
                    "Run pipeline validation in non-prod",
                    "Confirm deployment behavior unchanged unless intended",
                ]
            )
        elif flags.get("runs_as_root") or flags.get("secret_copied") or "docker" in fid.lower():
            steps.extend(
                [
                    "Rebuild image in authorized execution phase",
                    "Re-scan image",
                    "Confirm control passes",
                ]
            )
        elif flags.get("k8s_rbac_change") or flags.get("network_policy_change") or flags.get("privileged"):
            steps.extend(
                [
                    "Re-scan manifest / live state (read-only)",
                    "Confirm policy compliance",
                    "Check workload health after human-applied change",
                ]
            )
        else:
            steps.extend(
                [
                    "Re-run scan_devsecops_pack (or originating engine)",
                    "Confirm finding cleared",
                    "Review git diff still matches approved git_diff_hash",
                ]
            )
        steps.append("Deployment success alone must not close the finding")
        return {
            "finding_id": finding.get("id"),
            "method": "static_plus_authorized_re_scan",
            "steps": steps,
            "pass_criteria": "Finding cleared on re-scan AND approved change hash still matches",
            "validation_mode": context.get("validation_mode") or "STATIC_ONLY",
            "auto_execute": False,
        }

    def cross_agent_review_hooks(self, change: dict, context: dict) -> list[dict[str, Any]]:
        flags = change.get("flags") or {}
        hooks = []
        if flags.get("auth_change") or flags.get("security_sensitive_code"):
            hooks.append(
                {
                    "cross_agent_review_required": True,
                    "requested_agent": "security-engineer",
                    "reason": "AUTHORIZATION_CODE_CHANGED",
                    "review_status": "REQUESTED",
                }
            )
        if flags.get("ai") or "ai" in str((context.get("job") or {}).get("title") or "").lower():
            hooks.append(
                {
                    "cross_agent_review_required": True,
                    "requested_agent": "ai-security",
                    "reason": "AI_CONFIGURATION_CHANGED",
                    "review_status": "REQUESTED",
                }
            )
        files = " ".join(str(f.get("file") or "") for f in (change.get("diff_files") or []))
        if ".tf" in files or flags.get("terraform"):
            hooks.append(
                {
                    "cross_agent_review_required": True,
                    "requested_agent": "cloud",
                    "reason": "CLOUD_IAC_CHANGED",
                    "review_status": "REQUESTED",
                }
            )
        return hooks


def infer_devsecops_artifact_type(finding: dict, files: list[str], preview: str) -> str:
    blob = " ".join(files).lower() + " " + (preview or "")[:500].lower()
    fid = str(finding.get("id") or "").upper()
    title = str(finding.get("title") or "").lower()
    if any(x in blob for x in (".tf", "terraform")) or "TERRAFORM" in fid or "IAC" in fid:
        return "terraform"
    if ".github/workflows" in blob or "permissions:" in blob or "pull_request_target" in blob or "CICD" in fid:
        return "github_actions"
    if "dockerfile" in blob or "docker" in title:
        return "dockerfile"
    if any(k in blob for k in ("kind: deployment", "clusterrole", "networkpolicy", "helm", "chart.yaml")) or "K8S" in fid:
        return "kubernetes"
    if any(
        m in blob
        for m in (
            "requirements.txt",
            "package.json",
            "package-lock",
            "go.mod",
            "cargo.toml",
            "pom.xml",
            "pyproject.toml",
        )
    ) or "SCA" in fid or "depend" in title:
        return "dependency_update"
    # Unsupported-ish → still use source_code_patch with CAPABILITY_PARTIAL upstream
    return "source_code_patch"
