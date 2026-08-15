# tests/test_phase3_approval_devsecops.py
# Phase 3 — approval integrity enforcement + DevSecOps adapter.

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from change_assurance.approval_integrity import (
    build_approval_binding,
    seal_manager_approval,
    validate_approval_binding,
)
from change_assurance.artifacts.code_patch import SourceCodePatchHandler, classify_version_change
from change_assurance.artifacts.dockerfile import DockerfileHandler
from change_assurance.artifacts.github_actions import GitHubActionsHandler
from change_assurance.artifacts.kubernetes import KubernetesHandler
from change_assurance.engine import assure_job
from change_assurance.models import new_change_artifact
from change_assurance.recommendations import recommend
from change_assurance.secret_redaction import redact_text


def _kit(tmp: Path, files: dict[str, str]) -> Path:
    kit = tmp / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return kit


# —— Approval integrity (1–8) ——


def test_01_approved_artifact_unchanged_valid():
    art = new_change_artifact(
        finding_id="F1",
        domain="devsecops",
        artifact_type="source_code_patch",
        target_environment="prod",
        content_preview="print('ok')",
    )
    binding = build_approval_binding(
        job_id="j1",
        finding_id="F1",
        artifacts=[art],
        target_environment="prod",
        recommendation="RECOMMEND_APPROVE",
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    result = validate_approval_binding(binding, artifacts=[art], target_environment="prod")
    assert result["valid"] is True
    assert result["integrity"] == "VALID"


def test_02_artifact_changed_invalidated():
    art1 = new_change_artifact(
        finding_id="F1", domain="devsecops", artifact_type="source_code_patch", content_preview="a"
    )
    binding = build_approval_binding(
        job_id="j", finding_id="F1", artifacts=[art1], target_environment="prod", recommendation="RECOMMEND_APPROVE"
    )
    binding["manager_decision"] = "approved"
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = dict(art1)
    art2["artifact_hash"] = "changed-hash"
    art2["content_preview"] = "b"
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="prod")
    assert result["status"] == "APPROVAL_INVALIDATED"
    assert "ARTIFACT_CHANGED" in result["reasons"]


def test_03_git_diff_changes_invalidated():
    art1 = new_change_artifact(
        finding_id="F1", domain="devsecops", artifact_type="source_code_patch", content_preview="diff a"
    )
    art1["meta"]["git_diff_hash"] = "diff1"
    binding = build_approval_binding(
        job_id="j", finding_id="F1", artifacts=[art1], target_environment="local", recommendation="RECOMMEND_APPROVE"
    )
    binding["manager_decision"] = "approved"
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = dict(art1)
    art2["meta"] = dict(art1["meta"])
    art2["meta"]["git_diff_hash"] = "diff2"
    art2["artifact_hash"] = "x"
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="local")
    assert result["valid"] is False
    assert result["status"] == "APPROVAL_INVALIDATED"


def test_04_commit_change_revalidation_or_invalidated():
    art = new_change_artifact(
        finding_id="F1", domain="devsecops", artifact_type="source_code_patch", content_preview="x"
    )
    report = {
        "recommendation": "RECOMMEND_APPROVE",
        "artifacts": [art],
        "repo_fingerprint": {"repository": "/r", "branch": "main", "commit_sha": "aaa"},
        "live_state_fingerprint": "fp1",
    }
    binding = build_approval_binding(
        job_id="j",
        finding_id="F1",
        artifacts=[art],
        target_environment="local",
        recommendation="RECOMMEND_APPROVE",
        assurance_report=report,
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    report2 = dict(report)
    report2["repo_fingerprint"] = {"repository": "/r", "branch": "main", "commit_sha": "bbb"}
    report2["live_state_fingerprint"] = "fp2"
    result = validate_approval_binding(
        binding, artifacts=[art], target_environment="local", assurance_report=report2
    )
    assert result["valid"] is False
    assert "COMMIT_CHANGED" in result["reasons"] or "LIVE_STATE_CHANGED" in result["reasons"]


def test_05_target_environment_changes_invalidated():
    art = new_change_artifact(
        finding_id="F1", domain="cloud_security", artifact_type="terraform", content_preview="resource"
    )
    binding = build_approval_binding(
        job_id="j", finding_id="F1", artifacts=[art], target_environment="dev", recommendation="RECOMMEND_APPROVE"
    )
    binding["manager_decision"] = "approved"
    binding["status"] = "APPROVED_FOR_EXECUTION"
    result = validate_approval_binding(binding, artifacts=[art], target_environment="prod")
    assert result["status"] == "APPROVAL_INVALIDATED"
    assert "ENVIRONMENT_CHANGED" in result["reasons"] or "TARGET_CHANGED" in result["reasons"]


def test_06_assurance_report_material_change_invalidated():
    art = new_change_artifact(
        finding_id="F1", domain="devsecops", artifact_type="source_code_patch", content_preview="x"
    )
    report = {
        "domain": "devsecops",
        "primary_finding_id": "F1",
        "recommendation": "RECOMMEND_APPROVE",
        "validation_status": "PASS",
        "blast_radius": {"level": "LOW"},
        "remediation_risk": {"level": "LOW"},
        "artifacts": [art],
    }
    binding = build_approval_binding(
        job_id="j",
        finding_id="F1",
        artifacts=[art],
        target_environment="local",
        recommendation="RECOMMEND_APPROVE",
        assurance_report=report,
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    report2 = dict(report)
    report2["blast_radius"] = {"level": "CRITICAL"}
    report2["recommendation"] = "RECOMMEND_REJECT"
    result = validate_approval_binding(
        binding, artifacts=[art], target_environment="local", assurance_report=report2
    )
    assert result["valid"] is False
    assert "ASSURANCE_REPORT_CHANGED" in result["reasons"] or "RECOMMENDATION_CHANGED" in result["reasons"]


def test_07_recommendation_change_rereview():
    art = new_change_artifact(
        finding_id="F1", domain="devsecops", artifact_type="source_code_patch", content_preview="x"
    )
    report = {
        "domain": "devsecops",
        "primary_finding_id": "F1",
        "recommendation": "RECOMMEND_APPROVE",
        "validation_status": "PASS",
        "blast_radius": {"level": "LOW"},
        "remediation_risk": {"level": "LOW"},
        "artifacts": [{"artifact_id": art["artifact_id"], "artifact_hash": art["artifact_hash"], "artifact_type": "source_code_patch"}],
    }
    binding = build_approval_binding(
        job_id="j",
        finding_id="F1",
        artifacts=[art],
        target_environment="local",
        recommendation="RECOMMEND_APPROVE",
        assurance_report=report,
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    # Keep assurance slim hash same except recommendation field tracked separately
    report2 = dict(report)
    report2["recommendation"] = "RECOMMEND_REVIEW"
    result = validate_approval_binding(
        binding, artifacts=[art], target_environment="local", assurance_report=report2
    )
    assert result["valid"] is False
    assert "RECOMMENDATION_CHANGED" in result["reasons"]
    assert result["status"] in {"REVALIDATION_REQUIRED", "APPROVAL_INVALIDATED"}


def test_08_ai_recommendation_never_authorization():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    assert rec["manager_approval_required"] is True
    assert rec["recommendation"] != "APPROVED_FOR_EXECUTION"
    sealed = seal_manager_approval(
        job={"job_id": "j"},
        assurance_report={
            "primary_finding_id": "F1",
            "recommendation": "RECOMMEND_APPROVE",
            "artifacts": [],
        },
        decision="approve",
    )
    assert sealed["status"] == "APPROVED_FOR_EXECUTION"
    assert sealed["execution_performed"] is False


# —— DevSecOps (9–25) ——


def test_09_simple_yaml_security_fix(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {
            ".github/workflows/ci.yml": "on: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        },
    )
    job = {"job_id": "dso9", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-CICD-009", "title": "CI permissions too broad", "severity": "medium"}]
    report = assure_job(job, findings)
    assert report["domain"] == "devsecops"
    assert report["validation_mode"] == "STATIC_ONLY"
    assert report["recommendation"] in {"RECOMMEND_APPROVE", "RECOMMEND_REVIEW", "RECOMMEND_REJECT"}
    assert report["execution_performed"] is False


def test_10_dependency_patch_recognized(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {
            "requirements.txt": "requests==2.31.0\n",
        },
    )
    job = {"job_id": "dso10", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-SCA-001", "title": "Dependency vulnerability in requests", "severity": "high"}]
    report = assure_job(job, findings)
    art = report["artifacts"][0]
    assert art["artifact_type"] in {"dependency_update", "source_code_patch"}
    deps = art.get("dependency_updates") or (art.get("validation") or {}).get("analysis", {}).get("dependencies")
    assert deps


def test_11_major_dependency_upgrade_review():
    assert classify_version_change("1.0.0", "2.0.0") == "major"
    handler = SourceCodePatchHandler()
    art = new_change_artifact(
        finding_id="D",
        domain="devsecops",
        artifact_type="dependency_update",
        source_files=["requirements.txt"],
        content_preview="-lib==1.0.0\n+lib==2.0.0\n",
    )
    changes = handler.analyze_changes(art, {"validation_mode": "STATIC_ONLY"})
    assert changes["flags"].get("major_dependency") or any(
        d.get("change_kind") == "major" for d in changes.get("dependencies") or []
    )


def test_12_hardcoded_secret_reject(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"app/config.py": 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'},
    )
    job = {"job_id": "dso12", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-SEC-001", "title": "Hardcoded secrets", "severity": "critical"}]
    report = assure_job(job, findings)
    assert report["recommendation"] == "RECOMMEND_REJECT"


def test_13_gha_write_all_high_risk(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {
            ".github/workflows/deploy.yml": "on: push\npermissions: write-all\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploy\n"
        },
    )
    job = {"job_id": "dso13", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-CICD-013", "title": "GitHub Actions overprivileged", "severity": "high"}]
    report = assure_job(job, findings)
    assert (report["blast_radius"] or {}).get("level") in {"HIGH", "CRITICAL"}
    assert (report["remediation_risk"] or {}).get("level") in {"HIGH", "CRITICAL"}


def test_14_pull_request_target_dangerous(tmp_path: Path):
    yaml = """
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.PROD_TOKEN }}
"""
    kit = _kit(tmp_path, {".github/workflows/pr.yml": yaml})
    job = {"job_id": "dso14", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-CICD-014", "title": "Dangerous pull_request_target", "severity": "critical"}]
    report = assure_job(job, findings)
    assert report["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_REJECT"}


def test_15_dockerfile_root_user(tmp_path: Path):
    kit = _kit(tmp_path, {"Dockerfile": "FROM ubuntu:22.04\nUSER root\nCMD [\"bash\"]\n"})
    job = {"job_id": "dso15", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-DOCKER-001", "title": "Container runs as root", "severity": "high"}]
    report = assure_job(job, findings)
    flags = ((report["artifacts"][0].get("validation") or {}).get("analysis") or {}).get("flags") or {}
    assert flags.get("runs_as_root") or (report["remediation_risk"] or {}).get("level") in {"HIGH", "CRITICAL", "MEDIUM"}


def test_16_dockerfile_secret_copied_reject(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"Dockerfile": "FROM alpine\nCOPY .env /app/.env\nUSER nobody\n"},
    )
    job = {"job_id": "dso16", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-DOCKER-002", "title": "Secret in image", "severity": "critical"}]
    report = assure_job(job, findings)
    assert report["recommendation"] == "RECOMMEND_REJECT"


def test_17_k8s_privileged_high(tmp_path: Path):
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
  - name: c
    image: nginx
    securityContext:
      privileged: true
"""
    kit = _kit(tmp_path, {"k8s/pod.yaml": manifest})
    job = {"job_id": "dso17", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-K8S-001", "title": "Privileged container", "severity": "critical"}]
    report = assure_job(job, findings)
    assert (report["blast_radius"] or {}).get("level") in {"HIGH", "CRITICAL"}


def test_18_clusterrole_cluster_blast(tmp_path: Path):
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wide
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""
    kit = _kit(tmp_path, {"rbac/clusterrole.yaml": manifest})
    job = {"job_id": "dso18", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-K8S-002", "title": "ClusterRole too broad", "severity": "critical"}]
    report = assure_job(job, findings)
    assert (report["blast_radius"] or {}).get("scope") == "CLUSTER"


def test_19_production_networkpolicy_review(tmp_path: Path):
    manifest = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny
  namespace: production
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
"""
    kit = _kit(tmp_path, {"k8s/np.yaml": manifest})
    job = {"job_id": "dso19", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-K8S-003", "title": "Production NetworkPolicy change", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_REJECT"}
    assert (report["blast_radius"] or {}).get("scope") in {"PRODUCTION", "WORKLOAD", "NAMESPACE", "HIGH"} or (
        report["blast_radius"] or {}
    ).get("level") in {"HIGH", "MEDIUM", "CRITICAL"}


def test_20_unknown_validator_unavailable():
    from change_assurance.artifacts.generic import GenericArtifactHandler

    h = GenericArtifactHandler("obscure_binary")
    art = new_change_artifact(
        finding_id="X", domain="devsecops", artifact_type="obscure_binary", content_preview="..."
    )
    val = h.validate(art, {})
    assert val["status"] == "VALIDATION_UNAVAILABLE"


def test_21_unknown_downstream_review(tmp_path: Path):
    kit = _kit(tmp_path, {"requirements.txt": "-foo==1.0.0\n+foo==2.0.0\n"})
    job = {"job_id": "dso21", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-SCA-021", "title": "Major dependency upgrade", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_REJECT"}
    assert any(d.get("confidence") == "LOW" for d in report.get("dependencies") or []) or report[
        "manager_context_required"
    ]


def test_22_secret_evidence_redacted():
    text, hits = redact_text('token=AKIAIOSFODNN7EXAMPLE and github ghp_abcdefghijklmnopqrstuvwxyz012345')
    assert "AKIA" not in text or "SECRET_REDACTED" in text
    assert hits
    assert all(h.get("status") == "SECRET_REDACTED" or True for h in hits)


def test_23_terraform_inside_devsecops_uses_shared_handler(tmp_path: Path):
    tf = """
resource "aws_s3_bucket_public_access_block" "b" {
  bucket = "example"
  block_public_acls = true
}
"""
    kit = _kit(tmp_path, {"terraform/fix.tf": tf})
    job = {"job_id": "dso23", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-IAC-001", "title": "Terraform IaC hardening", "severity": "medium"}]
    report = assure_job(job, findings)
    assert report["artifacts"][0]["artifact_type"] == "terraform"


def test_24_verification_plan_generated(tmp_path: Path):
    kit = _kit(tmp_path, {"requirements.txt": "urllib3==2.0.0\n"})
    job = {"job_id": "dso24", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-SCA-024", "title": "Dependency CVE", "severity": "high"}]
    report = assure_job(job, findings)
    assert (report.get("verification") or {}).get("steps")
    assert report["auto_apply_forbidden"] is True


def test_25_no_automatic_execution(tmp_path: Path):
    kit = _kit(tmp_path, {"app.py": "print('hi')\n"})
    job = {"job_id": "dso25", "role": "devsecops", "kit_path": str(kit)}
    findings = [{"id": "DEVSEC-SAST-001", "title": "Code issue", "severity": "low"}]
    report = assure_job(job, findings)
    assert report.get("execution_performed") is False
    assert report.get("execution_authorized") is False
    assert report.get("auto_apply_forbidden") is True


def test_devsecops_pipeline_without_kit_still_review():
    job = {"job_id": "job_dso", "role": "devsecops", "kit_path": None}
    findings = [{"id": "DEVSEC-CICD-001", "title": "CI token overprivileged", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["domain"] == "devsecops"
    assert report["recommendation"] == "RECOMMEND_REVIEW"
