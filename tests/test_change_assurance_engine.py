# tests/test_change_assurance_engine.py
# Shared Change Assurance Engine tests (multi-domain, non-cloud-specific).

from __future__ import annotations

import zipfile
from pathlib import Path

from change_assurance.approval_integrity import build_approval_binding, validate_approval_binding
from change_assurance.engine import assure_job
from change_assurance.models import new_change_artifact
from change_assurance.recommendations import recommend


def test_generic_unknown_domain_review():
    job = {"job_id": "job_unknown", "role": "unknown-role", "kit_path": None}
    findings = [{"id": "X-001", "title": "Generic issue", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["type"] == "change_assurance_report"
    assert report["recommendation"] in {
        "RECOMMEND_REVIEW",
        "RECOMMEND_REJECT",
        "NO_ACTION_REQUIRED",
        "REMEDIATION_PREREQUISITES_REQUIRED",
    }
    assert report["manager_approval_required"] is True
    assert report["auto_apply_forbidden"] is True
    assert report["recommendation"] != "APPROVED"  # never authorization


def test_unknown_artifact_validation_unavailable(tmp_path: Path):
    job = {
        "job_id": "job_se",
        "role": "security-engineer",
        "kit_path": None,
    }
    findings = [{"id": "PERIM-DATA-001", "title": "Exposed admin", "severity": "critical"}]
    report = assure_job(job, findings)
    assert report["domain"] == "security_engineering"
    assert report["validation_status"] in {"VALIDATION_UNAVAILABLE", "FAIL", "UNKNOWN"}
    assert report["recommendation"] == "RECOMMEND_REVIEW"
    assert report["manager_context_required"] is True


def test_approval_invalidated_when_artifact_changes():
    art1 = new_change_artifact(
        finding_id="F1",
        domain="devsecops",
        artifact_type="source_code_patch",
        content_preview="print('a')",
    )
    binding = build_approval_binding(
        job_id="job1",
        finding_id="F1",
        artifacts=[art1],
        target_environment="prod",
        recommendation="RECOMMEND_APPROVE",
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = dict(art1)
    art2["content_preview"] = "print('b')"
    art2["artifact_hash"] = "changed"
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="prod")
    assert result["status"] == "APPROVAL_INVALIDATED"
    assert result["valid"] is False


def test_recommendation_never_equals_authorization():
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
    assert "APPROVE" != rec["recommendation"] or rec["recommendation"].startswith("RECOMMEND_")


def test_cloud_s3_still_works_via_engine(tmp_path: Path):
    tf = """
resource "aws_s3_account_public_access_block" "sentinel" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
    kit = tmp_path / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zf:
        zf.writestr("terraform/CLOUD-STO-001.tf", tf)
    job = {"job_id": "job_cloud_s3", "role": "cloud", "kit_path": str(kit)}
    findings = [
        {
            "id": "CLOUD-STO-001",
            "title": "S3 account public access block fully enabled",
            "severity": "critical",
        }
    ]
    import predeploy.aws_dependency_discovery as disc

    original = disc.discover_for_findings

    def fake(*a, **k):
        return {
            "kind": "s3_account_bpa",
            "status": "OK",
            "scope": "account-wide",
            "account_id": "123",
            "summary": {
                "account_pab": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "bucket_count": 1,
                "public_buckets": 0,
                "public_policy_buckets": 0,
                "public_acl_buckets": 0,
                "website_buckets": 0,
                "finding_status": "CONFIRMED",
            },
            "evidence": [
                {
                    "api_call": "s3control.get_public_access_block",
                    "observed_value": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "quality": "DIRECT",
                    "purpose": "proof",
                }
            ],
            "potentially_affected_workloads": "None detected",
        }

    disc.discover_for_findings = fake  # type: ignore
    try:
        report = assure_job(job, findings, try_terraform_cli=False)
    finally:
        disc.discover_for_findings = original  # type: ignore
    assert report["domain"] == "cloud_security"
    assert report["recommendation"] == "RECOMMEND_APPROVE"
    assert report["legacy_impact"]["recommendation"] == "RECOMMEND_APPROVE"


def test_devsecops_stub_pipeline_permission_review():
    job = {"job_id": "job_dso", "role": "devsecops", "kit_path": None}
    findings = [{"id": "DEVSEC-CICD-001", "title": "CI token overprivileged", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["domain"] == "devsecops"
    assert report["recommendation"] == "RECOMMEND_REVIEW"
    # Real adapter may still ask manager context; recommendation remains advisory
    assert report["manager_approval_required"] is True
    assert report["auto_apply_forbidden"] is True


def test_ai_security_tool_removal_review():
    job = {"job_id": "job_ai", "role": "ai-security", "kit_path": None}
    findings = [{"id": "AISEC-TOOL-001", "title": "Dangerous write tool enabled", "severity": "critical"}]
    report = assure_job(job, findings)
    assert report["domain"] == "ai_security"
    assert report["blast_radius"]["level"] == "UNKNOWN"
    assert report["recommendation"] == "RECOMMEND_REVIEW"
    assert report["manager_context_required"] is True


def test_security_engineering_identity_review():
    job = {"job_id": "job_se2", "role": "security-engineer", "kit_path": None}
    findings = [{"id": "PERIM-ID-001", "title": "Broad admin group", "severity": "high"}]
    report = assure_job(job, findings)
    assert report["domain"] == "security_engineering"
    assert report["recommendation"] == "RECOMMEND_REVIEW"
