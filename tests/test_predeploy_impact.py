# tests/test_predeploy_impact.py
# Automated tests for pre-deployment impact analysis (no live AWS required).

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from predeploy import blast_radius
from predeploy import remediation_readiness
from predeploy import terraform_plan_analysis as tfplan
from predeploy.impact_analysis import analyze_job
from predeploy.post_deployment_verification import verify_s3_account_bpa


def test_s3_bpa_no_public_buckets_recommend_approve(tmp_path: Path):
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

    job = {"job_id": "job_test_s3", "kit_path": str(kit), "role": "cloud"}
    findings = [
        {
            "id": "CLOUD-STO-001",
            "title": "S3 account public access block fully enabled",
            "severity": "critical",
            "description": "incomplete",
        }
    ]

    # Patch discovery to avoid AWS
    import predeploy.aws_dependency_discovery as disc

    original = disc.discover_for_findings

    def fake_discover(*args, **kwargs):
        return {
            "kind": "s3_account_bpa",
            "status": "OK",
            "scope": "account-wide",
            "summary": {
                "account_pab": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "bucket_count": 3,
                "public_buckets": 0,
                "public_policy_buckets": 0,
                "public_acl_buckets": 0,
                "website_buckets": 0,
                "finding_status": "CONFIRMED",
            },
            "evidence": [],
            "potentially_affected_workloads": "None detected",
        }

    disc.discover_for_findings = fake_discover  # type: ignore
    try:
        doc = analyze_job(job, findings, try_terraform_cli=False)
    finally:
        disc.discover_for_findings = original  # type: ignore

    assert doc["finding_status"] == "CONFIRMED"
    assert doc["recommendation"] == "RECOMMEND_APPROVE"
    assert doc["manager_approval_required"] is True
    assert doc["auto_apply_forbidden"] is True
    assert doc["deployment_ready"] is True
    assert (doc.get("blast_radius") or {}).get("level") in {"LOW", "MEDIUM"}


def test_s3_bpa_public_website_requires_review(tmp_path: Path):
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
    job = {"job_id": "job_test_s3_pub", "kit_path": str(kit), "role": "cloud"}
    findings = [{"id": "CLOUD-STO-001", "title": "S3 account public access block fully enabled", "severity": "critical"}]

    import predeploy.aws_dependency_discovery as disc

    original = disc.discover_for_findings

    def fake_discover(*args, **kwargs):
        return {
            "kind": "s3_account_bpa",
            "status": "OK",
            "scope": "account-wide",
            "summary": {
                "account_pab": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
                "bucket_count": 2,
                "public_buckets": 1,
                "public_policy_buckets": 1,
                "public_acl_buckets": 0,
                "website_buckets": 1,
                "finding_status": "CONFIRMED",
            },
            "evidence": [],
            "potentially_affected_workloads": "MANAGER CONTEXT REQUIRED — public/website buckets may be intentional",
            "flags_hint": {"public_workload_dependency": True},
        }

    disc.discover_for_findings = fake_discover  # type: ignore
    try:
        doc = analyze_job(job, findings, try_terraform_cli=False)
    finally:
        disc.discover_for_findings = original  # type: ignore

    assert doc["recommendation"] == "RECOMMEND_REVIEW"
    assert doc["deployment_ready"] is False or doc["recommendation"] == "RECOMMEND_REVIEW"


def test_cloudtrail_placeholder_reject(tmp_path: Path):
    tf = """
resource "aws_cloudtrail" "sentinel_org" {
  name           = "sentinel-multi-region-trail"
  s3_bucket_name = "REPLACE_CLOUDTRAIL_BUCKET"
  is_multi_region_trail = true
}
"""
    kit = tmp_path / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zf:
        zf.writestr("terraform/CLOUD-LOG-001.tf", tf)
    analysis = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-001"], try_cli=False)
    assert analysis["flags"]["placeholder_unresolved"] is True
    assert analysis["validate"]["status"] == "FAIL"
    ready = remediation_readiness.compute_recommendation(
        finding_status="CONFIRMED",
        terraform=analysis,
        blast={"level": "MEDIUM"},
        discovery={"summary": {"finding_status": "CONFIRMED"}},
    )
    assert ready["recommendation"] == "RECOMMEND_REJECT"
    assert ready["deployment_ready"] is False


def test_iam_change_high_blast_review():
    blast = blast_radius.classify_blast_radius(
        scope="account-wide",
        terraform_summary={"create": 1, "modify": 0, "replace": 0, "destroy": 0},
        flags={"iam_change": True},
    )
    assert blast["level"] in {"HIGH", "MEDIUM", "CRITICAL"}
    ready = remediation_readiness.compute_recommendation(
        finding_status="CONFIRMED",
        terraform={
            "validate": {"status": "PASS"},
            "plan": {"status": "PASS", "destructive_actions": "NONE", "summary": {"create": 1, "destroy": 0}},
            "flags": {"iam_change": True},
        },
        blast=blast,
        discovery={"potentially_affected_workloads": "MANAGER CONTEXT REQUIRED for IAM privilege reductions"},
    )
    assert ready["recommendation"] == "RECOMMEND_REVIEW"


def test_security_group_open_world_review():
    blast = blast_radius.classify_blast_radius(
        scope="regional",
        flags={"networking_change": True, "public_workload_dependency": True},
        discovery={},
    )
    assert blast["level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    ready = remediation_readiness.compute_recommendation(
        finding_status="CONFIRMED",
        terraform={
            "validate": {"status": "PASS"},
            "plan": {"status": "PASS", "destructive_actions": "NONE", "summary": {"create": 0, "modify": 1, "destroy": 0}},
            "flags": {"networking_change": True},
        },
        blast=blast,
        discovery={"potentially_affected_workloads": "MANAGER CONTEXT REQUIRED — open ingress may be intentional"},
    )
    assert ready["recommendation"] == "RECOMMEND_REVIEW"


def test_terraform_destroy_warning():
    blast = blast_radius.classify_blast_radius(
        scope="resource",
        terraform_summary={"create": 0, "modify": 0, "replace": 0, "destroy": 2},
        flags={"destructive_tf": True},
    )
    assert blast["level"] in {"HIGH", "CRITICAL"}
    ready = remediation_readiness.compute_recommendation(
        finding_status="CONFIRMED",
        terraform={
            "validate": {"status": "PASS"},
            "plan": {"status": "PASS", "destructive_actions": "PRESENT", "summary": {"destroy": 2}},
            "flags": {"destructive_tf": True},
        },
        blast=blast,
    )
    assert ready["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_REJECT"}
    assert ready["deployment_ready"] is False


def test_terraform_validate_failure_reject():
    ready = remediation_readiness.compute_recommendation(
        finding_status="CONFIRMED",
        terraform={
            "validate": {"status": "FAIL", "errors": ["syntax"]},
            "plan": {"status": "FAIL", "destructive_actions": "NONE", "summary": {}},
            "flags": {},
        },
        blast={"level": "LOW"},
    )
    assert ready["recommendation"] == "RECOMMEND_REJECT"


def test_finding_already_remediated():
    ready = remediation_readiness.compute_recommendation(
        finding_status="ALREADY_REMEDIATED",
        terraform={
            "validate": {"status": "PASS"},
            "plan": {"status": "PASS", "destructive_actions": "NONE", "summary": {"create": 1}},
            "flags": {},
        },
        blast={"level": "LOW"},
    )
    assert ready["recommendation"] == "RECOMMEND_REVIEW"
    assert ready["deployment_ready"] is False


def test_post_deploy_s3_pass_and_fail():
    ok = verify_s3_account_bpa(
        {
            "summary": {
                "account_pab": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        }
    )
    assert ok["passed"] is True
    assert ok["finding_remains_open"] is False
    bad = verify_s3_account_bpa({"summary": {"account_pab": {"BlockPublicAcls": False}}})
    assert bad["passed"] is False
    assert bad["finding_remains_open"] is True


def test_static_tf_placeholder_detection():
    sources = {"a.tf": 'bucket = "REPLACE_CLOUDTRAIL_BUCKET"\n'}
    analysis = tfplan.analyze_terraform_sources(sources)
    assert analysis["flags"]["placeholder_unresolved"] is True
    assert analysis["placeholders"][0]["token"] == "REPLACE_CLOUDTRAIL_BUCKET"
