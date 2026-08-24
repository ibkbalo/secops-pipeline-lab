# Cross-control pre-deploy conflict analysis + S3 MFA Delete applicability.

from __future__ import annotations

from pathlib import Path

from change_assurance.control_conflicts import (
    MANUAL_ONLY,
    NOT_APPLICABLE,
    RECOMMENDED,
    REQUIRED,
    analyze_proposed_change,
)
from change_assurance.domains.cloud.config_prerequisites import render_dedicated_terraform
from change_assurance.domains.cloud.s3_control_conflicts import (
    S3ControlConflictAdapter,
    classify_s3_bucket,
    mfa_delete_applicability,
)
from jinja2 import Environment, FileSystemLoader, select_autoescape
from manager_mode import build_manager_view


def test_01_s3_bucket_without_versioning_detected():
    src = '''
resource "aws_s3_bucket" "app" {
  bucket = "app-data-bucket"
}
'''
    out = analyze_proposed_change(
        reviewed_plan={
            "resources_to_create": ["aws_s3_bucket.app"],
            "resource_addresses": ["aws_s3_bucket.app"],
            "summary": {"create": 1, "modify": 0, "destroy": 0},
        },
        source_terraform=src,
        context={},
    )
    families = {p["control_family"] for p in out["predicted_secondary_findings"]}
    assert "s3_versioning" in families
    assert out["has_blocking_conflicts"] or any(
        p.get("applicability") in {REQUIRED, RECOMMENDED} and p.get("would_fail_after_apply")
        for p in out["predicted_secondary_findings"]
    )
    assert out["remediation_fully_hardened"] is False


def test_02_predeploy_detects_storage_conflict_for_config_style_bucket():
    # Simulate partial Config remotion: bucket exists, recovery companions pending, no versioning
    src = '''
resource "aws_s3_bucket" "config" {
  bucket = "sentinel-aws-config-111122223333-us-east-1"
  tags = { SentinelPurpose = "aws-config-delivery" }
}
resource "aws_s3_bucket_public_access_block" "config" { bucket = aws_s3_bucket.config.id }
resource "aws_s3_bucket_server_side_encryption_configuration" "config" { bucket = aws_s3_bucket.config.id }
'''
    out = analyze_proposed_change(
        reviewed_plan={
            "plan_kind": "recovery",
            "resources_to_create": [
                "aws_s3_bucket_public_access_block.config",
                "aws_s3_bucket_server_side_encryption_configuration.config",
                "aws_s3_bucket_ownership_controls.config",
                "aws_s3_bucket_policy.config",
                "aws_config_configuration_recorder.sentinel",
                "aws_config_delivery_channel.sentinel",
                "aws_config_configuration_recorder_status.sentinel",
            ],
            "summary": {"create": 7, "modify": 0, "destroy": 0},
        },
        source_terraform=src,
        context={
            "existing_resources": [
                "aws_iam_service_linked_role.config",
                "aws_s3_bucket.config",
            ],
            "expected_bucket_name": "sentinel-aws-config-111122223333-us-east-1",
            "bucket_tags": {"SentinelPurpose": "aws-config-delivery"},
        },
    )
    vers = [p for p in out["predicted_secondary_findings"] if p["control_family"] == "s3_versioning"]
    assert vers
    assert vers[0]["would_fail_after_apply"] is True
    assert vers[0]["applicability"] == REQUIRED


def test_03_manager_sees_predicted_secondary_finding():
    mm = build_manager_view(
        {
            "job_id": "job_x",
            "role": "cloud",
            "status": "pending_approval",
            "finding_decisions": {"CLOUD-LOG-002": "pending_recovery"},
            "finding_execution": {
                "CLOUD-LOG-002": {
                    "status": "RECOVERY_REQUIRED",
                    "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
                    "succeeded_resources": ["aws_s3_bucket.config"],
                    "prior_approval_valid": False,
                }
            },
            "approval_status": "APPROVAL_INVALIDATED",
            "execution_performed": True,
        },
        [{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled", "severity": "high"}],
        {
            "primary_finding_id": "CLOUD-LOG-002",
            "finding_status": "FAIL",
            "recommendation": "RECOMMEND_REVIEW",
            "remediation_status": "RECOVERY_REQUIRED",
            "cross_control_impact": {
                "summary_line": "1 blocking cross-control conflict(s), 0 advisory note(s).",
                "has_blocking_conflicts": True,
                "remediation_fully_hardened": False,
            },
            "predicted_secondary_findings": [
                {
                    "title": "S3 versioning missing for proposed/existing bucket",
                    "applicability": "REQUIRED",
                    "severity": "medium",
                    "would_fail_after_apply": True,
                    "manager_message": "versioning is not enabled — CLOUD-STO versioning would fail",
                }
            ],
            "remediation_fully_hardened": False,
            "reviewed_plan": {
                "summary": {"create": 7, "modify": 0, "destroy": 0},
                "manager_affect": {
                    "plan_reviewed": True,
                    "plan_create": 7,
                    "plan_modify": 0,
                    "plan_destroy": 0,
                    "summary_line": "7 CREATE",
                    "resources_to_create": ["x"],
                    "resources_modified": ["NONE"],
                    "resources_destroyed": ["NONE"],
                    "detail_lines": [],
                    "scope": "Regional",
                    "risk_rationale": "MEDIUM",
                    "cloudtrail_bucket": "NOT TOUCHED",
                    "known_dependencies": [],
                    "unknowns": [],
                },
            },
        },
        focus_finding_id="CLOUD-LOG-002",
    )
    primary = mm["primary"]
    assert primary["predicted_secondary_findings"]
    assert primary["remediation_fully_hardened"] is False


def test_04_no_false_fully_hardened_claim():
    out = analyze_proposed_change(
        reviewed_plan={"resources_to_create": ["aws_s3_bucket.x"], "summary": {"create": 1}},
        source_terraform='resource "aws_s3_bucket" "x" { bucket = "x" }\n',
    )
    assert out["remediation_fully_hardened"] is False


def test_05_config_generator_includes_versioning_not_mfa_delete():
    tf = render_dedicated_terraform(check_id="CLOUD-LOG-002")
    assert 'resource "aws_s3_bucket_versioning" "config"' in tf
    assert "status = \"Enabled\"" in tf
    assert "MFADelete" not in tf and "mfa_delete" not in tf.lower()


def test_06_ebs_not_contaminated_by_s3_analysis():
    out = analyze_proposed_change(
        reviewed_plan={"resources_to_create": ["aws_s3_bucket.x"], "summary": {"create": 1}},
        source_terraform='resource "aws_s3_bucket" "x" { bucket = "x" }\n',
    )
    families = {p["control_family"] for p in out["predicted_secondary_findings"]}
    assert "ebs" not in "".join(families).lower()
    assert not any("EBS" in str(p.get("title") or "") for p in out["predicted_secondary_findings"])


def test_07_generic_s3_not_cloud_log_002():
    adapter = S3ControlConflictAdapter()
    preds = adapter.analyze(
        resource_changes=[
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "change": {"actions": ["create"], "after": {"bucket": "app-logs-prod"}},
            }
        ],
        source_terraform='resource "aws_s3_bucket" "logs" { bucket = "app-logs-prod" }\n',
        context={},
    )
    assert any(p["control_family"] == "s3_versioning" for p in preds)
    assert all("CLOUD-LOG-002" not in str(p) for p in preds)


def test_08_mfa_delete_scope_service_delivery_not_applicable():
    assert classify_s3_bucket("sentinel-aws-config-952654481542-us-east-1") == "SERVICE_DELIVERY"
    assert mfa_delete_applicability("SERVICE_DELIVERY") == NOT_APPLICABLE
    assert mfa_delete_applicability("HIGH_VALUE") == MANUAL_ONLY
    assert mfa_delete_applicability("GENERAL") == RECOMMENDED


def test_09_no_automatic_apply_flags():
    out = analyze_proposed_change(
        reviewed_plan={"resources_to_create": ["aws_s3_bucket.x"]},
        source_terraform='resource "aws_s3_bucket" "x" {}\n',
    )
    assert out["auto_apply_forbidden"] is True
    for p in out["predicted_secondary_findings"]:
        assert p.get("terraform_apply") is False
        assert p.get("aws_modified") is False


def test_10_face_render_cross_control_section():
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["url_for"] = lambda *a, **k: "/"
    mm = {
        "version": "test",
        "primary": {
            "finding_id": "CLOUD-LOG-002",
            "plain_title": "AWS Config",
            "severity": "HIGH",
            "security_severity": "HIGH",
            "change_risk": "MEDIUM",
            "recommendation_label": "REVIEW WITH MANAGER",
            "manager_decision": "PENDING",
            "execution": "PARTIAL EXECUTION — RECOVERY REQUIRED",
            "what_found": "fail",
            "why_matters": "x",
            "what_change": "y",
            "after_change": "z",
            "why_recommend": "review",
            "affect": {
                "scope": "Regional",
                "plan_reviewed": True,
                "plan_create": 7,
                "plan_modify": 0,
                "plan_destroy": 0,
                "summary_line": "7 CREATE",
                "resources_to_create": ["a"],
                "resources_modified": ["NONE"],
                "resources_destroyed": ["NONE"],
                "potentially_affected": "scope",
                "expected_downtime": "none",
                "known_dependencies": [],
                "unknowns": [],
                "cloudtrail_bucket": "NOT TOUCHED",
                "detail_lines": [],
            },
            "predicted_secondary_findings": [
                {
                    "title": "S3 versioning missing",
                    "applicability": "REQUIRED",
                    "severity": "medium",
                    "would_fail_after_apply": True,
                    "manager_message": "versioning control would fail",
                }
            ],
            "remediation_fully_hardened": False,
            "cross_control_impact": {"summary_line": "1 blocking cross-control conflict(s), 0 advisory note(s)."},
            "finding_execution": {
                "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
                "previous_execution": "FAILED AFTER PARTIAL SUCCESS",
                "succeeded_resources": ["aws_s3_bucket.config"],
                "prior_approval_valid": False,
            },
            "approval_integrity": {"headline": "APPROVAL NEEDS REVIEW", "message": "x", "needs_review": True},
            "ai_checks": [],
            "learning": {},
            "banner": "HIGH SECURITY ISSUE",
        },
        "manager_decision": "PENDING",
        "execution": "PARTIAL EXECUTION — RECOVERY REQUIRED",
        "finding_rows": [],
        "summary": {"total_findings": 1},
        "recommendation_label": "REVIEW WITH MANAGER",
    }
    html = env.get_template("face/job.html").render(
        job={"job_id": "job_x", "role": "cloud", "status": "pending_approval"},
        review={
            "manager": mm,
            "impact": {},
            "findings": [{"id": "CLOUD-LOG-002", "title": "AWS Config", "severity": "high"}],
            "findings_count": 1,
            "kit_exists": False,
            "kit_files": [],
            "explain": {},
            "risk_score": 1,
            "risk_label": "low",
            "risk_class": "ok",
            "compliance": {},
        },
        FACE_VERSION="test",
    )
    assert "Cross-control impact" in html
    assert "Predicted secondary" in html or "versioning" in html.lower()
    assert "NOT fully hardened" in html or "versioning" in html.lower()
