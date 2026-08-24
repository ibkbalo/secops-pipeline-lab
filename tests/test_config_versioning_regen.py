# Artifact regen with versioning + stale recovery plan continuity.

from __future__ import annotations

import json
from pathlib import Path

from change_assurance.domains.cloud.config_prerequisites import render_dedicated_terraform
from change_assurance.plan_ingestion import (
    REASON_SOURCE_AFTER_XCONTROL,
    STATUS_PLAN_REGENERATION_REQUIRED,
    supersede_reviewed_plan_for_finding,
)
from manager_mode import build_manager_view
from jinja2 import Environment, FileSystemLoader, select_autoescape


def test_01_create_dedicated_includes_versioning():
    tf = render_dedicated_terraform(check_id="CLOUD-LOG-002")
    assert 'resource "aws_s3_bucket_versioning" "config"' in tf
    assert 'status = "Enabled"' in tf


def test_02_no_mfa_delete_automation():
    tf = render_dedicated_terraform(check_id="CLOUD-LOG-002")
    assert "MFADelete" not in tf
    assert "mfa_delete" not in tf.lower() or "intentionally omitted" in tf.lower()


def test_03_to_07_source_change_supersedes_recovery_plan(tmp_path):
    job = {
        "job_id": "job_regen",
        "status": "pending_approval",
        "manager_decision": None,
        "finding_decisions": {"CLOUD-LOG-002": "pending_recovery"},
        "execution_attempts": [
            {
                "finding_id": "CLOUD-LOG-002",
                "result": "PARTIAL_EXECUTION",
                "succeeded_resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                ],
                "failed_action": "s3:GetBucketCORS",
            }
        ],
        "finding_execution": {
            "CLOUD-LOG-002": {
                "status": "RECOVERY_REQUIRED",
                "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
                "succeeded_resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                ],
                "recovery_plan_bound": True,
                "recovery_plan_summary": {"create": 7, "modify": 0, "destroy": 0},
                "recovery_plan_sha256": "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672",
            }
        },
        "reviewed_terraform_plans": {
            "CLOUD-LOG-002": {
                "plan_path": r"C:\sentinel-labs\aws-config\CLOUD-LOG-002-recovery-v2.tfplan",
                "saved_plan_sha256": "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672",
                "plan_sha256": "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672",
                "summary": {"create": 7, "modify": 0, "destroy": 0},
                "plan_kind": "recovery",
                "source_artifact_sha256": "oldsha",
            }
        },
    }
    out = supersede_reviewed_plan_for_finding(
        job,
        "CLOUD-LOG-002",
        reason=REASON_SOURCE_AFTER_XCONTROL,
        new_source_artifact_path=str(tmp_path / "CLOUD-LOG-002.tf"),
        new_source_artifact_sha256="newsha",
    )
    assert out["status"] == STATUS_PLAN_REGENERATION_REQUIRED
    assert out["prior_plan_sha256"] == "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672"
    assert len(job["reviewed_plan_history"]) == 1
    assert job["reviewed_plan_history"][0]["saved_plan_sha256"] == (
        "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672"
    )
    assert job["reviewed_terraform_plans"]["CLOUD-LOG-002"]["status"] == STATUS_PLAN_REGENERATION_REQUIRED
    assert job["reviewed_terraform_plans"]["CLOUD-LOG-002"]["executable"] is False
    fe = job["finding_execution"]["CLOUD-LOG-002"]
    assert fe["status"] == "RECOVERY_REQUIRED"
    assert fe["recovery_plan_status"] == STATUS_PLAN_REGENERATION_REQUIRED
    assert fe["succeeded_resources"] == [
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
    ]
    assert job["execution_attempts"][0]["failed_action"] == "s3:GetBucketCORS"
    assert job["manager_decision"] is None
    assert job["finding_decisions"]["CLOUD-LOG-002"] == "pending_recovery"


def test_08_no_plan_generated_flag_in_supersede():
    job = {
        "job_id": "j",
        "reviewed_terraform_plans": {
            "X": {"plan_path": "a.tfplan", "saved_plan_sha256": "abc", "plan_kind": "recovery"}
        },
        "finding_execution": {"X": {"status": "RECOVERY_REQUIRED"}},
        "finding_decisions": {},
    }
    out = supersede_reviewed_plan_for_finding(job, "X", reason=REASON_SOURCE_AFTER_XCONTROL)
    assert out["status"] == STATUS_PLAN_REGENERATION_REQUIRED
    # No new plan path invented
    assert job["reviewed_terraform_plans"]["X"].get("plan_kind") == "stale_recovery"


def test_10_face_shows_plan_regeneration_required(tmp_path):
    art = tmp_path / "CLOUD-LOG-002.tf"
    art.write_text(render_dedicated_terraform(), encoding="utf-8")
    job = {
        "job_id": "job_face_regen",
        "role": "cloud",
        "status": "pending_approval",
        "manager_decision": None,
        "approval_status": "APPROVAL_INVALIDATED",
        "execution_performed": True,
        "apply_status": "partial_failed",
        "kit_path": str(tmp_path),
        "finding_decisions": {"CLOUD-LOG-002": "pending_recovery"},
        "prerequisite_resolutions": {
            "CLOUD-LOG-002": {
                "status": "PREREQUISITES_RESOLVED",
                "artifact_path": str(art),
                "artifact_sha256": "abc",
            }
        },
        "finding_execution": {
            "CLOUD-LOG-002": {
                "status": "RECOVERY_REQUIRED",
                "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
                "previous_execution": "FAILED AFTER PARTIAL SUCCESS",
                "succeeded_resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                ],
                "recovery_plan_status": STATUS_PLAN_REGENERATION_REQUIRED,
                "recovery_plan_superseded": True,
                "recovery_plan_superseded_reason": REASON_SOURCE_AFTER_XCONTROL,
                "prior_recovery_plan_path": r"C:\sentinel-labs\aws-config\CLOUD-LOG-002-recovery-v2.tfplan",
                "prior_recovery_plan_sha256": "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672",
                "prior_approval_valid": False,
            }
        },
        "reviewed_terraform_plans": {
            "CLOUD-LOG-002": {
                "status": STATUS_PLAN_REGENERATION_REQUIRED,
                "executable": False,
                "superseded": True,
                "prior_plan_sha256": "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672",
            }
        },
    }
    mm = build_manager_view(
        job,
        [{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled", "severity": "high"}],
        {
            "primary_finding_id": "CLOUD-LOG-002",
            "finding_status": "FAIL",
            "recommendation": "RECOMMEND_REVIEW",
            "remediation_status": "RECOVERY_REQUIRED",
            "remediation_fully_hardened": True,
            "predicted_secondary_findings": [],
            "cross_control_impact": {
                "summary_line": "0 blocking cross-control conflict(s), 0 advisory note(s).",
                "remediation_fully_hardened": True,
            },
        },
        focus_finding_id="CLOUD-LOG-002",
    )
    primary = mm["primary"]
    assert primary["manager_decision"] == "PENDING"
    assert "PARTIAL" in primary["execution"]
    assert primary.get("cross_control_note")
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["url_for"] = lambda *a, **k: "/"
    html = env.get_template("face/job.html").render(
        job=job,
        review={
            "manager": mm,
            "impact": {"finding_status": "FAIL", "recommendation": "RECOMMEND_REVIEW"},
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
    assert "PLAN REGENERATION REQUIRED" in html
    assert "SOURCE_ARTIFACT_CHANGED_AFTER_CROSS_CONTROL_ANALYSIS" in html
    assert "versioning requirement addressed" in html.lower() or "S3 versioning requirement" in html
    assert primary["manager_decision"] == "PENDING"
