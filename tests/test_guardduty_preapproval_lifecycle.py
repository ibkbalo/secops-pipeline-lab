# tests/test_guardduty_preapproval_lifecycle.py
# CLOUD-LOG-003 full pre-approval lifecycle (no apply / no approval).

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from change_assurance.approval_integrity import build_approval_binding, validate_approval_binding
from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.domains.cloud.guardduty_prerequisites import (
    REQUIRED_REMEDIATION_ROLE_PERMISSIONS,
    guardduty_permission_assessment,
)
from change_assurance.evidence_quality import QUALITY_DIRECT, assess_finding_evidence
from change_assurance.plan_ingestion import (
    bind_reviewed_terraform_plan,
    normalize_terraform_plan,
    risk_rationale_from_plan,
    sha256_file,
)
from change_assurance.plan_manager_context import manager_questions_for_plan
from change_assurance.recommendations import _blocking_manager_questions, recommend
from manager_mode import build_manager_card
from predeploy.post_deployment_verification import verification_plan_for_finding


GD_FID = "CLOUD-LOG-003"
GD_TITLE = "GuardDuty detector enabled"

# Minimal terraform plan JSON shape (1 create GuardDuty detector)
PLAN_JSON = {
    "format_version": "1.2",
    "terraform_version": "1.5.0",
    "resource_changes": [
        {
            "address": "aws_guardduty_detector.sentinel",
            "mode": "managed",
            "type": "aws_guardduty_detector",
            "name": "sentinel",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"enable": True},
            },
        }
    ],
}


def _direct_fail_evidence():
    return [
        {
            "api_call": "guardduty.list_detectors",
            "quality": "DIRECT",
            "observed_value": {
                "DetectorIds": [],
                "region": "us-east-1",
                "semantic": True,
                "control_state": "SERVICE_NOT_SUBSCRIBED",
                "code": "SubscriptionRequiredException",
                "human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1",
            },
        }
    ]


def test_01_direct_guardduty_confirmation():
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=_direct_fail_evidence(),
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"


def test_02_plan_normalization_create_only(tmp_path: Path):
    plan = normalize_terraform_plan(
        PLAN_JSON,
        finding_id=GD_FID,
        source_artifact_path="terraform/CLOUD-LOG-003.tf",
        source_artifact_sha256="a" * 64,
        saved_plan_path=str(tmp_path / "CLOUD-LOG-003.tfplan"),
        saved_plan_sha256="b" * 64,
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
    )
    s = plan["summary"]
    assert s["create"] == 1
    assert s["modify"] == 0
    assert s["destroy"] == 0
    assert "aws_guardduty_detector.sentinel" in plan["resource_addresses"]
    assert plan["account_id"] == "952654481542"
    assert plan["region"] == "us-east-1"
    assert plan["execution_role"] == "SentinelStacksRemediationRole"


def test_03_plan_and_artifact_hash_binding(tmp_path: Path):
    src = tmp_path / "CLOUD-LOG-003.tf"
    src.write_text(
        'resource "aws_guardduty_detector" "sentinel" {\n  enable = true\n}\n',
        encoding="utf-8",
    )
    plan_bin = tmp_path / "CLOUD-LOG-003.tfplan"
    plan_bin.write_bytes(b"fake-plan-bytes-for-sha")
    plan_json_path = tmp_path / "CLOUD-LOG-003.tfplan.json"
    plan_json_path.write_text(json.dumps(PLAN_JSON), encoding="utf-8")

    job = {
        "job_id": "job_test_gd",
        "aws_account_id": "952654481542",
        "region": "us-east-1",
        "execution_role": "SentinelStacksRemediationRole",
        "execution_profile": "sentinel-remediation",
        "reviewed_terraform_plans": {
            GD_FID: {
                "plan_path": str(plan_json_path),
                "saved_plan_path": str(plan_bin),
                "working_directory": str(tmp_path),
                "source_artifact_path": str(src),
                "source_artifact_sha256": sha256_file(src),
                "account_id": "952654481542",
                "region": "us-east-1",
                "execution_role": "SentinelStacksRemediationRole",
            }
        },
    }
    bound = bind_reviewed_terraform_plan(
        job,
        GD_FID,
        plan_path=plan_json_path,
        source_artifact_path=src,
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
        execution_profile="sentinel-remediation",
    )
    assert bound["status"] == "BOUND"
    assert bound["saved_plan_sha256"]
    assert bound["source_artifact_sha256"] == sha256_file(src)
    assert bound["execution_identity"].endswith(":role/SentinelStacksRemediationRole")
    assert bound["manager_decision"] == "PENDING"
    assert bound["execution_performed"] is False
    reviewed = bound["reviewed_plan"]
    assert (reviewed.get("summary") or {}).get("create") == 1


def test_04_additive_plan_recommend_approve_not_forced_review():
    # Human approval always required — but must NOT force REVIEW by itself
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
        manager_questions=[
            "MANAGER CONSIDERATION: Enabling Amazon GuardDuty incurs AWS service cost",
            "MANAGER CONSIDERATION: This remediation enables GuardDuty in us-east-1 only",
        ],
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    assert rec["deployment_ready"] is True
    assert rec.get("remediation_status") == "READY"
    assert rec["manager_approval_required"] is True
    assert _blocking_manager_questions(rec.get("manager_considerations")) == []


def test_05_destructive_plan_recommend_logic():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="HIGH",
        remediation_risk="HIGH",
        destructive=True,
        placeholders=False,
    )
    assert rec["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_REJECT"}
    assert rec["deployment_ready"] is False


def test_06_unresolved_prerequisite_blocks_readiness():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=True,
    )
    assert rec["recommendation"] == "REMEDIATION_PREREQUISITES_REQUIRED"
    assert rec.get("remediation_status") == "PREREQUISITES_REQUIRED"
    assert rec["deployment_ready"] is False


def test_07_genuine_business_context_can_cause_review():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
        manager_questions=[
            "MANAGER CONTEXT REQUIRED: Are any S3 buckets intentionally public?",
        ],
    )
    assert rec["recommendation"] == "RECOMMEND_REVIEW"
    assert rec["deployment_ready"] is False


def test_08_human_required_authorization_alone_does_not_force_review():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
        manager_questions=[],
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    assert rec["manager_approval_required"] is True


def test_09_recommendation_not_equal_manager_decision():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    # Recommendation is advisory; manager decision is a separate pending state
    assert "manager_decision" not in rec or rec.get("manager_decision") in {None, "PENDING"}


def test_10_guardduty_considerations_non_blocking():
    qs = manager_questions_for_plan(
        {"id": GD_FID, "title": GD_TITLE},
        flags={"guardduty_enable": True},
        plan_addresses=["aws_guardduty_detector.sentinel"],
        discovery={"region": "us-east-1"},
        evidence_assessment={"finding_status": "CONFIRMED"},
    )
    assert qs
    assert all("MANAGER CONSIDERATION" in q for q in qs)
    assert _blocking_manager_questions(qs) == []


def test_11_risk_rationale_low_for_additive_guardduty():
    plan = normalize_terraform_plan(
        PLAN_JSON,
        finding_id=GD_FID,
        account_id="952654481542",
        region="us-east-1",
    )
    risk = risk_rationale_from_plan(plan)
    assert risk["level"] == "LOW"
    assert "guardduty" in risk["rationale"].lower() or "detector" in risk["rationale"].lower()


def test_12_verification_plan_exists_before_approval():
    vp = verification_plan_for_finding(GD_FID, GD_TITLE)
    steps = " ".join(vp.get("steps") or []).lower()
    assert "list_detectors" in steps
    assert "enabled" in steps
    assert "account" in steps or "region" in steps
    assert "scan_cloud_pack" in steps or "rescan" in steps or "re-run" in steps


def test_13_permission_assessment_unknown_blocks_execution_not_auto_attach():
    assess = guardduty_permission_assessment(
        execution_role="SentinelStacksRemediationRole",
        execution_identity="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
        simulated=None,
    )
    assert assess["execution_permission_ready"] is False
    assert assess["permission_status"] == "UNKNOWN"
    assert assess["policy_auto_attached"] is False
    assert "guardduty:CreateDetector" in REQUIRED_REMEDIATION_ROLE_PERMISSIONS


def test_14_approval_binding_pending_hashes(tmp_path: Path):
    src = tmp_path / "CLOUD-LOG-003.tf"
    src.write_text('resource "aws_guardduty_detector" "sentinel" { enable = true }\n', encoding="utf-8")
    plan_path = tmp_path / "p.json"
    plan_path.write_text(json.dumps(PLAN_JSON), encoding="utf-8")
    plan = normalize_terraform_plan(
        PLAN_JSON,
        finding_id=GD_FID,
        source_artifact_path=str(src),
        source_artifact_sha256=sha256_file(src),
        saved_plan_path=str(plan_path),
        saved_plan_sha256=sha256_file(plan_path),
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
    )
    artifacts = [
        {
            "artifact_id": "a1",
            "artifact_hash": "c" * 64,
            "meta": {
                "saved_plan_sha256": plan["saved_plan_sha256"],
                "source_artifact_sha256": plan["source_artifact_sha256"],
                "execution_role": "SentinelStacksRemediationRole",
                "account_id": "952654481542",
                "region": "us-east-1",
                "terraform_plan_hash": plan.get("plan_content_hash"),
            },
        }
    ]
    binding = build_approval_binding(
        job_id="j1",
        finding_id=GD_FID,
        artifacts=artifacts,
        target_environment="952654481542",
        recommendation="RECOMMEND_APPROVE",
        assurance_report={"reviewed_plan": plan},
        target_identity="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
        manager_decision=None,
    )
    assert binding.get("saved_plan_sha256") or binding.get("terraform_plan_hash") or binding.get(
        "plan_or_diff_hash"
    )
    assert binding.get("manager_decision") in {None, "PENDING", "PENDING_MANAGER_DECISION"}


def test_15_manager_card_shows_approve_pending_no_execution():
    finding = {"id": GD_FID, "title": GD_TITLE, "severity": "high", "description": "GuardDuty off"}
    impact = {
        "finding_status": "CONFIRMED",
        "evidence_quality": "DIRECT",
        "region": "us-east-1",
        "change_assurance": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "remediation_status": "READY",
            "recommendation": "RECOMMEND_APPROVE",
            "recommendation_reasons": [
                "Finding confirmed with direct evidence",
                "Validation passed",
                "No destructive actions",
            ],
            "deployment_ready": True,
            "execution_ready": False,
            "execution_performed": False,
            "manager_decision": None,
            "manager_questions": [
                "MANAGER CONSIDERATION: Enabling Amazon GuardDuty incurs AWS service cost"
            ],
            "manager_context_required": False,
            "reviewed_plan": {
                "summary": {"create": 1, "modify": 0, "destroy": 0},
                "resource_addresses": ["aws_guardduty_detector.sentinel"],
                "saved_plan_sha256": "d" * 64,
                "source_artifact_sha256": "e" * 64,
                "account_id": "952654481542",
                "region": "us-east-1",
                "execution_role": "SentinelStacksRemediationRole",
            },
            "verification": verification_plan_for_finding(GD_FID, GD_TITLE),
            "approval_integrity": {"status": "PENDING_MANAGER_DECISION", "valid": False},
        },
        "evidence_assessment": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "result": "FAIL",
            "evidence_source": "guardduty.list_detectors",
            "observed": {"human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1"},
            "expected": "An enabled GuardDuty detector",
        },
    }
    card = build_manager_card(finding, {"id": "job_test"}, impact=impact, is_primary=True)
    text = str(card).lower()
    assert "recommend_approve" in text or "approve" in text
    assert "pending" in text
    assert "cannot decide alone" not in text
    assert "compromised" not in text


def test_16_no_casebook_success_before_execution():
    # Closure requires attributable execution — open finding without attributed apply is not SUCCESS
    from security_casebook import STATUS_SUCCESS, assess_control_resolution

    result = assess_control_resolution(
        control_ids=[GD_FID],
        before_findings=[{"id": GD_FID, "title": GD_TITLE}],
        after_findings=[{"id": GD_FID, "title": GD_TITLE}],
        before_scan={},
        after_scan={},
    )
    assert str(result.get("status") or "").upper() != STATUS_SUCCESS
    assert result.get("verified") is not True


def test_17_config_and_aa_regressions_still_pass():
    cfg = assess_finding_evidence(
        finding_id="CLOUD-LOG-002",
        title="AWS Config recorder enabled",
        evidence=[
            {
                "api_call": "configservice.describe_configuration_recorders",
                "observed_value": {
                    "ConfigurationRecorders": [],
                    "recorder_count": 0,
                    "region": "us-east-1",
                    "human_observed": "No AWS Config configuration recorder found in us-east-1",
                },
            }
        ],
        specs=cloud_specs(),
    )
    assert cfg["finding_status"] == "CONFIRMED"
    aa = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title="IAM Access Analyzer enabled",
        evidence=[
            {
                "api_call": "accessanalyzer.list_analyzers",
                "observed_value": {
                    "analyzers": [],
                    "active_account_analyzer_count": 0,
                    "region": "us-east-1",
                    "human_observed": "No Access Analyzer found in us-east-1",
                },
            }
        ],
        specs=cloud_specs(),
    )
    assert aa["finding_status"] == "CONFIRMED"
