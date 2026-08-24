# Plan-aware Change Assurance — real plan JSON fixture tests (no terraform apply).

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from change_assurance.approval_integrity import (
    build_approval_binding,
    validate_approval_binding,
)
from change_assurance.plan_ingestion import (
    ingest_reviewed_plan_for_finding,
    manager_affect_from_plan,
    normalize_terraform_plan,
    risk_rationale_from_plan,
    sha256_file,
    validate_plan_artifact_binding,
)
from manager_mode import _affect_summary, build_manager_card

FIXTURE = Path(__file__).parent / "fixtures" / "CLOUD-LOG-002-review.tfplan.json"
SRC_SHA = "da297d53055b31ca5d91d17b42dca58da79f8582e3b146d93e074b36964fe7fc"


@pytest.fixture(scope="module")
def plan_json() -> dict:
    assert FIXTURE.is_file(), f"missing fixture {FIXTURE}"
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def normalized(plan_json) -> dict:
    plan = normalize_terraform_plan(
        plan_json,
        finding_id="CLOUD-LOG-002",
        source_artifact_path="terraform/CLOUD-LOG-002.tf",
        source_artifact_sha256=SRC_SHA,
        saved_plan_path=str(FIXTURE),
        saved_plan_sha256=sha256_file(FIXTURE),
        account_id="952654481542",
        region="us-east-1",
    )
    plan["manager_affect"] = manager_affect_from_plan(plan)
    plan["risk"] = risk_rationale_from_plan(plan)
    return plan


def test_01_nine_add_zero_change_zero_destroy(normalized):
    s = normalized["summary"]
    assert s["create"] == 9
    assert s["modify"] == 0
    assert s["destroy"] == 0


def test_02_all_nine_addresses_visible(normalized):
    addrs = set(normalized["resource_addresses"])
    expected = {
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
        "aws_s3_bucket_public_access_block.config",
        "aws_s3_bucket_server_side_encryption_configuration.config",
        "aws_s3_bucket_ownership_controls.config",
        "aws_s3_bucket_policy.config",
        "aws_config_configuration_recorder.sentinel",
        "aws_config_delivery_channel.sentinel",
        "aws_config_configuration_recorder_status.sentinel",
    }
    assert expected <= addrs
    assert len(normalized["resources_to_create"]) == 9


def test_03_no_modifications(normalized):
    assert normalized["resources_modified"] == []


def test_04_no_destroys(normalized):
    assert normalized["resources_destroyed"] == []


def test_05_cloudtrail_not_in_plan(normalized):
    assert normalized["cloudtrail_bucket_touched"] is False
    blob = json.dumps(normalized["resource_addresses"])
    assert "cloudtrail" not in blob.lower()


def test_06_dependencies_surfaced(normalized):
    ids = [d["id"] for d in normalized["dependencies"]]
    assert any("service-linked role" in x for x in ids)
    assert any("bucket/policy" in x for x in ids)
    assert any("recorder before delivery" in x for x in ids)
    assert any("delivery channel before recorder" in x for x in ids)
    assert "none_detected" not in ids


def test_07_medium_risk_has_rationale(normalized):
    risk = normalized["risk"]
    assert risk["level"] == "MEDIUM"
    assert "rationale" in risk
    assert "Config" in risk["rationale"] or "IAM" in risk["rationale"]
    assert "modifies zero existing resources" in risk["rationale"].lower() or "modifies/destroys no existing" in risk["rationale"].lower()


def test_08_source_artifact_hash_bound(normalized):
    assert normalized["source_artifact_sha256"] == SRC_SHA.lower()


def test_09_plan_hash_bound_to_approval(normalized):
    art = {
        "artifact_id": "a1",
        "artifact_type": "terraform",
        "artifact_hash": SRC_SHA,
        "proposed_changes": [{"action": "CREATE"}] * 9,
        "meta": {
            "plan_hash": normalized["plan_content_hash"],
            "saved_plan_sha256": normalized["saved_plan_sha256"],
            "source_artifact_sha256": SRC_SHA,
            "plan_account_id": "952654481542",
            "plan_region": "us-east-1",
        },
        "validation": {
            "analysis": {"plan": {"summary": normalized["summary"]}, "reviewed_plan": normalized}
        },
    }
    binding = build_approval_binding(
        job_id="job_t",
        finding_id="CLOUD-LOG-002",
        artifacts=[art],
        target_environment="952654481542",
        recommendation="RECOMMEND_REVIEW",
    )
    assert binding["terraform_plan_hash"] == normalized["plan_content_hash"]
    assert binding["saved_plan_sha256"] == normalized["saved_plan_sha256"]
    assert binding["source_artifact_sha256"] == SRC_SHA.lower()
    sealed = dict(binding)
    sealed["manager_decision"] = "approved"
    sealed["status"] = "APPROVED_FOR_EXECUTION"
    ok = validate_approval_binding(sealed, artifacts=[art], target_environment="952654481542")
    assert ok["valid"] is True


def test_10_source_tf_change_invalidates_approval(normalized):
    art = {
        "artifact_id": "a1",
        "artifact_type": "terraform",
        "artifact_hash": SRC_SHA,
        "meta": {
            "plan_hash": normalized["plan_content_hash"],
            "saved_plan_sha256": normalized["saved_plan_sha256"],
            "source_artifact_sha256": SRC_SHA,
            "plan_account_id": "952654481542",
            "plan_region": "us-east-1",
        },
        "validation": {"analysis": {"reviewed_plan": normalized}},
    }
    binding = build_approval_binding(
        job_id="job_t",
        finding_id="CLOUD-LOG-002",
        artifacts=[art],
        target_environment="x",
        recommendation="RECOMMEND_REVIEW",
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = copy.deepcopy(art)
    art2["artifact_hash"] = "deadbeef" * 8
    art2["meta"]["source_artifact_sha256"] = "deadbeef" * 8
    art2["validation"]["analysis"]["reviewed_plan"] = {
        **normalized,
        "source_artifact_sha256": "deadbeef" * 8,
    }
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="x")
    assert result["valid"] is False
    assert "ARTIFACT_CHANGED" in result["reasons"] or "SOURCE_ARTIFACT_CHANGED" in result["reasons"]


def test_11_plan_change_invalidates_approval(normalized):
    art = {
        "artifact_id": "a1",
        "artifact_type": "terraform",
        "artifact_hash": SRC_SHA,
        "meta": {
            "plan_hash": normalized["plan_content_hash"],
            "saved_plan_sha256": normalized["saved_plan_sha256"],
            "source_artifact_sha256": SRC_SHA,
        },
        "validation": {"analysis": {"reviewed_plan": normalized}},
    }
    binding = build_approval_binding(
        job_id="job_t",
        finding_id="CLOUD-LOG-002",
        artifacts=[art],
        target_environment="x",
        recommendation="RECOMMEND_REVIEW",
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = copy.deepcopy(art)
    art2["meta"]["plan_hash"] = "changed-plan-hash"
    art2["validation"]["analysis"]["reviewed_plan"] = {
        **normalized,
        "plan_content_hash": "changed-plan-hash",
        "saved_plan_sha256": "changed-saved-plan",
    }
    art2["meta"]["saved_plan_sha256"] = "changed-saved-plan"
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="x")
    assert result["valid"] is False
    assert "PLAN_CHANGED" in result["reasons"]


def test_12_account_mismatch_invalidates(normalized):
    check = validate_plan_artifact_binding(
        normalized,
        current_artifact_sha256=SRC_SHA,
        expected_account="000000000000",
        expected_region="us-east-1",
    )
    assert check["valid"] is False
    assert "ACCOUNT_MISMATCH" in check["reasons"]

    art = {
        "artifact_id": "a1",
        "artifact_type": "terraform",
        "artifact_hash": SRC_SHA,
        "meta": {
            "plan_hash": normalized["plan_content_hash"],
            "source_artifact_sha256": SRC_SHA,
            "plan_account_id": "952654481542",
            "plan_region": "us-east-1",
        },
        "validation": {"analysis": {"reviewed_plan": normalized}},
    }
    binding = build_approval_binding(
        job_id="j",
        finding_id="CLOUD-LOG-002",
        artifacts=[art],
        target_environment="x",
        recommendation="RECOMMEND_REVIEW",
        manager_decision="approved",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = copy.deepcopy(art)
    art2["meta"]["plan_account_id"] = "111111111111"
    art2["validation"]["analysis"]["reviewed_plan"] = {**normalized, "account_id": "111111111111"}
    result = validate_approval_binding(binding, artifacts=[art2], target_environment="x")
    assert result["valid"] is False
    assert "ACCOUNT_MISMATCH" in result["reasons"]


def test_13_region_mismatch_invalidates(normalized):
    check = validate_plan_artifact_binding(
        normalized,
        current_artifact_sha256=SRC_SHA,
        expected_account="952654481542",
        expected_region="eu-west-1",
    )
    assert check["valid"] is False
    assert "REGION_MISMATCH" in check["reasons"]


def test_14_no_terraform_apply_markers(normalized):
    assert normalized.get("execution_performed") is False
    assert normalized.get("apply_forbidden") is True


def test_15_access_analyzer_regression_import():
    from change_assurance.domains.cloud.adapter import CloudSecurityAdapter

    adapter = CloudSecurityAdapter()
    deps = adapter.discover_dependencies(
        {"flags": {"access_analyzer_enable": True}, "plan": {}},
        {"finding_id": "CLOUD-IAM-013", "discovery": {}},
    )
    assert deps
    assert deps[0]["type"] == "access_analyzer"
    assert "none_detected" not in str(deps)


def test_16_manager_mode_uses_plan_not_generic(normalized):
    ca = {
        "reviewed_plan": normalized,
        "dependencies": normalized["dependencies"],
        "remediation_risk": normalized["risk"],
        "blast_radius": {"level": "MEDIUM", "scope": "REGIONAL:us-east-1"},
        "recommendation": "RECOMMEND_REVIEW",
    }
    impact = {
        "discovery": {"potentially_affected_workloads": "see change_assurance"},
        "reviewed_plan": normalized,
        "recommendation": "RECOMMEND_REVIEW",
    }
    finding = {
        "id": "CLOUD-LOG-002",
        "title": "AWS Config recorder enabled",
        "severity": "high",
    }
    affect = _affect_summary(impact, ca, finding)
    assert affect["plan_reviewed"] is True
    assert affect["plan_create"] == 9
    assert affect["plan_modify"] == 0
    assert affect["plan_destroy"] == 0
    assert "see change_assurance" not in str(affect["potentially_affected"])
    assert "none_detected" not in [str(x).lower() for x in affect["known_dependencies"]]
    assert any("service-linked" in x for x in affect["known_dependencies"])
    assert affect["cloudtrail_bucket"] == "NOT TOUCHED"
    assert affect["risk_rationale"]

    card = build_manager_card(
        finding,
        {"role": "cloud", "manager_decision": None},
        impact,
        is_primary=True,
    )
    assert "REVIEW" in str(card["recommendation_label"]).upper()
    assert card["affect"]["plan_create"] == 9
    assert card.get("execution") == "NOT PERFORMED"
    assert card.get("manager_decision") in {None, "PENDING", "pending"}


def test_17_ingest_from_job_binding(plan_json):
    job = {
        "reviewed_terraform_plans": {
            "CLOUD-LOG-002": {
                "finding_id": "CLOUD-LOG-002",
                "plan_json": plan_json,
                "source_artifact_sha256": SRC_SHA,
                "region": "us-east-1",
                "account_id": "952654481542",
                "execution_role": "SentinelStacksRemediationRole",
                "execution_profile": "sentinel-remediation",
            }
        }
    }
    reviewed = ingest_reviewed_plan_for_finding(
        job,
        "CLOUD-LOG-002",
        source_artifact_sha256=SRC_SHA,
        region="us-east-1",
        account_id="952654481542",
    )
    assert reviewed is not None
    assert reviewed["summary"]["create"] == 9
    assert reviewed["apply_forbidden"] is True
    assert reviewed["execution_role"] == "SentinelStacksRemediationRole"
    assert "SentinelStacksRemediationRole" in str(reviewed.get("execution_identity") or "")


def test_18_execution_role_change_invalidates_approval(normalized):
    art = {
        "artifact_id": "a1",
        "artifact_type": "terraform",
        "artifact_hash": SRC_SHA,
        "meta": {
            "plan_hash": normalized["plan_content_hash"],
            "saved_plan_sha256": normalized["saved_plan_sha256"],
            "source_artifact_sha256": SRC_SHA,
            "plan_account_id": "952654481542",
            "plan_region": "us-east-1",
            "execution_role": "SentinelStacksRemediationRole",
            "execution_identity": "arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
        },
        "validation": {
            "analysis": {
                "reviewed_plan": {
                    **normalized,
                    "execution_role": "SentinelStacksRemediationRole",
                    "execution_identity": "arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
                }
            }
        },
    }
    binding = build_approval_binding(
        job_id="j",
        finding_id="CLOUD-LOG-002",
        artifacts=[art],
        target_environment="x",
        recommendation="RECOMMEND_REVIEW",
        manager_decision="approved",
        target_identity="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
    )
    binding["status"] = "APPROVED_FOR_EXECUTION"
    art2 = copy.deepcopy(art)
    art2["meta"]["execution_role"] = "OtherRole"
    art2["meta"]["execution_identity"] = "arn:aws:iam::952654481542:role/OtherRole"
    art2["validation"]["analysis"]["reviewed_plan"] = {
        **normalized,
        "execution_role": "OtherRole",
        "execution_identity": "arn:aws:iam::952654481542:role/OtherRole",
    }
    result = validate_approval_binding(
        binding,
        artifacts=[art2],
        target_environment="x",
        target_identity="arn:aws:iam::952654481542:role/OtherRole",
    )
    assert result["valid"] is False
    assert "EXECUTION_ROLE_CHANGED" in result["reasons"]
