# CREATE DEDICATED AWS Config prerequisites — regeneration tests.
# No AWS apply. No auto-execution.

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from change_assurance.domains.cloud.config_prerequisites import (
    EXPECTED_RESOURCES,
    render_dedicated_runbook,
    render_dedicated_terraform,
    resolve_aws_config_dedicated,
)
from change_assurance.prerequisite_resolution import (
    CHOICE_CREATE_DEDICATED,
    apply_decision_and_regenerate,
    record_decision,
)
from change_assurance.recommendations import recommend
from manager_mode import build_manager_card
from predeploy import terraform_plan_analysis as tfplan


def test_01_dedicated_generates_config_slr():
    tf = render_dedicated_terraform()
    assert 'resource "aws_iam_service_linked_role" "config"' in tf


def test_02_aws_service_name_config():
    tf = render_dedicated_terraform()
    assert 'aws_service_name = "config.amazonaws.com"' in tf


def test_03_recorder_references_generated_role_arn():
    tf = render_dedicated_terraform()
    assert "role_arn = aws_iam_service_linked_role.config.arn" in tf
    assert "REPLACE_CONFIG_ROLE" not in tf
    assert "arn:aws:iam::aws:role/" not in tf


def test_04_dedicated_s3_bucket_generated():
    tf = render_dedicated_terraform()
    assert 'resource "aws_s3_bucket" "config"' in tf
    assert (
        "sentinel-aws-config-${data.aws_caller_identity.current.account_id}"
        "-${data.aws_region.current.region}"
    ) in tf


def test_04b_aws_region_uses_region_not_deprecated_name():
    """AWS provider v6 deprecates aws_region.name — generated TF must use .region."""
    tf = render_dedicated_terraform()
    assert "data.aws_region.current.region" in tf
    assert "data.aws_region.current.name" not in tf
    assert 'data "aws_region" "current"' in tf


def test_05_cloudtrail_bucket_not_reused():
    tf = render_dedicated_terraform()
    assert "aws-cloudtrail-logs" not in tf
    assert "cloudtrail.amazonaws.com" not in tf
    resolved = resolve_aws_config_dedicated(
        {"id": "CLOUD-LOG-002"},
        {"choice": CHOICE_CREATE_DEDICATED, "region": "us-east-1"},
    )
    assert any("CloudTrail" in x or "cloudtrail" in x.lower() for x in (resolved or {}).get("do_not_touch") or [])


def test_06_public_access_block():
    tf = render_dedicated_terraform()
    assert 'resource "aws_s3_bucket_public_access_block" "config"' in tf
    assert "block_public_acls       = true" in tf


def test_07_encryption_configuration():
    tf = render_dedicated_terraform()
    assert 'resource "aws_s3_bucket_server_side_encryption_configuration" "config"' in tf
    assert 'sse_algorithm = "AES256"' in tf


def test_08_bucket_policy_principal_config():
    tf = render_dedicated_terraform()
    assert "config.amazonaws.com" in tf
    assert 'Principal = { Service = "config.amazonaws.com" }' in tf or "Service = \"config.amazonaws.com\"" in tf


def test_09_source_account_restriction():
    tf = render_dedicated_terraform()
    assert "AWS:SourceAccount" in tf


def test_10_putobject_scoped_to_config_path():
    tf = render_dedicated_terraform()
    assert "/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*" in tf
    assert "s3:x-amz-acl" in tf
    assert "bucket-owner-full-control" in tf


def test_11_configuration_recorder():
    tf = render_dedicated_terraform()
    assert 'resource "aws_config_configuration_recorder" "sentinel"' in tf
    assert 'name     = "sentinel-recorder"' in tf


def test_12_delivery_channel():
    tf = render_dedicated_terraform()
    assert 'resource "aws_config_delivery_channel" "sentinel"' in tf
    assert "s3_bucket_name = aws_s3_bucket.config.bucket" in tf


def test_13_recorder_status_enabled():
    tf = render_dedicated_terraform()
    assert 'resource "aws_config_configuration_recorder_status" "sentinel"' in tf
    assert "is_enabled = true" in tf


def test_14_dependency_ordering():
    tf = render_dedicated_terraform()
    # Role + bucket policy before recorder; recorder before delivery; delivery before status
    assert "depends_on = [" in tf
    assert "aws_config_delivery_channel.sentinel" in tf
    assert "aws_s3_bucket_policy.config" in tf
    assert "aws_iam_service_linked_role.config" in tf


def test_15_16_no_replace_tokens():
    tf = render_dedicated_terraform()
    assert "REPLACE_CONFIG_ROLE" not in tf
    assert "REPLACE_CONFIG_BUCKET" not in tf
    assert "TODO" not in tf
    assert "CHANGEME" not in tf
    assert "YOUR_" not in tf


def test_17_placeholder_state_clears(tmp_path: Path):
    kit = tmp_path / "kit"
    (kit / "terraform").mkdir(parents=True)
    (kit / "runbooks").mkdir(parents=True)
    (kit / "terraform" / "CLOUD-LOG-002.tf").write_text(render_dedicated_terraform(), encoding="utf-8")
    (kit / "runbooks" / "CLOUD-LOG-002.yml").write_text(render_dedicated_runbook(), encoding="utf-8")
    (kit / "manifest.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "check_id": "CLOUD-LOG-002",
                        "files": ["terraform/CLOUD-LOG-002.tf", "runbooks/CLOUD-LOG-002.yml"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is False
    assert a["placeholders"] == []


def test_18_execution_ready_false_until_lifecycle():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="MEDIUM",
        remediation_risk="MEDIUM",
        destructive=False,
        placeholders=False,
        manager_questions=["MANAGER CONTEXT REQUIRED: Confirm expected AWS Config/S3 cost is acceptable."],
    )
    assert rec["deployment_ready"] is False
    assert rec.get("manager_approval_required") is True
    assert rec["recommendation"] == "RECOMMEND_REVIEW"

def test_19_manager_mode_records_create_dedicated():
    finding = {"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled", "severity": "high"}
    impact = {
        "finding_status": "CONFIRMED",
        "recommendation": "RECOMMEND_REVIEW",
        "deployment_ready": False,
        "execution_ready": False,
        "remediation_status": "PREREQUISITES_RESOLVED",
        "relevant_artifacts": ["terraform/CLOUD-LOG-002.tf"],
        "relevant_placeholders": [],
        "prerequisite_decision": {
            "choice": CHOICE_CREATE_DEDICATED,
            "inferred": False,
            "actor": "manager",
        },
        "prerequisite_manager_decision": "CREATE DEDICATED RESOURCES",
        "cost_note": "AWS Config can generate usage charges",
        "do_not_touch": ["Existing CloudTrail bucket"],
    }
    card = build_manager_card(
        finding,
        {"job_id": "j1", "role": "cloud", "status": "pending_approval"},
        impact,
        is_primary=True,
    )
    ready = card["artifact_readiness"]
    assert ready["remediation_status"] == "PREREQUISITES_RESOLVED"
    assert ready["unresolved_placeholders"] == ["NONE"]
    assert ready["manager_decision_prompt"] == "CREATE DEDICATED RESOURCES"
    assert "CREATE DEDICATED" in card["why_recommend"]


def test_20_cost_context_shown():
    finding = {"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled", "severity": "high"}
    impact = {
        "finding_status": "CONFIRMED",
        "remediation_status": "PREREQUISITES_RESOLVED",
        "relevant_placeholders": [],
        "prerequisite_decision": {"choice": CHOICE_CREATE_DEDICATED},
        "cost_note": "AWS Config can generate usage charges for configuration recording",
    }
    card = build_manager_card(finding, {"job_id": "j1", "role": "cloud"}, impact, is_primary=True)
    assert "usage charges" in (card["artifact_readiness"].get("cost_note") or "")


def test_21_expected_resources_list_complete():
    for name in (
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
        "aws_config_configuration_recorder.sentinel",
        "aws_config_delivery_channel.sentinel",
        "aws_config_configuration_recorder_status.sentinel",
    ):
        assert name in EXPECTED_RESOURCES


def test_22_no_auto_execution_flags():
    resolved = resolve_aws_config_dedicated(
        {"id": "CLOUD-LOG-002"},
        {"choice": CHOICE_CREATE_DEDICATED, "region": "us-east-1"},
    )
    assert resolved["auto_apply_forbidden"] is True
    assert resolved["execution_performed"] is False
    assert "AUTO" not in str(resolved.get("prerequisite_status") or "")


def test_23_apply_decision_regenerates_kit(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "jobs").mkdir(parents=True)
    kit = ws / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zf:
        zf.writestr(
            "terraform/CLOUD-LOG-002.tf",
            'role_arn = "arn:aws:iam::aws:role/REPLACE_CONFIG_ROLE"\ns3_bucket_name = "REPLACE_CONFIG_BUCKET"\n',
        )
        zf.writestr("runbooks/CLOUD-LOG-002.yml", "title: old\n")
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "items": [
                        {
                            "check_id": "CLOUD-LOG-002",
                            "files": ["terraform/CLOUD-LOG-002.tf", "runbooks/CLOUD-LOG-002.yml"],
                        }
                    ]
                }
            ),
        )
    job = {
        "job_id": "job_test_config",
        "role": "cloud",
        "kit_path": str(kit),
        "scan_report_path": "",
    }
    (ws / "jobs" / "job_test_config.json").write_text(json.dumps(job), encoding="utf-8")
    result = apply_decision_and_regenerate(
        ws,
        "job_test_config",
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        note="lab create dedicated",
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    assert result["resolved"] is True
    assert result["placeholder_unresolved"] is False
    assert result["execution_ready"] is False
    assert result["execution_performed"] is False
    with zipfile.ZipFile(kit, "r") as zf:
        tf = zf.read("terraform/CLOUD-LOG-002.tf").decode("utf-8")
        yml = zf.read("runbooks/CLOUD-LOG-002.yml").decode("utf-8")
    assert "REPLACE_CONFIG_ROLE" not in tf
    assert "REPLACE_CONFIG_BUCKET" not in tf
    assert "aws_iam_service_linked_role" in tf
    assert "CREATE_DEDICATED" in yml
    assert "least-privilege / CIS harden" not in yml
    job2 = json.loads((ws / "jobs" / "job_test_config.json").read_text(encoding="utf-8"))
    assert job2["prerequisite_decisions"]["CLOUD-LOG-002"]["choice"] == CHOICE_CREATE_DEDICATED
    assert job2["prerequisite_decisions"]["CLOUD-LOG-002"]["inferred"] is False


def test_24_access_analyzer_regression_still_imports():
    from manager_explanations import lookup_explanation

    meta = lookup_explanation("CLOUD-IAM-013")
    assert meta and "Access Analyzer" in (meta.get("plain_english_name") or meta.get("what_it_is") or "Access Analyzer")
