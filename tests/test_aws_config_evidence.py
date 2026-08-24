# tests/test_aws_config_evidence.py
# CLOUD-LOG-002 / AWS Config recorder — cross-service evidence binding.

from __future__ import annotations

from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import (
    EVIDENCE_CONTROL_MISMATCH,
    QUALITY_DIRECT,
    QUALITY_ERROR,
    QUALITY_INDIRECT,
    assess_finding_evidence,
    evidence_control_mismatch_reason,
    match_spec,
)
from manager_mode import build_manager_card
from predeploy.aws_dependency_discovery import discover_for_findings


CONFIG_TITLE = "AWS Config recorder enabled"
CONFIG_FID = "CLOUD-LOG-002"


def test_01_empty_recorders_direct_fail_confirmed():
    evidence = [
        {
            "api_call": "configservice.describe_configuration_recorders",
            "observed_value": {
                "ConfigurationRecorders": [],
                "recorder_count": 0,
                "region": "us-east-1",
                "human_observed": "No AWS Config configuration recorder found in us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=CONFIG_FID,
        title=CONFIG_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"
    assert "configservice.describe_configuration_recorders" in str(result["evidence_source"])
    assert "us-east-1" in str(result.get("observed") or result.get("manager_summary"))


def test_02_recorder_exists_recording_true_pass():
    evidence = [
        {
            "api_call": "configservice.describe_configuration_recorders",
            "observed_value": {
                "ConfigurationRecorders": [{"name": "default"}],
                "recorder_count": 1,
                "recording": True,
                "ConfigurationRecordersStatus": [{"name": "default", "recording": True}],
                "region": "us-east-1",
                "human_observed": "AWS Config configuration recorder recording in us-east-1",
            },
        },
        {
            "api_call": "configservice.describe_configuration_recorder_status",
            "observed_value": {
                "ConfigurationRecordersStatus": [{"name": "default", "recording": True}],
                "recording": True,
                "region": "us-east-1",
                "human_observed": "AWS Config configuration recorder recording in us-east-1",
            },
        },
    ]
    result = assess_finding_evidence(
        finding_id=CONFIG_FID,
        title=CONFIG_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "ALREADY_REMEDIATED"
    assert result["result"] == "PASS"


def test_03_recorder_exists_recording_false_fail():
    evidence = [
        {
            "api_call": "configservice.describe_configuration_recorders",
            "observed_value": {
                "ConfigurationRecorders": [{"name": "default"}],
                "recorder_count": 1,
                "recording": False,
                "ConfigurationRecordersStatus": [{"name": "default", "recording": False}],
                "region": "us-east-1",
                "human_observed": "AWS Config configuration recorder exists but is not recording in us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=CONFIG_FID,
        title=CONFIG_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["result"] == "FAIL"
    assert result["evidence_quality"] == QUALITY_DIRECT


def test_04_access_denied_error_unverified_path():
    evidence = [
        {
            "api_call": "configservice.describe_configuration_recorders",
            "observed_value": {
                "error": "AccessDenied",
                "code": "AccessDeniedException",
                "region": "us-east-1",
                "human_observed": "AWS Config API error in us-east-1: AccessDeniedException",
            },
            "quality": "ERROR",
        }
    ]
    result = assess_finding_evidence(
        finding_id=CONFIG_FID,
        title=CONFIG_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] in {"ERROR", "UNVERIFIED"}
    assert result["finding_status"] != "ALREADY_REMEDIATED"
    assert result["finding_status"] != "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_ERROR


def test_05_cloudtrail_cannot_prove_config_control():
    evidence = [
        {
            "api_call": "cloudtrail.describe_trails",
            "observed_value": {"trail_count": 1, "multi_region": True},
            "quality": "DIRECT",
        }
    ]
    result = assess_finding_evidence(
        finding_id=CONFIG_FID,
        title=CONFIG_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] != "ALREADY_REMEDIATED"
    assert result["finding_status"] != "CONFIRMED" or result["evidence_quality"] != QUALITY_DIRECT
    assert result["finding_status"] == "UNVERIFIED"
    labeled = result.get("labeled_evidence") or []
    assert labeled
    assert labeled[0]["quality"] == QUALITY_INDIRECT
    assert result.get("evidence_control_mismatch") is True
    assert EVIDENCE_CONTROL_MISMATCH in (result.get("reason") or "")


def test_06_cross_service_mismatch_helper():
    spec = match_spec(cloud_specs(), finding_id=CONFIG_FID, title=CONFIG_TITLE)
    assert spec is not None
    assert spec.control_key == "aws_config_recorder"
    reason = evidence_control_mismatch_reason(spec, "cloudtrail.describe_trails")
    assert reason and EVIDENCE_CONTROL_MISMATCH in reason

    aa = match_spec(cloud_specs(), finding_id="CLOUD-IAM-013", title="IAM Access Analyzer enabled")
    assert aa is not None
    bad = evidence_control_mismatch_reason(aa, "iam.get_account_password_policy")
    assert bad and EVIDENCE_CONTROL_MISMATCH in bad


def test_07_region_preserved_in_manager_card():
    finding = {
        "id": CONFIG_FID,
        "title": CONFIG_TITLE,
        "severity": "high",
        "description": "AWS Config is not recording",
    }
    job = {"job_id": "job_cfg", "role": "cloud", "status": "pending_approval"}
    impact = {
        "finding_status": "CONFIRMED",
        "evidence_quality": "DIRECT",
        "change_assurance": {
            "finding_status": "CONFIRMED",
            "recommendation": "RECOMMEND_REVIEW",
            "remediation_risk": {"level": "LOW"},
            "validation_status": "PASS",
            "deployment_ready": False,
            "evidence_assessment": {
                "finding_status": "CONFIRMED",
                "evidence_quality": "DIRECT",
                "result": "FAIL",
                "evidence_source": "configservice.describe_configuration_recorders",
                "observed": {
                    "region": "us-east-1",
                    "human_observed": "No AWS Config configuration recorder found in us-east-1",
                },
                "expected": "An enabled/recording AWS Config configuration recorder",
                "labeled_evidence": [
                    {
                        "api_call": "configservice.describe_configuration_recorders",
                        "quality": "DIRECT",
                        "observed_value": {
                            "ConfigurationRecorders": [],
                            "region": "us-east-1",
                            "human_observed": "No AWS Config configuration recorder found in us-east-1",
                        },
                    }
                ],
            },
            "relevant_artifacts": [],
        },
    }
    card = build_manager_card(finding, job, impact, is_primary=True)
    proof = card["evidence_proof"]
    assert proof["finding_status"] == "CONFIRMED"
    assert proof["result"] == "FAIL"
    assert "configservice.describe_configuration_recorders" in str(proof["evidence_source"])
    assert "No AWS Config configuration recorder found in us-east-1" in str(proof["observed"])
    assert "trail_count" not in str(proof["observed"]).lower()
    assert card["recommendation_label"] == "REVIEW WITH MANAGER"
    assert "ALREADY" not in str(card.get("finding_status_label") or "").upper()


def test_08_access_analyzer_direct_evidence_still_correct():
    evidence = [
        {
            "api_call": "accessanalyzer.list_analyzers",
            "observed_value": {
                "analyzers": [],
                "active_account_analyzer_count": 0,
                "region": "us-east-1",
                "human_observed": "No Access Analyzer found in us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title="IAM Access Analyzer enabled",
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["evidence_source"] == "accessanalyzer.list_analyzers"


def test_09_discovery_routes_config_not_cloudtrail(monkeypatch):
    captured = {}

    def fake_config(**kwargs):
        captured["called"] = "config"
        captured["kwargs"] = kwargs
        return {
            "kind": "aws_config",
            "status": "OK",
            "region": kwargs.get("region"),
            "summary": {"finding_status": "CONFIRMED"},
            "evidence": [],
            "evidence_assessment": {"finding_status": "CONFIRMED"},
        }

    def fake_trail(**kwargs):
        captured["called"] = "trail"
        return {"kind": "cloudtrail", "status": "OK"}

    monkeypatch.setattr(
        "predeploy.aws_dependency_discovery.discover_aws_config", fake_config
    )
    monkeypatch.setattr(
        "predeploy.aws_dependency_discovery.discover_cloudtrail", fake_trail
    )
    out = discover_for_findings(
        [CONFIG_FID],
        [{"id": CONFIG_FID, "title": CONFIG_TITLE}],
        profile="sentinel-demo",
        region="us-east-1",
    )
    assert captured.get("called") == "config"
    assert out["kind"] == "aws_config"
    assert captured["kwargs"]["region"] == "us-east-1"


def test_10_no_auto_execution_flags():
    from change_assurance.recommendations import recommend

    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec.get("auto_apply") is not True
    assert rec["recommendation"] in {"RECOMMEND_REVIEW", "RECOMMEND_APPROVE", "RECOMMEND_REJECT"}
    assert rec["recommendation"] != "NO_ACTION_REQUIRED"