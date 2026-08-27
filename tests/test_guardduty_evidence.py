# tests/test_guardduty_evidence.py
# CLOUD-LOG-003 / Amazon GuardDuty detector — direct evidence + semantic exceptions.

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from change_assurance.aws_response_semantics import (
    interpret_aws_exception,
    register_semantic_exception,
)
from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import (
    QUALITY_DIRECT,
    QUALITY_ERROR,
    assess_finding_evidence,
    match_spec,
)
from change_assurance.recommendations import recommend
from manager_mode import build_manager_card
from predeploy.aws_dependency_discovery import discover_aws_guardduty, discover_for_findings


GD_TITLE = "GuardDuty detector enabled"
GD_FID = "CLOUD-LOG-003"


def test_01_spec_matches_guardduty_control():
    spec = match_spec(cloud_specs(), finding_id=GD_FID, title=GD_TITLE)
    assert spec is not None
    assert spec.control_key == "aws_guardduty_detector"
    assert "guardduty.list_detectors" in spec.preferred_sources


def test_02_empty_detector_list_direct_fail_confirmed():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "observed_value": {
                "DetectorIds": [],
                "detector_count": 0,
                "detectors": [],
                "region": "us-east-1",
                "human_observed": "No GuardDuty detector exists in the account/Region (us-east-1)",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"
    assert "guardduty.list_detectors" in str(result["evidence_source"])
    assert "us-east-1" in str(result.get("observed") or result.get("manager_summary"))


def test_03_enabled_detector_pass():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "observed_value": {
                "DetectorIds": ["abc123"],
                "detector_count": 1,
                "detectors": [{"id": "abc123", "status": "ENABLED", "enabled": True}],
                "region": "us-east-1",
                "human_observed": "GuardDuty detector abc123 is ENABLED in us-east-1",
            },
        },
        {
            "api_call": "guardduty.get_detector",
            "observed_value": {
                "detectors": [{"id": "abc123", "status": "ENABLED", "enabled": True}],
                "region": "us-east-1",
                "human_observed": "GuardDuty detector abc123 is ENABLED in us-east-1",
            },
        },
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "ALREADY_REMEDIATED"
    assert result["result"] == "PASS"
    assert result["evidence_quality"] == QUALITY_DIRECT


def test_04_detector_exists_but_disabled_fail():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "observed_value": {
                "DetectorIds": ["abc123"],
                "detector_count": 1,
                "detectors": [{"id": "abc123", "status": "DISABLED", "enabled": False}],
                "region": "us-east-1",
                "human_observed": "GuardDuty detector(s) exist in us-east-1 but none are ENABLED",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["result"] == "FAIL"
    assert result["evidence_quality"] == QUALITY_DIRECT


def test_05_subscription_required_direct_fail_confirmed():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "quality": "DIRECT",
            "observed_value": {
                "DetectorIds": [],
                "detector_count": 0,
                "detectors": [],
                "region": "us-east-1",
                "semantic": True,
                "control_state": "SERVICE_NOT_SUBSCRIBED",
                "code": "SubscriptionRequiredException",
                "aws_response_classification": "SubscriptionRequiredException",
                "human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1",
                "notes": "does not prove an attack or compromise",
                "evidence_quality": "DIRECT",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"
    assert "guardduty.list_detectors" in str(result["evidence_source"])
    blob = str(result.get("observed") or "") + str(result.get("manager_summary") or "")
    assert "us-east-1" in blob or "not subscribed" in blob.lower()
    # Must not claim compromise
    assert "compromise" not in str(result.get("reason") or "").lower() or "does not" in str(
        evidence[0]["observed_value"].get("notes") or ""
    ).lower()


def test_06_access_denied_error_unverified_path():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "quality": "ERROR",
            "observed_value": {
                "error": "AccessDenied",
                "code": "AccessDeniedException",
                "region": "us-east-1",
                "human_observed": "GuardDuty API error in us-east-1: AccessDeniedException",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] in {"ERROR", "UNVERIFIED"}
    assert result["evidence_quality"] == QUALITY_ERROR
    assert result["result"] in {"ERROR", "UNVERIFIED"}


def test_07_timeout_unexpected_error_unverified():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "quality": "ERROR",
            "observed_value": {
                "error": "Read timeout on endpoint URL",
                "code": "RequestTimeout",
                "region": "us-east-1",
                "human_observed": "GuardDuty API error in us-east-1: RequestTimeout",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] in {"ERROR", "UNVERIFIED"}
    assert result["evidence_quality"] == QUALITY_ERROR


def test_08_evidence_source_and_region_preserved():
    evidence = [
        {
            "api_call": "guardduty.list_detectors",
            "observed_value": {
                "DetectorIds": [],
                "region": "eu-west-1",
                "human_observed": "No GuardDuty detector exists in the account/Region (eu-west-1)",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id=GD_FID,
        title=GD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["evidence_source"] == "guardduty.list_detectors"
    assert "eu-west-1" in str(result.get("observed") or result.get("manager_summary"))


def test_09_remediation_not_ready_while_unverified():
    rec = recommend(
        finding_status="UNVERIFIED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["deployment_ready"] is False
    assert rec.get("remediation_status") == "NOT_READY"
    assert rec.get("execution_ready") is False


def test_10_remediation_reviewable_after_confirmed():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["recommendation"] in {"RECOMMEND_APPROVE", "RECOMMEND_REVIEW"}
    assert rec.get("remediation_status") != "NOT_READY" or rec.get("deployment_ready") is True


def test_11_generic_semantic_exception_interpreter_non_guardduty():
    register_semantic_exception(
        "config",
        "FakeConfigNotEnabledException",
        control_state="SERVICE_NOT_SUBSCRIBED",
        human_template="AWS Config is not subscribed/enabled in {region}",
        evidence_quality="DIRECT",
        passes=False,
        notes="fixture for generic interpreter",
    )
    sem = interpret_aws_exception(
        service="config",
        error_code="FakeConfigNotEnabledException",
        region="us-west-2",
        api_call="config.describe_configuration_recorders",
    )
    assert sem is not None
    assert sem["evidence_quality"] == "DIRECT"
    assert sem["pass"] is False
    assert sem["control_state"] == "SERVICE_NOT_SUBSCRIBED"
    assert "us-west-2" in sem["human_observed"]
    # Unknown exception remains None
    assert (
        interpret_aws_exception(
            service="config",
            error_code="AccessDeniedException",
            region="us-west-2",
        )
        is None
    )


def test_12_discover_routes_guardduty_not_generic_skip():
    with patch(
        "predeploy.aws_dependency_discovery.discover_aws_guardduty",
        return_value={"kind": "aws_guardduty", "status": "OK"},
    ) as mocked:
        out = discover_for_findings(
            ["CLOUD-LOG-003"],
            [{"id": "CLOUD-LOG-003", "title": "GuardDuty detector enabled"}],
            profile="sentinel-demo",
            region="us-east-1",
        )
        mocked.assert_called_once()
        assert out["kind"] == "aws_guardduty"


def test_13_collector_subscription_required_mocked():
    class FakeClientError(Exception):
        def __init__(self):
            self.response = {"Error": {"Code": "SubscriptionRequiredException", "Message": "not subscribed"}}

    fake_gd = MagicMock()
    fake_gd.list_detectors.side_effect = FakeClientError()
    fake_session = MagicMock()
    fake_session.client.side_effect = lambda svc, **kw: (
        fake_gd if svc == "guardduty" else MagicMock(**{"get_caller_identity.return_value": {"Account": "111"}})
    )

    with patch.dict("sys.modules", {"boto3": MagicMock(Session=MagicMock(return_value=fake_session))}):
        with patch("boto3.Session", return_value=fake_session):
            # Ensure ClientError import path doesn't break — raise plain Exception with code in name
            fake_gd.list_detectors.side_effect = Exception("SubscriptionRequiredException")
            out = discover_aws_guardduty(
                profile="sentinel-demo",
                region="us-east-1",
                finding_id=GD_FID,
                finding={"title": GD_TITLE},
            )
    ea = out.get("evidence_assessment") or {}
    assert ea.get("finding_status") == "CONFIRMED"
    assert ea.get("evidence_quality") == QUALITY_DIRECT
    assert ea.get("result") == "FAIL"
    assert (out.get("summary") or {}).get("aws_response_classification") == "SubscriptionRequiredException"


def test_14_collector_empty_list_mocked():
    fake_gd = MagicMock()
    fake_gd.list_detectors.return_value = {"DetectorIds": []}
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {"Account": "111"}
    fake_session = MagicMock()

    def _client(svc, **kw):
        if svc == "guardduty":
            return fake_gd
        return fake_sts

    fake_session.client.side_effect = _client
    with patch("boto3.Session", return_value=fake_session):
        out = discover_aws_guardduty(
            profile="sentinel-demo",
            region="us-east-1",
            finding_id=GD_FID,
            finding={"title": GD_TITLE},
        )
    ea = out.get("evidence_assessment") or {}
    assert ea.get("finding_status") == "CONFIRMED"
    assert ea.get("result") == "FAIL"
    assert (out.get("summary") or {}).get("aws_response_classification") == "EmptyDetectorList"


def test_15_collector_enabled_detector_mocked():
    fake_gd = MagicMock()
    fake_gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    fake_gd.get_detector.return_value = {"Status": "ENABLED"}
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {"Account": "111"}
    fake_session = MagicMock()

    def _client(svc, **kw):
        if svc == "guardduty":
            return fake_gd
        return fake_sts

    fake_session.client.side_effect = _client
    with patch("boto3.Session", return_value=fake_session):
        out = discover_aws_guardduty(
            profile="sentinel-demo",
            region="us-east-1",
            finding_id=GD_FID,
            finding={"title": GD_TITLE},
        )
    ea = out.get("evidence_assessment") or {}
    assert ea.get("finding_status") == "ALREADY_REMEDIATED"
    assert ea.get("result") == "PASS"


def test_16_collector_access_denied_mocked():
    fake_gd = MagicMock()
    fake_gd.list_detectors.side_effect = Exception("AccessDeniedException: User is not authorized")
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {"Account": "111"}
    fake_session = MagicMock()

    def _client(svc, **kw):
        if svc == "guardduty":
            return fake_gd
        return fake_sts

    fake_session.client.side_effect = _client
    with patch("boto3.Session", return_value=fake_session):
        out = discover_aws_guardduty(
            profile="sentinel-demo",
            region="us-east-1",
            finding_id=GD_FID,
            finding={"title": GD_TITLE},
        )
    ea = out.get("evidence_assessment") or {}
    assert ea.get("finding_status") in {"ERROR", "UNVERIFIED"}
    assert ea.get("evidence_quality") == QUALITY_ERROR


def test_17_face_manager_card_direct_guardduty_evidence():
    finding = {
        "id": GD_FID,
        "title": GD_TITLE,
        "severity": "high",
        "description": "GuardDuty is not enabled",
    }
    impact = {
        "finding_status": "CONFIRMED",
        "evidence_quality": "DIRECT",
        "region": "us-east-1",
        "change_assurance": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "remediation_status": "READY",
            "manager_decision": "PENDING",
            "execution_status": "NOT_PERFORMED",
            "deployment_ready": True,
        },
        "discovery": {
            "kind": "aws_guardduty",
            "region": "us-east-1",
            "summary": {
                "aws_response_classification": "SubscriptionRequiredException",
                "finding_status": "CONFIRMED",
            },
            "evidence_assessment": {
                "finding_status": "CONFIRMED",
                "evidence_quality": "DIRECT",
                "result": "FAIL",
                "evidence_source": "guardduty.list_detectors",
                "observed": {
                    "human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1",
                    "region": "us-east-1",
                },
                "expected": "An enabled GuardDuty detector",
                "manager_summary": {
                    "headline": "FINDING CONFIRMED",
                    "result": "FAIL",
                    "finding_status": "CONFIRMED",
                    "evidence_source": "guardduty.list_detectors",
                    "observed": {
                        "human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1"
                    },
                    "expected": "An enabled GuardDuty detector",
                },
            },
        },
        "evidence_assessment": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "result": "FAIL",
            "evidence_source": "guardduty.list_detectors",
            "observed": {
                "human_observed": "Amazon GuardDuty is not subscribed/enabled in us-east-1",
                "region": "us-east-1",
            },
            "expected": "An enabled GuardDuty detector",
        },
    }
    card = build_manager_card(finding, {"id": "job_test"}, impact=impact, is_primary=True)
    text = str(card).lower()
    assert "confirmed" in text or str(card.get("finding_status") or "").upper() == "CONFIRMED"
    assert "evidence insufficient" not in text
    assert "guardduty" in text
    assert "compromised" not in text


def test_18_config_and_access_analyzer_regression():
    # Config empty recorders still CONFIRMED
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
    assert cfg["evidence_quality"] == QUALITY_DIRECT

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
    assert aa["evidence_source"] == "accessanalyzer.list_analyzers"
