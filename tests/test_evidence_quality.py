# tests/test_evidence_quality.py
# Evidence relevance & sufficiency — generic + Cloud IAM example.

from __future__ import annotations

from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import (
    QUALITY_DIRECT,
    QUALITY_ERROR,
    QUALITY_INDIRECT,
    QUALITY_INSUFFICIENT,
    assess_finding_evidence,
)
from change_assurance.recommendations import recommend
from manager_mode import build_manager_card


PASSWORD_TITLE = "AWS IAM password policy minimum length >= 14"


def test_01_direct_evidence_failing_value_confirmed():
    evidence = [
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"MinimumPasswordLength": 8},
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"
    assert result["observed"]["MinimumPasswordLength"] == 8


def test_02_direct_evidence_passing_value_pass():
    evidence = [
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"MinimumPasswordLength": 14},
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "ALREADY_REMEDIATED"
    assert result["result"] == "PASS"


def test_03_indirect_evidence_only_unverified():
    evidence = [
        {
            "api_call": "iam.get_account_summary",
            "observed_value": {"Users": 2, "AccountMFAEnabled": 1, "MFADevices": 1},
            "quality": "INDIRECT",
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-001",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "UNVERIFIED"
    assert result["evidence_quality"] == QUALITY_INSUFFICIENT
    assert "MinimumPasswordLength" in (result["reason"] or "")


def test_04_missing_required_field_unverified():
    evidence = [
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"RequireSymbols": True},  # wrong field
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "UNVERIFIED"


def test_05_api_error_not_pass():
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=[],
        specs=cloud_specs(),
        collection_error="AccessDenied",
    )
    assert result["finding_status"] == "ERROR"
    assert result["result"] == "ERROR"
    assert result["finding_status"] != "PASS"
    assert result["finding_status"] != "ALREADY_REMEDIATED"


def test_06_capability_unavailable():
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=[],
        specs=cloud_specs(),
        capability_unavailable=True,
    )
    assert result["finding_status"] == "UNVERIFIED"
    assert result["evidence_quality"] == "UNAVAILABLE"


def test_07_multiple_evidence_direct_controls_confirmation():
    evidence = [
        {
            "api_call": "iam.get_account_summary",
            "observed_value": {"Users": 2, "AccountMFAEnabled": 1},
            "quality": "INDIRECT",
            "purpose": "context",
        },
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"MinimumPasswordLength": 8},
            "quality": "DIRECT",
            "purpose": "proof",
        },
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_source"] == "iam.get_account_password_policy"
    labeled = result["labeled_evidence"]
    qualities = {e["api_call"]: e["quality"] for e in labeled}
    assert qualities["iam.get_account_summary"] == QUALITY_INDIRECT
    assert qualities["iam.get_account_password_policy"] == QUALITY_DIRECT


def test_08_context_evidence_labeled_indirect():
    evidence = [
        {"api_call": "iam.get_account_summary", "observed_value": {"Users": 2}},
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"MinimumPasswordLength": 10},
        },
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-002",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    indirect = [e for e in result["labeled_evidence"] if e["quality"] == QUALITY_INDIRECT]
    assert indirect
    assert indirect[0]["api_call"] == "iam.get_account_summary"


def test_09_manager_mode_shows_observed_expected():
    job = {"job_id": "j", "role": "cloud", "status": "pending_approval"}
    finding = {
        "id": "CLOUD-IAM-002",
        "title": PASSWORD_TITLE,
        "severity": "high",
        "description": "Password minimum length is below the CIS 14-character floor.",
    }
    impact = {
        "recommendation": "RECOMMEND_REVIEW",
        "finding_status": "CONFIRMED",
        "change_assurance": {
            "recommendation": "RECOMMEND_REVIEW",
            "remediation_risk": {"level": "LOW"},
            "evidence_assessment": {
                "finding_status": "CONFIRMED",
                "evidence_quality": "DIRECT",
                "observed": {"MinimumPasswordLength": 8},
                "expected": "14 or greater",
                "result": "FAIL",
                "evidence_source": "iam.get_account_password_policy",
                "human_label": "Minimum password length",
                "manager_summary": {
                    "headline": "EVIDENCE DIRECT",
                    "observed": {"MinimumPasswordLength": 8},
                    "expected": "14 or greater",
                    "result": "FAIL",
                    "evidence_source": "AWS IAM password policy",
                    "human_label": "Minimum password length",
                    "finding_status": "CONFIRMED",
                },
                "labeled_evidence": [
                    {"api_call": "iam.get_account_summary", "quality": "INDIRECT"},
                    {"api_call": "iam.get_account_password_policy", "quality": "DIRECT"},
                ],
            },
        },
    }
    card = build_manager_card(finding, job, impact, is_primary=True)
    proof = card["evidence_proof"]
    assert proof
    assert proof["insufficient"] is False
    assert "8" in str(proof["observed"])
    assert "14" in str(proof["expected"])
    assert proof["result"] == "FAIL"


def test_10_change_assurance_no_approve_when_unverified():
    rec = recommend(
        finding_status="UNVERIFIED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["recommendation"] == "RECOMMEND_REVIEW"
    assert rec["deployment_ready"] is False


def test_11_existing_s3_direct_still_works():
    evidence = [
        {
            "api_call": "s3control.get_public_access_block",
            "observed_value": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-STO-001",
        title="S3 account public access block fully enabled",
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT


def test_12_no_auto_execution_introduced():
    from change_assurance.engine import assure_job

    report = assure_job(
        {"job_id": "eq12", "role": "cloud", "kit_path": None},
        [{"id": "CLOUD-IAM-002", "title": PASSWORD_TITLE, "severity": "high"}],
    )
    assert report.get("auto_apply_forbidden") is True
    assert report.get("execution_performed") is False


def test_iam_001_style_password_does_not_confirm_from_summary_alone():
    """Regression: password-length finding must not confirm from get_account_summary alone."""
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-001",
        title=PASSWORD_TITLE,
        evidence=[
            {
                "api_call": "iam.get_account_summary",
                "observed_value": {
                    "Users": 2,
                    "AccountMFAEnabled": 1,
                    "AccountAccessKeysPresent": 0,
                },
            }
        ],
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "UNVERIFIED"
    assert result["manager_summary"]["headline"] == "EVIDENCE INSUFFICIENT"


AA_TITLE = "IAM Access Analyzer enabled"


def test_13_access_analyzer_empty_list_confirmed():
    evidence = [
        {
            "api_call": "accessanalyzer.list_analyzers",
            "region": "us-east-1",
            "observed_value": {
                "analyzers": [],
                "analyzer_count": 0,
                "active_account_analyzer_count": 0,
                "region": "us-east-1",
                "human_observed": "No Access Analyzer found in us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == QUALITY_DIRECT
    assert result["result"] == "FAIL"
    assert result["evidence_source"] == "accessanalyzer.list_analyzers"
    assert result["observed"]["region"] == "us-east-1"


def test_14_access_analyzer_active_account_pass():
    evidence = [
        {
            "api_call": "accessanalyzer.list_analyzers",
            "region": "us-east-1",
            "observed_value": {
                "analyzers": [
                    {"name": "sentinel-account", "type": "ACCOUNT", "status": "ACTIVE"}
                ],
                "analyzer_count": 1,
                "active_account_analyzer_count": 1,
                "region": "us-east-1",
                "human_observed": "Analyzer name: sentinel-account; Type: ACCOUNT; Status: ACTIVE",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "ALREADY_REMEDIATED"
    assert result["result"] == "PASS"


def test_15_access_analyzer_inactive_does_not_pass():
    evidence = [
        {
            "api_call": "accessanalyzer.list_analyzers",
            "region": "us-east-1",
            "observed_value": {
                "analyzers": [
                    {"name": "sentinel-account", "type": "ACCOUNT", "status": "CREATING"}
                ],
                "analyzer_count": 1,
                "active_account_analyzer_count": 0,
                "region": "us-east-1",
                "human_observed": "No Access Analyzer found in us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["result"] == "FAIL"


def test_16_access_analyzer_access_denied_error_unverified():
    evidence = [
        {
            "api_call": "accessanalyzer.list_analyzers",
            "region": "us-east-1",
            "quality": "ERROR",
            "observed_value": {
                "error": "AccessDenied",
                "code": "AccessDeniedException",
                "region": "us-east-1",
            },
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "ERROR"
    assert result["evidence_quality"] == QUALITY_ERROR
    assert result["result"] == "ERROR"


def test_17_access_analyzer_summary_only_indirect_unverified():
    evidence = [
        {
            "api_call": "iam.get_account_summary",
            "observed_value": {"Users": 2, "AccountMFAEnabled": 1},
            "quality": "INDIRECT",
        }
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "UNVERIFIED"
    assert result["evidence_quality"] == QUALITY_INSUFFICIENT


def test_18_manager_mode_prefers_access_analyzer_direct():
    finding = {
        "id": "CLOUD-IAM-013",
        "title": AA_TITLE,
        "severity": "high",
        "description": "Access Analyzer is off.",
    }
    job = {"job_id": "j-aa", "role": "cloud", "title": "Cloud"}
    impact = {
        "finding_status": "CONFIRMED",
        "change_assurance": {
            "finding_status": "CONFIRMED",
            "evidence_assessment": {
                "finding_status": "CONFIRMED",
                "evidence_quality": "DIRECT",
                "result": "FAIL",
                "evidence_source": "accessanalyzer.list_analyzers",
                "human_label": "IAM Access Analyzer",
                "manager_summary": {
                    "observed": {
                        "human_observed": "No Access Analyzer found in us-east-1",
                        "region": "us-east-1",
                        "active_account_analyzer_count": 0,
                    },
                    "expected": "At least one active account-level analyzer",
                    "result": "FAIL",
                    "evidence_source": "accessanalyzer.list_analyzers",
                    "human_label": "IAM Access Analyzer",
                },
                "labeled_evidence": [
                    {
                        "api_call": "accessanalyzer.list_analyzers",
                        "quality": "DIRECT",
                        "region": "us-east-1",
                        "observed_value": {
                            "analyzers": [],
                            "human_observed": "No Access Analyzer found in us-east-1",
                            "region": "us-east-1",
                            "active_account_analyzer_count": 0,
                        },
                    },
                    {
                        "api_call": "iam.get_account_summary",
                        "quality": "INDIRECT",
                        "observed_value": {"Users": 2},
                    },
                ],
            },
        },
    }
    card = build_manager_card(finding, job, impact, is_primary=True)
    proof = card["evidence_proof"]
    assert proof["insufficient"] is False
    assert proof["finding_status"] == "CONFIRMED"
    assert proof["result"] == "FAIL"
    assert "No Access Analyzer found in us-east-1" in str(proof["observed"])
    assert "Access Analyzer" in str(proof["evidence_source"])
    assert proof["direct_items"][0]["api_call"] == "accessanalyzer.list_analyzers"
    assert all("get_account_summary" not in str(d.get("api_call")) for d in proof["direct_items"])
