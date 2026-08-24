# Manager Mode plain-English explanations — control-specific, evidence-aware.
# No LLMs. No auto-execution.

from __future__ import annotations

import manager_explanations as mx
import manager_mode
from manager_explanations import (
    build_understanding,
    explanation_control_mismatch_reason,
    remediation_explanation_mismatch_reason,
    unsupported_risk_claim_reason,
)


def _aa_finding():
    return {
        "id": "CLOUD-IAM-013",
        "title": "IAM Access Analyzer enabled",
        "severity": "high",
        "description": "Access Analyzer is off",
        "resource": {"region": "us-east-1"},
    }


def _aa_impact_confirmed():
    return {
        "primary_finding_id": "CLOUD-IAM-013",
        "finding_status": "CONFIRMED",
        "evidence_assessment": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "result": "FAIL",
            "evidence_source": "accessanalyzer.list_analyzers",
            "observed": {
                "region": "us-east-1",
                "active_account_analyzer_count": 0,
                "human_observed": "No Access Analyzer found in us-east-1",
            },
            "expected": "At least one active account-level analyzer",
        },
        "relevant_artifacts": ["terraform/CLOUD-IAM-013.tf"],
        "artifacts": [
            {
                "source_files": ["terraform/CLOUD-IAM-013.tf"],
                "content_preview": 'resource "aws_accessanalyzer_analyzer" "sentinel" { type = "ACCOUNT" }',
            }
        ],
        "auto_apply_forbidden": True,
    }


def test_01_iam013_plain_english_and_direct_evidence():
    u = build_understanding(_aa_finding(), _aa_impact_confirmed(), _aa_impact_confirmed())
    assert u["safe_to_present"] is True
    assert "Access Analyzer" in u["what_is_this"]
    assert "us-east-1" in u["what_sentinel_found"]
    assert "directly" in u["what_sentinel_found"].lower() or "No Access Analyzer" in u["what_sentinel_found"]
    assert "does not by itself prove" in (u.get("absence_does_not_prove") or "").lower() or "does not" in u[
        "what_it_means"
    ].lower()


def test_02_iam013_severity_rationale_high():
    u = build_understanding(_aa_finding(), _aa_impact_confirmed(), _aa_impact_confirmed())
    sev = u["severity"]
    assert sev["rating"] == "HIGH"
    assert "Sentinel" in sev["label"]
    assert sev["incomplete"] is False
    assert any("detective" in b.lower() or "external" in b.lower() for b in sev["basis"])
    assert any("breach" in c.lower() or "exploitation" in c.lower() for c in sev["context"])


def test_03_iam013_remediation_will_and_will_not():
    u = build_understanding(_aa_finding(), _aa_impact_confirmed(), _aa_impact_confirmed())
    assert "account-level" in u["fix_will_do"].lower() or "Access Analyzer" in u["fix_will_do"]
    assert "us-east-1" in u["fix_will_do"]
    joined = " ".join(u["fix_will_not_do"]).lower()
    assert "password" in joined
    assert "resource policies" in joined or "permissions" in joined


def test_04_guardduty_not_iam_or_s3():
    finding = {
        "id": "CLOUD-DFT-001",
        "title": "Drift from baseline: GuardDuty required but absent",
        "severity": "high",
        "resource": {"region": "us-east-1"},
    }
    impact = {
        "finding_status": "CONFIRMED",
        "evidence_assessment": {
            "finding_status": "CONFIRMED",
            "evidence_quality": "DIRECT",
            "result": "FAIL",
            "observed": {"error": "SubscriptionRequiredException", "code": "SubscriptionRequiredException"},
            "evidence_source": "guardduty.list_detectors",
        },
    }
    u = build_understanding(finding, impact, impact)
    blob = " ".join(str(u.get(k) or "") for k in u).lower()
    assert "guardduty" in u["what_is_this"].lower()
    assert "s3" not in u["what_is_this"].lower()
    assert "least privilege" not in blob
    assert "access analyzer" not in blob
    assert "SubscriptionRequired" in u["what_sentinel_found"] or "subscribed" in u["what_sentinel_found"].lower()


def test_05_config_vpc_ebs_distinct():
    cases = [
        ("CLOUD-LOG-002", "AWS Config recorder enabled", "config"),
        ("CLOUD-NET-001", "VPC flow logs enabled: vpc-1", "flow"),
        ("CLOUD-STO-004", "EBS encryption by default enabled", "ebs"),
        ("CLOUD-STO-001", "S3 access logging: bucket-x", "logging"),
        ("CLOUD-STO-002", "S3 versioning: bucket-x", "version"),
        ("CLOUD-IAM-014", "IAM Identity Center (SSO) preferred over long-lived IAM users", "identity"),
    ]
    for fid, title, token in cases:
        u = build_understanding(
            {"id": fid, "title": title, "severity": "high", "resource": {"region": "us-east-1"}},
            {"finding_status": "CONFIRMED", "evidence_assessment": {"evidence_quality": "DIRECT", "finding_status": "CONFIRMED", "result": "FAIL"}},
            {},
        )
        assert u["available"] and u["safe_to_present"], fid
        assert token in (u["what_is_this"] + u["fix_will_do"] + u["plain_english_name"]).lower(), fid


def test_06_unverified_and_error_language():
    finding = _aa_finding()
    unver = {
        "finding_status": "UNVERIFIED",
        "evidence_assessment": {
            "finding_status": "UNVERIFIED",
            "evidence_quality": "INSUFFICIENT",
            "result": "UNVERIFIED",
        },
    }
    u = build_understanding(finding, unver, unver)
    assert "does not directly prove" in u["what_sentinel_found"].lower()

    err = {
        "finding_status": "ERROR",
        "evidence_assessment": {
            "finding_status": "ERROR",
            "evidence_quality": "ERROR",
            "evidence_source": "accessanalyzer.list_analyzers",
        },
    }
    u2 = build_understanding(finding, err, err)
    assert "could not verify" in u2["what_sentinel_found"].lower() or "api" in u2["what_sentinel_found"].lower()


def test_07_confirmed_direct_observation_language():
    u = build_understanding(_aa_finding(), _aa_impact_confirmed(), _aa_impact_confirmed())
    assert "directly" in u["what_sentinel_found"].lower() or "No Access Analyzer found" in u["what_sentinel_found"]


def test_08_unsupported_breach_claim_rejected():
    reason = unsupported_risk_claim_reason(
        "Attackers can currently access your AWS resources.",
        evidence_quality="DIRECT",
        finding_status="CONFIRMED",
    )
    assert reason and reason.startswith("UNSUPPORTED_RISK_CLAIM")


def test_09_cross_control_explanation_leakage():
    bad = "Enable S3 Block Public Access and nginx WAF rules for GuardDuty."
    reason = explanation_control_mismatch_reason("CLOUD-IAM-013", "IAM Access Analyzer enabled", bad)
    assert reason and reason.startswith("EXPLANATION_CONTROL_MISMATCH")


def test_10_remediation_explanation_mismatch():
    meta = mx.lookup_explanation("CLOUD-IAM-013")
    reason = remediation_explanation_mismatch_reason(
        meta,
        "Apply generic hardening",
        artifact_preview='resource "aws_s3_bucket" "x" {}',
    )
    assert reason and reason.startswith("REMEDIATION_EXPLANATION_MISMATCH")


def test_11_severity_incomplete_flag():
    u = build_understanding(
        {"id": "CLOUD-UNKNOWN-999", "title": "Something obscure", "severity": "high"},
        {},
        {},
    )
    assert u["available"] is False or u["severity"]["incomplete"] is True or "SEVERITY_RATIONALE_INCOMPLETE" in (
        u.get("errors") or []
    )


def test_12_manager_card_includes_understanding():
    job = {"job_id": "j", "role": "cloud", "status": "pending_approval", "auto_apply": False}
    card = manager_mode.build_manager_card(
        _aa_finding(), job, _aa_impact_confirmed(), is_primary=True
    )
    u = card.get("understanding") or {}
    assert u.get("safe_to_present") is True
    assert "Access Analyzer" in (u.get("what_is_this") or "")
    assert card.get("execution") in {"NOT PERFORMED", "NOT AUTHORIZED", "NOT PERFORMED / NOT AUTHORIZED"} or "NOT" in str(
        card.get("execution") or ""
    ).upper()


def test_13_approval_integrity_unchanged_shape():
    job = {
        "job_id": "j",
        "role": "cloud",
        "status": "pending_approval",
        "manager_decision": None,
        "auto_apply": False,
    }
    card = manager_mode.build_manager_card(_aa_finding(), job, _aa_impact_confirmed(), is_primary=True)
    assert "approval_integrity" in card
    assert card["recommendation_raw"]
    assert card.get("understanding", {}).get("fix_will_do")


def test_14_no_auto_execution_in_explanation_path():
    u = build_understanding(_aa_finding(), _aa_impact_confirmed(), _aa_impact_confirmed())
    blob = str(u).lower()
    assert "auto-apply" not in blob and "auto_apply" not in blob
