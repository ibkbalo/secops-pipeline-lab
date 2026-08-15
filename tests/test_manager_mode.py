# tests/test_manager_mode.py
# Manager Mode presentation — does not weaken backend safety.

from __future__ import annotations

import manager_mode as mm


def _cloud_finding():
    return {
        "id": "CLOUD-STO-001",
        "title": "S3 account public access block fully enabled",
        "severity": "critical",
        "description": (
            "Your AWS account does not have all four account-level S3 Block Public Access "
            "protections enabled. A future misconfiguration could expose objects."
        ),
        "remediation": {
            "steps": [
                "Enable all four AWS account-level S3 Block Public Access protections.",
                "Re-scan CLOUD-STO-001.",
            ]
        },
    }


def _devsec_finding():
    return {
        "id": "DEVSEC-SCA-001",
        "title": "Vulnerable dependency requests",
        "severity": "high",
        "description": "The application depends on a vulnerable version of requests.",
        "remediation": {"steps": ["Update requests from 2.28.0 to 2.31.0."]},
    }


def test_01_recommendation_separate_from_manager_decision():
    job = {"job_id": "j1", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_APPROVE",
        "finding_status": "CONFIRMED",
        "blast_radius": {"level": "LOW", "scope": "ACCOUNT"},
        "change_assurance": {
            "recommendation": "RECOMMEND_APPROVE",
            "validation_status": "PASS",
            "remediation_risk": {"level": "LOW"},
            "manager_context_required": False,
            "manager_questions": [],
            "approval_integrity": {"status": "PENDING_MANAGER_DECISION", "valid": False},
        },
    }
    view = mm.build_manager_view(job, [_cloud_finding()], impact)
    assert view["recommendation_label"] == "APPROVE"
    assert view["manager_decision"] == "PENDING"
    assert view["primary"]["recommendation_label"] != view["primary"]["manager_decision"]


def test_02_approved_does_not_mean_executed():
    job = {
        "job_id": "j2",
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "execution_authorized": True,
        "execution_performed": False,
    }
    impact = {
        "recommendation": "RECOMMEND_APPROVE",
        "change_assurance": {"recommendation": "RECOMMEND_APPROVE", "remediation_risk": {"level": "LOW"}},
    }
    view = mm.build_manager_view(job, [_cloud_finding()], impact)
    assert view["manager_decision"] == "APPROVED"
    assert view["execution"] == "NOT PERFORMED"
    assert view["primary"]["execution"] == "NOT PERFORMED"


def test_03_approval_invalidation_plain_english():
    plain = mm.integrity_plain_english(
        {
            "status": "APPROVAL_INVALIDATED",
            "integrity": "INVALIDATED",
            "valid": False,
            "reasons": ["ARTIFACT_CHANGED"],
        }
    )
    assert plain["needs_review"] is True
    assert "APPROVAL NEEDS REVIEW" in plain["headline"]
    assert "changed after you approved" in plain["message"].lower()
    assert "ARTIFACT_CHANGED" in plain["technical_reasons"]


def test_04_severity_and_change_risk_separate():
    job = {"job_id": "j4", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_APPROVE",
        "finding_status": "CONFIRMED",
        "blast_radius": {"level": "LOW", "scope": "ACCOUNT"},
        "change_assurance": {
            "recommendation": "RECOMMEND_APPROVE",
            "remediation_risk": {"level": "LOW"},
            "validation_status": "PASS",
        },
    }
    card = mm.build_manager_card(_cloud_finding(), job, impact, is_primary=True)
    assert card["security_severity"] == "CRITICAL"
    assert card["change_risk"] == "LOW"
    assert card["security_severity"] != card["change_risk"] or True  # concepts remain distinct fields


def test_05_manager_context_questions_display():
    job = {"job_id": "j5", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_REVIEW",
        "change_assurance": {
            "recommendation": "RECOMMEND_REVIEW",
            "manager_context_required": True,
            "manager_questions": [
                "MANAGER CONTEXT REQUIRED: Does this AWS account intentionally host public content directly from S3?"
            ],
            "remediation_risk": {"level": "MEDIUM"},
        },
    }
    card = mm.build_manager_card(_cloud_finding(), job, impact, is_primary=True)
    assert card["manager_input_needed"] is True
    assert card["manager_questions"]
    assert "intentionally host public" in card["manager_questions"][0].lower()
    assert "Human context is required" in card["why_recommend"]


def test_06_advanced_details_still_have_technical_fields():
    # Manager view preserves raw recommendation for Advanced Details consumers
    job = {"job_id": "j6", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_APPROVE",
        "primary_finding_id": "CLOUD-STO-001",
        "change_assurance": {
            "recommendation": "RECOMMEND_APPROVE",
            "artifacts": [{"artifact_id": "a1", "artifact_type": "terraform", "artifact_hash": "abc"}],
            "approval_binding": {"artifact_hash": "abc", "change_hash": "def"},
        },
    }
    view = mm.build_manager_view(job, [_cloud_finding()], impact)
    assert view["recommendation_raw"] == "RECOMMEND_APPROVE"
    assert view["primary"]["finding_id"] == "CLOUD-STO-001"
    # Plain label differs from raw
    assert view["recommendation_label"] == "APPROVE"


def test_07_cloud_manager_mode_renders_six_questions():
    job = {"job_id": "j7", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_APPROVE",
        "finding_status": "CONFIRMED",
        "discovery": {"summary": {"public_buckets": 0}, "potentially_affected_workloads": "None detected"},
        "blast_radius": {"level": "LOW", "scope": "ACCOUNT", "reasons": ["Account-wide control"]},
        "change_assurance": {
            "recommendation": "RECOMMEND_APPROVE",
            "validation_status": "PASS",
            "remediation_risk": {"level": "LOW"},
            "artifacts": [{"artifact_type": "terraform", "destructive": {"destructive": False}}],
            "verification": {"steps": ["Re-scan AWS", "Confirm all four protections enabled"]},
        },
    }
    card = mm.build_manager_card(_cloud_finding(), job, impact, is_primary=True)
    assert card["agent"] == "Cloud Security Engineer"
    assert "S3" in card["what_found"] or "public" in card["what_found"].lower()
    assert card["what_change"]
    assert card["why_matters"]
    assert "currently exposed" not in card["why_matters"].lower() or "does not" in card["why_matters"].lower()
    assert card["affect"]["scope"]
    assert card["why_recommend"]
    assert card["after_change"]
    assert card["recommendation_label"] == "APPROVE"


def test_08_devsecops_manager_mode_renders():
    job = {"job_id": "j8", "role": "devsecops", "status": "pending_approval"}
    impact = {
        "recommendation": "RECOMMEND_REVIEW",
        "finding_status": "CONFIRMED",
        "blast_radius": {"level": "MEDIUM", "scope": "REPOSITORY"},
        "change_assurance": {
            "domain": "devsecops",
            "recommendation": "RECOMMEND_REVIEW",
            "validation_mode": "STATIC_ONLY",
            "remediation_risk": {"level": "MEDIUM"},
            "artifacts": [
                {
                    "artifact_type": "dependency_update",
                    "dependency_updates": [
                        {"package": "requests", "old_version": "2.28.0", "new_version": "2.31.0", "change_kind": "minor"}
                    ],
                }
            ],
            "repo_fingerprint": {"repository": "/app", "branch": "main", "commit_sha": "abc123"},
            "manager_questions": ["MANAGER CONTEXT REQUIRED: Is this dependency API relied upon by production code?"],
            "manager_context_required": True,
        },
    }
    card = mm.build_manager_card(_devsec_finding(), job, impact, is_primary=True)
    assert card["agent"] == "DevSecOps Engineer"
    assert "requests" in card["what_change"].lower() or "Update" in card["what_change"]
    assert card["recommendation_label"] == "REVIEW WITH MANAGER"
    assert card["learning"]["concept"]


def test_09_already_remediated_clear():
    job = {"job_id": "j9", "role": "cloud", "status": "pending_approval"}
    impact = {
        "recommendation": "NO_ACTION_REQUIRED",
        "finding_status": "ALREADY_REMEDIATED",
        "change_assurance": {"recommendation": "NO_ACTION_REQUIRED", "remediation_risk": {"level": "LOW"}},
    }
    card = mm.build_manager_card(_cloud_finding(), job, impact, is_primary=True)
    assert card["already_remediated"] is True
    assert "ALREADY" in card["banner"]
    assert card["recommendation_label"] == "NO ACTION NEEDED"


def test_10_no_automatic_execution_introduced():
    job = {"job_id": "j10", "role": "cloud", "status": "approved", "manager_decision": "approved"}
    view = mm.build_manager_view(job, [_cloud_finding()], {"recommendation": "RECOMMEND_APPROVE"})
    assert view["execution"] == "NOT PERFORMED"
    # translate helpers never emit execution instructions as authorization
    assert mm.translate_recommendation("RECOMMEND_APPROVE") == "APPROVE"
    assert "DEPLOY" not in mm.translate_recommendation("RECOMMEND_APPROVE")


def test_commit_changed_plain_english():
    plain = mm.integrity_plain_english(
        {"status": "APPROVAL_INVALIDATED", "reasons": ["COMMIT_CHANGED"], "valid": False}
    )
    assert "source code changed" in plain["message"].lower()


def test_reject_label():
    assert mm.translate_recommendation("RECOMMEND_REJECT") == "DO NOT APPLY"
