# tests/test_guardduty_permission_readiness.py
# GuardDuty execution-permission probe + Stage A IAM package (no AWS writes).

from __future__ import annotations

from unittest.mock import MagicMock, patch

from change_assurance.domains.cloud.guardduty_prerequisites import (
    REQUIRED_GUARDDUTY_ACTIONS,
    REQUIRED_REMEDIATION_ROLE_PERMISSIONS,
    guardduty_permission_assessment,
    prepare_guardduty_permission_package,
    probe_guardduty_permissions_via_iam,
    render_guardduty_inline_policy_document,
)
from change_assurance.recommendations import recommend


def test_01_required_permissions_include_create_and_slr():
    assert "guardduty:CreateDetector" in REQUIRED_GUARDDUTY_ACTIONS
    assert "guardduty:ListDetectors" in REQUIRED_GUARDDUTY_ACTIONS
    assert "iam:CreateServiceLinkedRole" in REQUIRED_REMEDIATION_ROLE_PERMISSIONS
    assert "guardduty:*" not in REQUIRED_REMEDIATION_ROLE_PERMISSIONS


def test_02_policy_document_is_least_privilege_not_star():
    doc = render_guardduty_inline_policy_document(
        account_id="952654481542", region="us-east-1"
    )
    blob = str(doc)
    assert "guardduty:*" not in blob
    assert "guardduty.amazonaws.com" in blob
    assert "CreateDetector" in blob
    assert "aws:RequestedRegion" in blob


def test_03_implicit_deny_is_fail_not_unknown():
    sim = {a: "implicitDeny" for a in REQUIRED_REMEDIATION_ROLE_PERMISSIONS}
    assess = guardduty_permission_assessment(
        execution_role="SentinelStacksRemediationRole",
        execution_identity="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
        simulated=sim,
        probe_profile="sentinel-demo",
        slr_exists=False,
    )
    assert assess["permission_ready"] == "FAIL"
    assert assess["execution_permission_ready"] is False
    assert assess["staged_prerequisite"] is True
    assert "CreateDetector" in assess["detail"]


def test_04_all_allow_is_pass():
    sim = {a: "allow" for a in REQUIRED_REMEDIATION_ROLE_PERMISSIONS}
    assess = guardduty_permission_assessment(
        execution_role="SentinelStacksRemediationRole",
        execution_identity="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
        simulated=sim,
        probe_profile="sentinel-demo",
        slr_exists=True,
    )
    assert assess["permission_ready"] == "PASS"
    assert assess["execution_permission_ready"] is True


def test_05_probe_error_is_unknown_with_reason():
    assess = guardduty_permission_assessment(
        execution_role="SentinelStacksRemediationRole",
        simulated=None,
        probe_error="profile=sentinel-remediation: AccessDenied: iam:SimulatePrincipalPolicy",
        probe_profile=None,
    )
    assert assess["permission_ready"] == "UNKNOWN"
    assert "SimulatePrincipalPolicy" in assess["detail"] or "probe failed" in assess["detail"].lower()


def test_06_probe_prefers_scanner_profile_over_remediation():
    fake_iam = MagicMock()
    fake_iam.simulate_principal_policy.return_value = {
        "EvaluationResults": [
            {"EvalActionName": "guardduty:CreateDetector", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "guardduty:GetDetector", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "guardduty:ListDetectors", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "guardduty:UpdateDetector", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "guardduty:TagResource", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "guardduty:ListTagsForResource", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "iam:CreateServiceLinkedRole", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "iam:GetRole", "EvalDecision": "implicitDeny"},
        ]
    }
    fake_session = MagicMock()
    fake_session.client.return_value = fake_iam

    with patch("boto3.Session", return_value=fake_session) as sess:
        out, prof, err = probe_guardduty_permissions_via_iam(
            profile="sentinel-remediation",
            region="us-east-1",
            source_arn="arn:aws:iam::952654481542:role/SentinelStacksRemediationRole",
            probe_profiles=["sentinel-demo", "sentinel-remediation"],
        )
    assert err is None
    assert prof == "sentinel-demo"
    assert out["guardduty:CreateDetector"].lower() == "implicitdeny"
    # First successful session should be sentinel-demo (preferred)
    assert sess.call_args_list[0].kwargs.get("profile_name") == "sentinel-demo" or (
        sess.call_args_list[0][1].get("profile_name") == "sentinel-demo"
    )


def test_07_prepare_package_has_stage_a_and_b():
    pkg = prepare_guardduty_permission_package(
        account_id="952654481542", region="us-east-1", finding_id="CLOUD-LOG-003"
    )
    assert "aws_iam_role_policy" in pkg["terraform"]
    assert "SentinelGuardDutyRemediation" in pkg["terraform"]
    assert "PutRolePolicy" in pkg["apply_identity_requirement"]
    assert pkg["stage_b"]["resource"] == "aws_guardduty_detector.sentinel"
    assert pkg["aws_modified"] is False
    assert pkg["policy_auto_attached"] is False


def test_08_human_auth_alone_still_not_force_review_when_perms_pass_path():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
        manager_questions=[
            "MANAGER CONSIDERATION: Enabling Amazon GuardDuty incurs AWS service cost"
        ],
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    assert rec["manager_approval_required"] is True
