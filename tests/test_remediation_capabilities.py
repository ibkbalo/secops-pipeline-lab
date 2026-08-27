# tests/test_remediation_capabilities.py
# Generic remediation capability registry + bootstrap (no AWS writes).

from __future__ import annotations

from change_assurance.capabilities import (
    BOOTSTRAP_PENDING_ADMIN,
    EXECUTION_BLOCKED_PENDING_CAPABILITY,
    MISSING_PERMISSIONS,
    READY,
    assess_execution_capability,
    match_capability,
)
from change_assurance.capabilities.bootstrap import build_bootstrap_package, render_inline_policy_document
from change_assurance.capabilities.identities import resolve_identities
from change_assurance.capabilities.probe import assert_no_wildcards, classify_simulation
from change_assurance.capabilities.registry import all_specs
from change_assurance.recommendations import recommend
from security_casebook import STATUS_SUCCESS, assess_control_resolution


def test_01_supported_controls_declare_capabilities():
    specs = {s.capability_id: s for s in all_specs()}
    assert "aws_guardduty_detector_enable" in specs
    assert "aws_config_recorder_enable" in specs
    assert "aws_accessanalyzer_account" in specs


def test_02_capability_ready_when_all_permissions_exist():
    spec = match_capability(finding_id="CLOUD-LOG-003", title="GuardDuty detector enabled")
    assert spec is not None
    sim = {a: "allow" for a in spec.action_names()}
    classified = classify_simulation(spec, sim)
    assert classified["state"] == READY


def test_03_missing_permissions_when_absent():
    spec = match_capability(finding_id="CLOUD-LOG-003")
    sim = {a: "implicitDeny" for a in spec.action_names()}
    classified = classify_simulation(spec, sim)
    assert classified["state"] == MISSING_PERMISSIONS
    assert "guardduty:CreateDetector" in classified["missing"]


def test_04_missing_capability_generates_bootstrap_artifact():
    spec = match_capability(finding_id="CLOUD-LOG-003")
    pkg = build_bootstrap_package(
        spec,
        account_id="952654481542",
        region="us-east-1",
        role_name="SentinelStacksRemediationRole",
        finding_id="CLOUD-LOG-003",
        missing_permissions=["guardduty:CreateDetector"],
    )
    assert pkg["kind"] == "BOOTSTRAP_CAPABILITY_PROVISIONING"
    assert "BOOTSTRAP" in pkg["label"]
    assert "aws_iam_role_policy" in pkg["terraform"]
    assert pkg["executable_by_remediation_role"] is False
    assert pkg["authorization_status"] == BOOTSTRAP_PENDING_ADMIN


def test_05_remediation_role_cannot_self_bootstrap():
    idents = resolve_identities({"aws_account_id": "952654481542"})
    exec_id = idents["remediation_executor"]["identity"]
    boot = idents["bootstrap_provisioner"]
    assert exec_id in boot["forbidden_executors"]
    assert boot["self_escalation_forbidden"] is True
    assert idents["remediation_executor"]["may_modify_own_iam"] is False


def test_06_scanner_cannot_bootstrap():
    idents = resolve_identities({"aws_account_id": "952654481542"})
    assert idents["scanner_planner"]["writes_allowed"] is False
    assert idents["scanner_planner"]["identity"] in idents["bootstrap_provisioner"]["forbidden_executors"]


def test_07_bootstrap_auth_separate_from_remediation_auth():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        title="GuardDuty detector enabled",
        job={"aws_account_id": "952654481542", "region": "us-east-1"},
        simulated={a: "implicitDeny" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["remediation_authorization_separate"] is True
    assert assessment["bootstrap_authorization_status"] == BOOTSTRAP_PENDING_ADMIN
    # Remediation recommendation remains advisory and independent
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["manager_approval_required"] is True
    assert rec["recommendation"] == "RECOMMEND_APPROVE"


def test_08_guardduty_capability_requirements():
    spec = match_capability(finding_id="CLOUD-LOG-003")
    actions = set(spec.action_names())
    assert "guardduty:CreateDetector" in actions
    assert "iam:CreateServiceLinkedRole" in actions
    assert_no_wildcards(spec.action_names())


def test_09_config_capability_regression():
    spec = match_capability(finding_id="CLOUD-LOG-002", title="AWS Config recorder enabled")
    assert spec is not None
    assert spec.capability_id == "aws_config_recorder_enable"
    assert "config:PutConfigurationRecorder" in spec.action_names()


def test_10_access_analyzer_capability_regression():
    spec = match_capability(finding_id="CLOUD-IAM-013", title="IAM Access Analyzer enabled")
    assert spec is not None
    assert "access-analyzer:CreateAnalyzer" in spec.action_names()


def test_11_slr_conditional_permission():
    spec = match_capability(finding_id="CLOUD-LOG-003")
    slr = next(p for p in spec.permissions if p.action == "iam:CreateServiceLinkedRole")
    assert slr.condition == {"StringEquals": {"iam:AWSServiceName": "guardduty.amazonaws.com"}}
    doc = render_inline_policy_document(spec, account_id="952654481542", region="us-east-1")
    blob = str(doc)
    assert "guardduty.amazonaws.com" in blob
    assert "guardduty:*" not in blob


def test_12_no_guardduty_wildcard():
    spec = match_capability(finding_id="CLOUD-LOG-003")
    assert all(not a.endswith(":*") for a in spec.action_names())
    assert "guardduty:*" not in spec.action_names()


def test_13_no_iam_wildcard():
    for spec in all_specs():
        assert "iam:*" not in spec.action_names()
        assert_no_wildcards(spec.action_names())


def test_14_capability_ready_ordinary_remediation_excludes_iam():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "allow" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["state"] == READY
    assert assessment["ordinary_remediation_includes_iam"] is False
    assert assessment["bootstrap_authorization_status"] == "SATISFIED"
    assert assessment["bootstrap"]["satisfied"] is True
    assert assessment["execution_gate"] == "READY_PENDING_MANAGER_AUTHORIZATION"


def test_15_capability_missing_blocks_execution():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "implicitDeny" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["state"] == MISSING_PERMISSIONS
    assert assessment["execution_gate"] == EXECUTION_BLOCKED_PENDING_CAPABILITY
    assert assessment["execution_capability_ready"] is False


def test_16_manager_recommendation_remains_advisory():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["manager_approval_required"] is True
    assert "AUTO" not in rec["recommendation"]


def test_17_casebook_cannot_close_from_capability_provisioning_alone():
    result = assess_control_resolution(
        control_ids=["CLOUD-LOG-003"],
        before_findings=[{"id": "CLOUD-LOG-003"}],
        after_findings=[{"id": "CLOUD-LOG-003"}],
        before_scan={},
        after_scan={},
    )
    assert str(result.get("status") or "").upper() != STATUS_SUCCESS


def test_18_capability_state_does_not_alter_finding_evidence():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "implicitDeny" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["finding_evidence_unaffected"] is True
    assert "evidence_quality" not in assessment
    assert "finding_status" not in assessment


def test_19_identity_separation():
    idents = resolve_identities({"aws_account_id": "952654481542"})
    assert idents["scanner_planner"]["profile"] == "sentinel-demo"
    assert idents["remediation_executor"]["role_name"] == "SentinelStacksRemediationRole"
    assert idents["bootstrap_executor_available"] is False
    assert idents["bootstrap_provisioner"]["status"] == "NO_PROGRAMMATIC_BOOTSTRAP_EXECUTOR"


def test_20_aws_allowed_decision_counts_as_allow():
    """IAM SimulatePrincipalPolicy returns EvalDecision='allowed', not 'allow'."""
    from change_assurance.capabilities.probe import normalize_eval_decision

    assert normalize_eval_decision("allowed") == "allow"
    assert normalize_eval_decision("Allowed") == "allow"
    spec = match_capability(finding_id="CLOUD-LOG-003")
    sim = {a: "allowed" for a in spec.action_names()}
    classified = classify_simulation(spec, sim)
    assert classified["state"] == READY
    assert set(classified["available"]) == set(spec.action_names())


def test_21_missing_before_bootstrap_then_ready_after_external_install():
    """Lifecycle: MISSING → external bootstrap installed → reassessment READY."""
    spec = match_capability(finding_id="CLOUD-LOG-003")
    before = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542", "region": "us-east-1"},
        simulated={a: "implicitDeny" for a in spec.action_names()},
        run_live_probe=False,
    )
    assert before["state"] == MISSING_PERMISSIONS
    assert before["bootstrap_authorization_status"] == BOOTSTRAP_PENDING_ADMIN
    assert before["execution_capability_ready"] is False

    # External admin installed policy — next independent simulation proves allow
    after = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542", "region": "us-east-1"},
        simulated={a: "allowed" for a in spec.action_names()},
        run_live_probe=False,
    )
    assert after["state"] == READY
    assert after["permission_ready"] == READY
    assert after["execution_capability_ready"] is True
    assert after["bootstrap_authorization_status"] == "SATISFIED"
    assert after["bootstrap"]["verification_state"] == "VERIFIED"
    assert after["execution_gate"] == "READY_PENDING_MANAGER_AUTHORIZATION"


def test_22_stale_missing_cannot_persist_indefinitely():
    from change_assurance.capabilities.freshness import capability_needs_reprobe

    stale = {
        "state": MISSING_PERMISSIONS,
        "verified_at": "2020-01-01T00:00:00Z",
    }
    assert capability_needs_reprobe(stale) is True
    fresh_ready = {
        "state": READY,
        "verified_at": "2099-01-01T00:00:00Z",
    }
    assert capability_needs_reprobe(fresh_ready) is False


def test_23_ready_requires_actual_permission_proof():
    """Policy existence alone is not enough — simulation must allow every action."""
    spec = match_capability(finding_id="CLOUD-LOG-003")
    # All but GetRole allowed — still MISSING
    sim = {a: "allowed" for a in spec.action_names()}
    sim["iam:GetRole"] = "implicitDeny"
    classified = classify_simulation(spec, sim)
    assert classified["state"] == MISSING_PERMISSIONS
    assert "iam:GetRole" in classified["missing"]


def test_24_bootstrap_satisfied_after_proof():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "allowed" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["bootstrap_authorization_status"] == "SATISFIED"
    assert assessment["bootstrap_install_state"] == "SATISFIED"
    assert assessment["bootstrap_verification_state"] == "VERIFIED"


def test_25_resource_map_includes_guardduty_slr_getrole():
    from change_assurance.capabilities.probe import resource_map_for_spec

    spec = match_capability(finding_id="CLOUD-LOG-003")
    rmap = resource_map_for_spec(spec, account_id="952654481542", region="us-east-1")
    assert "iam:GetRole" in rmap
    assert "AWSServiceRoleForAmazonGuardDuty" in rmap["iam:GetRole"]


def test_26_ordinary_plan_excludes_bootstrap_iam_after_ready():
    """Ordinary remediation must not permanently bundle bootstrap IAM."""
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "allowed" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["ordinary_remediation_includes_iam"] is False
    note = (assessment.get("bootstrap") or {}).get("ordinary_remediation_note") or ""
    assert "control artifact only" in note.lower() or "terraform/" in note
    assert assessment.get("bootstrap", {}).get("terraform") is None  # satisfied record, not install package



def test_27_manager_decision_remains_pending_when_capability_ready():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542", "manager_decision": "PENDING"},
        simulated={a: "allowed" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["state"] == READY
    assert assessment["execution_gate"] == "READY_PENDING_MANAGER_AUTHORIZATION"
    # Capability READY never implies execution performed
    assert assessment.get("aws_modified") is False
    assert assessment.get("auto_attached") is False


def test_28_no_execution_from_capability_assessment():
    assessment = assess_execution_capability(
        finding_id="CLOUD-LOG-003",
        job={"aws_account_id": "952654481542"},
        simulated={a: "allowed" for a in match_capability(finding_id="CLOUD-LOG-003").action_names()},
        run_live_probe=False,
    )
    assert assessment["aws_modified"] is False
    assert assessment["auto_attached"] is False
    assert assessment["self_bootstrap_forbidden"] is True


def test_29_fresh_ready_skips_unnecessary_reprobe():
    from datetime import datetime, timezone, timedelta
    from change_assurance.capabilities.freshness import capability_needs_reprobe

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert (
        capability_needs_reprobe({"state": READY, "verified_at": recent}, now=now) is False
    )
    assert (
        capability_needs_reprobe(
            {"state": MISSING_PERMISSIONS, "verified_at": recent}, now=now
        )
        is True
    )


def test_30_changed_plan_hash_rebuilds_pending_binding(tmp_path):
    """Changed plan/hash must rebuild a pending approval binding (no auto-approve)."""
    from change_assurance.approval_integrity import build_approval_binding, validate_approval_binding

    art = {
        "artifact_id": "gd-plan",
        "artifact_type": "terraform_plan",
        "artifact_hash": "hash-v1",
        "meta": {"plan_hash": "plan-v1", "source_hash": "src-v1", "terraform_plan_hash": "plan-v1"},
    }
    binding = build_approval_binding(
        job_id="job_test",
        finding_id="CLOUD-LOG-003",
        artifacts=[art],
        target_environment="952654481542",
        recommendation="RECOMMEND_APPROVE",
        manager_decision=None,
    )
    assert binding["status"] == "PENDING_MANAGER_DECISION"
    assert binding.get("manager_decision") is None

    art2 = dict(art)
    art2["artifact_hash"] = "hash-v2"
    art2["meta"] = {
        "plan_hash": "plan-v2",
        "source_hash": "src-v1",
        "terraform_plan_hash": "plan-v2",
    }
    result = validate_approval_binding(
        binding, artifacts=[art2], target_environment="952654481542"
    )
    assert result["valid"] is False
    assert result["status"] != "APPROVED_FOR_EXECUTION"

    rebound = build_approval_binding(
        job_id="job_test",
        finding_id="CLOUD-LOG-003",
        artifacts=[art2],
        target_environment="952654481542",
        recommendation="RECOMMEND_APPROVE",
        manager_decision=None,
    )
    assert rebound["status"] == "PENDING_MANAGER_DECISION"
    assert rebound.get("manager_decision") is None
    assert rebound["artifact_hash"] != binding["artifact_hash"]


