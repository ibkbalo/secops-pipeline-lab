# Partial Terraform execution + recovery plan — generic class tests.

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from change_assurance.execution_recovery import (
    EXECUTION_LABEL_PARTIAL,
    INVALIDATION_PARTIAL_EXECUTION,
    STATUS_RECOVERY_REQUIRED,
    bind_recovery_terraform_plan,
    record_partial_terraform_execution,
)
from manager_mode import build_manager_card, execution_label, manager_decision_label

FIXTURE = Path(__file__).parent / "fixtures" / "CLOUD-LOG-002-review.tfplan.json"
SRC_SHA = "da297d53055b31ca5d91d17b42dca58da79f8582e3b146d93e074b36964fe7fc"
EXEC_SHA = "a5318a896f4f3ec160bab243badda6f7d440cd6ac27350db574d0905e9d0bd2e"
REC_SHA = "07af9f7bdfa78d13643dee988997662aa76ce2b998053fa238afef3006876672"


def _recovery_plan_json() -> dict:
    # Minimal 7-create plan JSON (generic — not CLOUD-LOG-002-only)
    resources = [
        ("aws_s3_bucket_public_access_block", "config"),
        ("aws_s3_bucket_server_side_encryption_configuration", "config"),
        ("aws_s3_bucket_ownership_controls", "config"),
        ("aws_s3_bucket_policy", "config"),
        ("aws_config_configuration_recorder", "sentinel"),
        ("aws_config_delivery_channel", "sentinel"),
        ("aws_config_configuration_recorder_status", "sentinel"),
    ]
    return {
        "format_version": "1.0",
        "resource_changes": [
            {
                "address": f"{t}.{n}",
                "type": t,
                "name": n,
                "change": {"actions": ["create"]},
            }
            for t, n in resources
        ],
    }


@pytest.fixture
def ws_job(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "jobs").mkdir(parents=True)
    (ws / "approvals").mkdir(parents=True)
    plan = tmp_path / "approved.tfplan"
    plan.write_bytes(b"fake-approved-plan-bytes")
    rec = tmp_path / "recovery.tfplan"
    rec.write_bytes(b"fake-recovery-plan-bytes")
    # Real hashes computed from bytes
    from change_assurance.plan_ingestion import sha256_file

    exec_sha = sha256_file(plan)
    rec_sha = sha256_file(rec)
    job_id = "job_partial_exec"
    job = {
        "job_id": job_id,
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "approval_status": "APPROVED_FOR_EXECUTION",
        "execution_authorized": True,
        "execution_performed": False,
        "finding_decisions": {"FIND-A": "approved", "FIND-B": "approved"},
        "approval_binding": {
            "status": "APPROVED_FOR_EXECUTION",
            "manager_decision": "approved",
            "saved_plan_sha256": exec_sha,
            "execution_authorized": True,
            "finding_id": "FIND-A",
        },
        "region": "us-east-1",
        "aws_account_id": "952654481542",
        "execution_role": "SentinelStacksRemediationRole",
        "reviewed_terraform_plans": {
            "FIND-A": {
                "plan_path": str(plan),
                "saved_plan_sha256": exec_sha,
                "plan_kind": "execution",
            }
        },
    }
    (ws / "jobs" / f"{job_id}.json").write_text(json.dumps(job), encoding="utf-8")
    return ws, job_id, plan, rec, exec_sha, rec_sha


def test_01_partial_execution_recorded(ws_job):
    ws, job_id, plan, _rec, exec_sha, _ = ws_job
    out = record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="AccessDenied on bucket CORS read",
        failed_action="s3:GetBucketCORS",
    )
    assert out["status"] == STATUS_RECOVERY_REQUIRED
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert len(job["execution_attempts"]) == 1
    assert job["execution_attempts"][0]["result"] == "PARTIAL_EXECUTION"
    assert job["execution_performed"] is True


def test_02_two_resources_succeeded(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="x",
        failed_action="s3:GetBucketCORS",
    )
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert job["finding_execution"]["FIND-A"]["succeeded_resources"] == [
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
    ]


def test_03_prior_approval_invalidated(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    out = record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["a", "b"],
        failure_reason="fail",
        failed_action="s3:GetBucketCORS",
    )
    assert out["invalidation_reason"] == INVALIDATION_PARTIAL_EXECUTION
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert job["approval_status"] == "APPROVAL_INVALIDATED"
    assert job["approval_binding"]["status"] == "APPROVAL_INVALIDATED"
    assert job["execution_authorized"] is False
    assert job["approval_binding"]["manager_decision"] is None


def test_04_to_08_recovery_binding_and_manager_state(ws_job, monkeypatch):
    ws, job_id, plan, rec, exec_sha, rec_sha = ws_job
    record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="CORS AccessDenied",
        failed_action="s3:GetBucketCORS",
    )

    def _fake_ingest(job, finding_id, **kwargs):
        pj = _recovery_plan_json()
        from change_assurance.plan_ingestion import (
            manager_affect_from_plan,
            normalize_terraform_plan,
            risk_rationale_from_plan,
            sha256_file,
        )

        n = normalize_terraform_plan(
            pj,
            finding_id=finding_id,
            saved_plan_path=str(rec),
            saved_plan_sha256=sha256_file(rec),
            source_artifact_sha256=SRC_SHA,
            account_id="952654481542",
            region="us-east-1",
            execution_role="SentinelStacksRemediationRole",
        )
        n["manager_affect"] = manager_affect_from_plan(n)
        n["risk"] = risk_rationale_from_plan(n)
        return n

    monkeypatch.setattr(
        "change_assurance.execution_recovery.ingest_reviewed_plan_for_finding",
        _fake_ingest,
    )
    out = bind_recovery_terraform_plan(
        ws,
        job_id,
        "FIND-A",
        recovery_plan_path=rec,
        expected_plan_sha256=rec_sha,
        source_artifact_sha256=SRC_SHA,
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
        expected_create=7,
    )
    assert out["summary"]["create"] == 7
    assert out["summary"]["modify"] == 0
    assert out["summary"]["destroy"] == 0
    assert out["recovery_plan_sha256"] == rec_sha
    assert out["manager_decision"] == "PENDING"
    assert out["prior_approval_valid"] is False

    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert job["finding_decisions"]["FIND-A"] == "pending_recovery"
    assert job["finding_decisions"]["FIND-B"] == "approved"  # sibling preserved
    assert job["reviewed_terraform_plans"]["FIND-A"]["plan_kind"] == "recovery"
    assert job["manager_decision"] is None

    # Manager Mode labels
    assert manager_decision_label(job, {"id": "FIND-A"}) == "PENDING"
    impact = {"primary_finding_id": "FIND-A", "finding_execution": job["finding_execution"]}
    assert "PARTIAL" in execution_label(job, impact)
    assert "NOT PERFORMED" not in execution_label(job, impact)

    card = build_manager_card(
        {"id": "FIND-A", "title": "Test control", "severity": "high"},
        job,
        {
            "primary_finding_id": "FIND-A",
            "recommendation": "RECOMMEND_REVIEW",
            "finding_status": "OPEN",
        },
        is_primary=True,
    )
    assert card["manager_decision"] == "PENDING"
    assert "PARTIAL" in card["execution"]
    assert card["finding_execution"]["succeeded_resources"]
    assert card["approval_integrity"]["needs_review"] is True


def test_09_case_not_resolved(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    out = record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["a"],
        failure_reason="x",
    )
    assert out["case_resolved"] is False
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert job["execution_attempts"][0]["case_resolved"] is False


def test_10_history_preserves_successes(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["r1", "r2"],
        failure_reason="x",
        failed_action="s3:GetBucketCORS",
    )
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    att = job["execution_attempts"][0]
    assert att["succeeded_resources"] == ["r1", "r2"]
    assert att["failed_action"] == "s3:GetBucketCORS"


def test_11_to_13_no_auto_actions(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    out = record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["a"],
        failure_reason="x",
    )
    assert out["auto_apply"] is False
    assert out["auto_retry"] is False
    assert out["auto_rollback"] is False
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    att = job["execution_attempts"][0]
    assert att["automatic_apply"] is False
    assert att["automatic_retry"] is False
    assert att["automatic_rollback"] is False
    assert att["platform_auto_execution"] is False
    assert att["human_triggered_execution"] is True


def test_14_generic_beyond_cloud_log_002(ws_job):
    ws, job_id, plan, _, exec_sha, _ = ws_job
    # Same API for an arbitrary finding id
    out = record_partial_terraform_execution(
        ws,
        job_id,
        "AZURE-NET-001",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["azurerm_resource_group.rg"],
        failure_reason="provider auth failed",
        failed_action="Microsoft.Resources/subscriptions/resourcegroups/read",
    )
    assert out["status"] == STATUS_RECOVERY_REQUIRED
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert "AZURE-NET-001" in job["finding_execution"]


def test_15_face_render_partial_not_not_performed(ws_job, monkeypatch):
    ws, job_id, plan, rec, exec_sha, rec_sha = ws_job
    record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="lacked s3:GetBucketCORS",
        failed_action="s3:GetBucketCORS",
    )

    def _fake_ingest(job, finding_id, **kwargs):
        from change_assurance.plan_ingestion import (
            manager_affect_from_plan,
            normalize_terraform_plan,
            risk_rationale_from_plan,
            sha256_file,
        )

        n = normalize_terraform_plan(
            _recovery_plan_json(),
            finding_id=finding_id,
            saved_plan_path=str(rec),
            saved_plan_sha256=sha256_file(rec),
            region="us-east-1",
            account_id="952654481542",
            execution_role="SentinelStacksRemediationRole",
        )
        n["manager_affect"] = manager_affect_from_plan(n)
        n["risk"] = risk_rationale_from_plan(n)
        return n

    monkeypatch.setattr(
        "change_assurance.execution_recovery.ingest_reviewed_plan_for_finding",
        _fake_ingest,
    )
    bind_recovery_terraform_plan(
        ws,
        job_id,
        "FIND-A",
        recovery_plan_path=rec,
        expected_plan_sha256=rec_sha,
        expected_create=7,
        region="us-east-1",
        account_id="952654481542",
        execution_role="SentinelStacksRemediationRole",
    )
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from manager_mode import build_manager_view

    mm = build_manager_view(
        job,
        [{"id": "FIND-A", "title": "AWS Config recorder enabled", "severity": "high"}],
        {
            "primary_finding_id": "FIND-A",
            "recommendation": "RECOMMEND_REVIEW",
            "finding_status": "OPEN",
            "reviewed_plan": {
                "summary": {"create": 7, "modify": 0, "destroy": 0},
                "manager_affect": {
                    "plan_reviewed": True,
                    "plan_create": 7,
                    "plan_modify": 0,
                    "plan_destroy": 0,
                    "summary_line": "Scope: Regional — us-east-1. Plan: 7 CREATE / 0 CHANGE / 0 DESTROY.",
                    "resources_to_create": ["x"],
                    "resources_modified": ["NONE"],
                    "resources_destroyed": ["NONE"],
                    "cloudtrail_bucket": "NOT TOUCHED",
                    "known_dependencies": ["dep"],
                    "unknowns": ["u"],
                    "detail_lines": ["7 CREATE"],
                    "scope": "Regional — us-east-1",
                    "risk_rationale": "MEDIUM because recovery",
                },
                "risk": {"level": "MEDIUM", "rationale": "MEDIUM because recovery"},
            },
        },
        focus_finding_id="FIND-A",
    )
    templates_root = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_root)), autoescape=select_autoescape(["html"]))
    env.globals["url_for"] = lambda *a, **k: "/"
    html = env.get_template("face/job.html").render(
        job=job,
        review={
            "manager": mm,
            "impact": {"recommendation": "RECOMMEND_REVIEW"},
            "findings": [{"id": "FIND-A", "title": "AWS Config recorder enabled", "severity": "high"}],
            "findings_count": 1,
            "kit_exists": False,
            "kit_files": [],
            "explain": {},
            "risk_score": 1,
            "risk_label": "low",
            "risk_class": "ok",
            "compliance": {},
        },
        FACE_VERSION="test",
    )
    assert "NOT PERFORMED" not in html or "PARTIAL EXECUTION" in html
    assert "PARTIAL EXECUTION" in html or "RECOVERY REQUIRED" in html
    assert "PENDING" in html
    assert "aws_iam_service_linked_role.config" in html
    assert "s3:GetBucketCORS" in html or "GetBucketCORS" in html


def _recovery_v3_plan_json() -> dict:
    resources = [
        ("aws_config_configuration_recorder", "sentinel"),
        ("aws_config_configuration_recorder_status", "sentinel"),
        ("aws_config_delivery_channel", "sentinel"),
        ("aws_s3_bucket_ownership_controls", "config"),
        ("aws_s3_bucket_policy", "config"),
        ("aws_s3_bucket_public_access_block", "config"),
        ("aws_s3_bucket_server_side_encryption_configuration", "config"),
        ("aws_s3_bucket_versioning", "config"),
    ]
    return {
        "format_version": "1.0",
        "resource_changes": [
            {
                "address": f"{t}.{n}",
                "type": t,
                "name": n,
                "change": {"actions": ["create"]},
            }
            for t, n in resources
        ],
    }


def test_16_bind_recovery_v3_eight_creates_preserves_history(ws_job, monkeypatch):
    """Bind 8/0/0 recovery-v3; keep original partial + superseded v2 history."""
    ws, job_id, plan, _, exec_sha, _ = ws_job
    from change_assurance.plan_ingestion import sha256_file

    v2 = ws.parent / "recovery-v2.tfplan"
    v2.write_bytes(b"fake-recovery-v2")
    v2_sha = sha256_file(v2)
    v3 = ws.parent / "recovery-v3.tfplan"
    v3.write_bytes(b"fake-recovery-v3")
    v3_sha = sha256_file(v3)
    src_sha = "491ee23976fb39e51359b1a06f99a83ddc06fb40e1731b4ab6370a85fca242f9"

    record_partial_terraform_execution(
        ws,
        job_id,
        "FIND-A",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="lacked s3:GetBucketCORS",
        failed_action="s3:GetBucketCORS",
    )

    def _fake_ingest(job, finding_id, **kwargs):
        from change_assurance.plan_ingestion import (
            manager_affect_from_plan,
            normalize_terraform_plan,
            risk_rationale_from_plan,
        )

        ref = (job.get("reviewed_terraform_plans") or {}).get(finding_id) or {}
        path = str(ref.get("plan_path") or ref.get("saved_plan_path") or "")
        # First bind uses 7 creates (v2); second uses 8 (v3)
        use_v3 = "recovery-v3" in path.replace("\\", "/").lower()
        payload = _recovery_v3_plan_json() if use_v3 else _recovery_plan_json()
        disk_sha = v3_sha if use_v3 else v2_sha
        n = normalize_terraform_plan(
            payload,
            finding_id=finding_id,
            saved_plan_path=path or str(v3),
            saved_plan_sha256=disk_sha,
            source_artifact_sha256=kwargs.get("source_artifact_sha256") or src_sha,
            region="us-east-1",
            account_id="952654481542",
            execution_role="SentinelStacksRemediationRole",
        )
        n["manager_affect"] = manager_affect_from_plan(n)
        n["risk"] = risk_rationale_from_plan(n)
        return n

    monkeypatch.setattr(
        "change_assurance.execution_recovery.ingest_reviewed_plan_for_finding",
        _fake_ingest,
    )

    bind_recovery_terraform_plan(
        ws,
        job_id,
        "FIND-A",
        recovery_plan_path=v2,
        expected_plan_sha256=v2_sha,
        source_artifact_sha256=SRC_SHA,
        expected_create=7,
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
    )
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    job.setdefault("reviewed_plan_history", []).append(
        {
            "plan_kind": "execution",
            "plan_sha256": exec_sha,
            "summary": {"create": 9, "modify": 0, "destroy": 0},
            "status": "PARTIALLY_EXECUTED",
            "executable": False,
        }
    )
    (ws / "jobs" / f"{job_id}.json").write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")

    out = bind_recovery_terraform_plan(
        ws,
        job_id,
        "FIND-A",
        recovery_plan_path=v3,
        expected_plan_sha256=v3_sha,
        source_artifact_sha256=src_sha,
        expected_create=8,
        account_id="952654481542",
        region="us-east-1",
        execution_role="SentinelStacksRemediationRole",
    )
    assert out["summary"] == {"create": 8, "modify": 0, "replace": 0, "destroy": 0} or (
        out["summary"]["create"] == 8
        and out["summary"]["modify"] == 0
        and out["summary"]["destroy"] == 0
    )
    assert out["recovery_plan_sha256"] == v3_sha
    assert "aws_s3_bucket_versioning.config" in (out.get("resource_addresses") or [])
    assert "aws_iam_service_linked_role.config" not in (out.get("resource_addresses") or [])
    assert "aws_s3_bucket.config" not in (out.get("resource_addresses") or [])
    assert out["manager_decision"] == "PENDING"

    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    fe = job["finding_execution"]["FIND-A"]
    assert fe["recovery_plan_status"] == "CURRENT"
    assert fe["cross_control_versioning_addressed"] is True
    assert fe["succeeded_resources"] == [
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
    ]
    assert fe["prior_recovery_plan_sha256"] == v2_sha
    assert fe["prior_recovery_plan_superseded"] is True
    assert job["reviewed_terraform_plans"]["FIND-A"]["source_artifact_sha256"] == src_sha
    assert job["finding_decisions"]["FIND-A"] == "pending_recovery"
    assert job["manager_decision"] is None
    assert job["execution_authorized"] is False

    history = job.get("reviewed_plan_history") or []
    shas = {(h.get("plan_sha256") or h.get("saved_plan_sha256")) for h in history}
    assert exec_sha in shas
    assert v2_sha in shas

    card = build_manager_card(
        {"id": "FIND-A", "title": "AWS Config recorder enabled", "severity": "high"},
        job,
        {
            "primary_finding_id": "FIND-A",
            "recommendation": "RECOMMEND_REVIEW",
            "finding_status": "OPEN",
        },
        is_primary=True,
    )
    assert card["manager_decision"] == "PENDING"
    assert "PARTIAL" in card["execution"]
    assert card["source_artifact_sha256"] == src_sha
    assert card["cross_control_note"] == "S3 versioning addressed in proposed recovery plan"
    assert card["finding_execution"]["recovery_plan_summary"]["create"] == 8
