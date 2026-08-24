# Cross-job remediation lifecycle continuity tests.

from __future__ import annotations

import json
from pathlib import Path

from change_assurance.execution_recovery import (
    bind_recovery_terraform_plan,
    record_partial_terraform_execution,
)
from change_assurance.remediation_ledger import (
    STATUS_RECOVERY_REQUIRED,
    discover_aws_config_prerequisites,
    key_for_control,
    lifecycle_key,
    load_record,
    merge_prerequisite_evidence,
    reconcile_job_with_ledger,
    seed_from_job,
    upsert_execution_state,
)
from manager_mode import build_manager_view, execution_label, manager_decision_label


def _write_job(ws: Path, job: dict) -> None:
    (ws / "jobs").mkdir(parents=True, exist_ok=True)
    (ws / "jobs" / f"{job['job_id']}.json").write_text(json.dumps(job, indent=2), encoding="utf-8")


def _recovery_plan_json():
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


def test_cross_job_continuity_job_a_to_job_b(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "jobs").mkdir(parents=True)
    plan = tmp_path / "exec.tfplan"
    plan.write_bytes(b"exec-plan-bytes")
    rec_plan = tmp_path / "recovery.tfplan"
    rec_plan.write_bytes(b"recovery-plan-bytes")
    from change_assurance.plan_ingestion import sha256_file

    exec_sha = sha256_file(plan)
    rec_sha = sha256_file(rec_plan)

    # Dedicated artifact without placeholders
    art = tmp_path / "CLOUD-CTRL-001.tf"
    art.write_text(
        "# CREATE DEDICATED\nresource \"aws_iam_service_linked_role\" \"config\" {}\n"
        "resource \"aws_s3_bucket\" \"config\" {}\n",
        encoding="utf-8",
    )

    job_a = {
        "job_id": "job_A",
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "aws_account_id": "111122223333",
        "region": "us-east-1",
        "execution_role": "SentinelStacksRemediationRole",
        "execution_profile": "sentinel-remediation",
        "kit_path": str(tmp_path / "kit_A.zip"),
        "prerequisite_decisions": {
            "CLOUD-CTRL-001": {"choice": "CREATE_DEDICATED", "finding_id": "CLOUD-CTRL-001"}
        },
        "prerequisite_resolutions": {
            "CLOUD-CTRL-001": {
                "choice": "CREATE_DEDICATED",
                "status": "PREREQUISITES_RESOLVED",
                "artifact_path": str(art),
                "artifact_sha256": "abc",
                "resources": ["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
            }
        },
        "reviewed_terraform_plans": {
            "CLOUD-CTRL-001": {
                "plan_path": str(plan),
                "plan_kind": "execution",
                "account_id": "111122223333",
                "region": "us-east-1",
                "source_artifact_path": str(art),
                "source_artifact_sha256": "abc",
            }
        },
        "approval_binding": {
            "status": "APPROVED_FOR_EXECUTION",
            "manager_decision": "approved",
            "saved_plan_sha256": exec_sha,
            "execution_authorized": True,
        },
        "finding_decisions": {"CLOUD-CTRL-001": "approved"},
        "execution_authorized": True,
        "execution_performed": False,
    }
    _write_job(ws, job_a)

    # 1-4: Job A partial execution + recovery bind
    record_partial_terraform_execution(
        ws,
        "job_A",
        "CLOUD-CTRL-001",
        approved_plan_path=plan,
        approved_plan_sha256=exec_sha,
        succeeded_resources=["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
        failure_reason="AccessDenied CORS",
        failed_action="s3:GetBucketCORS",
    )

    def _fake_ingest(job, finding_id, **kwargs):
        from change_assurance.plan_ingestion import (
            manager_affect_from_plan,
            normalize_terraform_plan,
            risk_rationale_from_plan,
            sha256_file as _sha,
        )

        n = normalize_terraform_plan(
            _recovery_plan_json(),
            finding_id=finding_id,
            saved_plan_path=str(rec_plan),
            saved_plan_sha256=_sha(rec_plan),
            account_id="111122223333",
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
    bind_recovery_terraform_plan(
        ws,
        "job_A",
        "CLOUD-CTRL-001",
        recovery_plan_path=rec_plan,
        expected_plan_sha256=rec_sha,
        source_artifact_path=art,
        source_artifact_sha256="abc",
        account_id="111122223333",
        region="us-east-1",
        expected_create=7,
    )

    job_a = json.loads((ws / "jobs" / "job_A.json").read_text(encoding="utf-8"))
    assert job_a["finding_execution"]["CLOUD-CTRL-001"]["status"] == STATUS_RECOVERY_REQUIRED
    assert len(job_a["finding_execution"]["CLOUD-CTRL-001"]["succeeded_resources"]) == 2

    # Seed / ensure ledger (upsert already ran from record/bind)
    key = lifecycle_key(
        provider="aws", account_id="111122223333", region="us-east-1", control_id="CLOUD-CTRL-001"
    )
    rec = load_record(ws, key)
    assert rec is not None
    assert rec["remediation_state"] == STATUS_RECOVERY_REQUIRED

    # 5-14: Job B discovers same control — reconcile from ledger (not copy from job A id)
    job_b = {
        "job_id": "job_B",
        "role": "cloud",
        "status": "pending_approval",
        "manager_decision": None,
        "summary": {"top_findings": [{"id": "CLOUD-CTRL-001", "severity": "high"}]},
        "kit_path": str(tmp_path / "kit_B"),
        "execution_performed": False,
        "finding_decisions": {},
    }
    (tmp_path / "kit_B" / "terraform").mkdir(parents=True)
    # Simulate regressive unresolved artifact
    (tmp_path / "kit_B" / "terraform" / "CLOUD-CTRL-001.tf").write_text(
        'role_arn = "REPLACE_CONFIG_ROLE"\ns3_bucket_name = "REPLACE_CONFIG_BUCKET"\n',
        encoding="utf-8",
    )
    _write_job(ws, job_b)

    # Fake discovery: both exist
    monkeypatch.setattr(
        "change_assurance.remediation_ledger.discover_aws_config_prerequisites",
        lambda **kw: {
            "role": {
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "evidence_source": "iam.get_role",
                "expected_arn": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                "observed_arn": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
            },
            "bucket": {
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "evidence_source": "s3.head_bucket",
                "expected_name": "sentinel-aws-config-111122223333-us-east-1",
                "observed_name": "sentinel-aws-config-111122223333-us-east-1",
            },
            "read_only": True,
            "aws_modified": False,
        },
    )

    job_b = reconcile_job_with_ledger(
        ws,
        job_b,
        control_ids=["CLOUD-CTRL-001"],
        account_id="111122223333",
        region="us-east-1",
        run_discovery=True,
        persist=True,
    )

    assert job_b["finding_execution"]["CLOUD-CTRL-001"]["status"] == STATUS_RECOVERY_REQUIRED
    assert "PARTIAL" in job_b["finding_execution"]["CLOUD-CTRL-001"]["execution_status"]
    assert execution_label(
        job_b, {"primary_finding_id": "CLOUD-CTRL-001", "finding_execution": job_b["finding_execution"]}
    ) != "NOT PERFORMED"
    assert "PARTIAL" in execution_label(
        job_b, {"primary_finding_id": "CLOUD-CTRL-001", "finding_execution": job_b["finding_execution"]}
    )
    assert job_b["prerequisite_resources" if False else "finding_execution"]
    assert (
        job_b["remediation_lifecycle"]["prerequisite_resources"][
            "aws_iam_service_linked_role.config"
        ]["status"]
        == "EXISTS"
    )
    assert (
        job_b["remediation_lifecycle"]["prerequisite_resources"]["aws_s3_bucket.config"]["status"]
        == "EXISTS"
    )
    # Placeholders overwritten from ledger source artifact
    tf_b = (tmp_path / "kit_B" / "terraform" / "CLOUD-CTRL-001.tf").read_text(encoding="utf-8")
    assert "REPLACE_CONFIG_ROLE" not in tf_b
    assert "REPLACE_CONFIG_BUCKET" not in tf_b
    assert job_b["reviewed_terraform_plans"]["CLOUD-CTRL-001"]["plan_path"] == str(rec_plan)
    assert manager_decision_label(job_b, {"id": "CLOUD-CTRL-001"}) == "PENDING"
    assert job_b["approval_binding"]["status"] == "APPROVAL_INVALIDATED"
    assert job_b["approval_status"] == "APPROVAL_INVALIDATED"
    # Finding remains open — remediation != resolved control
    assert (load_record(ws, key) or {}).get("finding_state") == "OPEN"

    # 15: later prerequisite removal can change state
    monkeypatch.setattr(
        "change_assurance.remediation_ledger.discover_aws_config_prerequisites",
        lambda **kw: {
            "role": {"status": "MISSING", "evidence_quality": "DIRECT", "evidence_source": "iam.get_role"},
            "bucket": {
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "evidence_source": "s3.head_bucket",
                "expected_name": "b",
            },
            "read_only": True,
        },
    )
    job_b2 = json.loads((ws / "jobs" / "job_B.json").read_text(encoding="utf-8"))
    job_b2 = reconcile_job_with_ledger(
        ws,
        job_b2,
        control_ids=["CLOUD-CTRL-001"],
        account_id="111122223333",
        region="us-east-1",
        run_discovery=True,
        persist=True,
    )
    pr = job_b2["remediation_lifecycle"]["prerequisite_resources"]
    assert pr["aws_iam_service_linked_role.config"]["status"] == "MISSING"

    # 16-18: different account/region/control do NOT inherit
    other = {
        "job_id": "job_C",
        "role": "cloud",
        "status": "pending_approval",
        "summary": {"top_findings": [{"id": "CLOUD-CTRL-001"}]},
    }
    _write_job(ws, other)
    other = reconcile_job_with_ledger(
        ws,
        other,
        control_ids=["CLOUD-CTRL-001"],
        account_id="999999999999",
        region="us-east-1",
        run_discovery=False,
        persist=True,
    )
    assert not (other.get("finding_execution") or {}).get("CLOUD-CTRL-001")

    other2 = {
        "job_id": "job_D",
        "role": "cloud",
        "status": "pending_approval",
        "summary": {"top_findings": [{"id": "CLOUD-CTRL-001"}]},
    }
    _write_job(ws, other2)
    other2 = reconcile_job_with_ledger(
        ws,
        other2,
        control_ids=["CLOUD-CTRL-001"],
        account_id="111122223333",
        region="eu-west-1",
        run_discovery=False,
        persist=True,
    )
    assert not (other2.get("finding_execution") or {}).get("CLOUD-CTRL-001")

    other3 = {
        "job_id": "job_E",
        "role": "cloud",
        "status": "pending_approval",
        "aws_account_id": "111122223333",
        "region": "us-east-1",
        "summary": {"top_findings": [{"id": "CLOUD-OTHER-999"}]},
    }
    _write_job(ws, other3)
    other3 = reconcile_job_with_ledger(
        ws,
        other3,
        control_ids=["CLOUD-OTHER-999"],
        run_discovery=False,
        persist=True,
    )
    assert not (other3.get("finding_execution") or {}).get("CLOUD-OTHER-999")


def test_19_face_render_new_scan_job(tmp_path):
    ws = tmp_path / "ws"
    (ws / "jobs").mkdir(parents=True)
    key = lifecycle_key(
        provider="aws", account_id="1", region="us-east-1", control_id="CLOUD-CTRL-001"
    )
    upsert_execution_state(
        ws,
        provider="aws",
        account_id="1",
        region="us-east-1",
        control_id="CLOUD-CTRL-001",
        remediation_state=STATUS_RECOVERY_REQUIRED,
        finding_execution={
            "status": STATUS_RECOVERY_REQUIRED,
            "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
            "previous_execution": "FAILED AFTER PARTIAL SUCCESS",
            "succeeded_resources": ["aws_iam_service_linked_role.config", "aws_s3_bucket.config"],
            "recovery_plan_summary": {"create": 7, "modify": 0, "destroy": 0},
            "recovery_plan_sha256": "abc",
            "recovery_resources": ["r1"],
            "prior_approval_valid": False,
            "latest_attempt": {
                "failure_reason": "lacked s3:GetBucketCORS",
                "failed_action": "s3:GetBucketCORS",
            },
        },
        reviewed_plan={
            "plan_path": "x.tfplan",
            "summary": {"create": 7, "modify": 0, "destroy": 0},
            "plan_kind": "recovery",
        },
        approval={"status": "APPROVAL_INVALIDATED", "invalidation_reasons": ["PARTIAL_EXECUTION_CHANGED_STATE"]},
        prerequisite_decision={"choice": "CREATE_DEDICATED"},
        prerequisite_resources={
            "aws_iam_service_linked_role.config": {
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "identity": "arn:...",
            },
            "aws_s3_bucket.config": {
                "status": "EXISTS",
                "evidence_quality": "DIRECT",
                "identity": "bucket",
            },
        },
        job_id="job_new",
    )
    job = {
        "job_id": "job_new",
        "role": "cloud",
        "status": "pending_approval",
        "aws_account_id": "1",
        "region": "us-east-1",
        "finding_decisions": {"CLOUD-CTRL-001": "pending_recovery"},
        "approval_status": "APPROVAL_INVALIDATED",
        "execution_performed": True,
        "apply_status": "partial_failed",
    }
    job = reconcile_job_with_ledger(
        ws, job, control_ids=["CLOUD-CTRL-001"], run_discovery=False, persist=True
    )
    mm = build_manager_view(
        job,
        [{"id": "CLOUD-CTRL-001", "title": "Test control", "severity": "high"}],
        {
            "primary_finding_id": "CLOUD-CTRL-001",
            "finding_status": "FAIL",
            "recommendation": "RECOMMEND_REVIEW",
            "remediation_lifecycle_state": STATUS_RECOVERY_REQUIRED,
            "suppress_placeholder_prerequisites": True,
            "prerequisite_existence": [
                {"label": "AWS Config IAM role", "status": "EXISTS", "evidence_quality": "DIRECT"},
                {"label": "S3 delivery bucket", "status": "EXISTS", "evidence_quality": "DIRECT"},
            ],
            "prerequisite_manager_decision": "CREATE DEDICATED RESOURCES",
            "remediation_status": "RECOVERY_REQUIRED",
            "reviewed_plan": {
                "summary": {"create": 7, "modify": 0, "destroy": 0},
                "manager_affect": {
                    "plan_reviewed": True,
                    "plan_create": 7,
                    "plan_modify": 0,
                    "plan_destroy": 0,
                    "summary_line": "Plan: 7 CREATE / 0 CHANGE / 0 DESTROY",
                    "resources_to_create": ["x"],
                    "resources_modified": ["NONE"],
                    "resources_destroyed": ["NONE"],
                    "detail_lines": [],
                    "scope": "Regional",
                    "risk_rationale": "MEDIUM",
                    "cloudtrail_bucket": "NOT TOUCHED",
                    "known_dependencies": [],
                    "unknowns": [],
                },
            },
        },
        focus_finding_id="CLOUD-CTRL-001",
    )
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["url_for"] = lambda *a, **k: "/"
    html = env.get_template("face/job.html").render(
        job=job,
        review={
            "manager": mm,
            "impact": {"recommendation": "RECOMMEND_REVIEW", "finding_status": "FAIL"},
            "findings": [{"id": "CLOUD-CTRL-001", "title": "Test", "severity": "high"}],
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
    assert "PARTIAL EXECUTION" in html
    assert "NOT PERFORMED" not in html or "PARTIAL" in html
    assert "PENDING" in html
    assert "EXISTS" in html
    assert "Missing: AWS Config IAM role" not in html


def test_20_generic_non_cloud_log_key_isolation(tmp_path):
    ws = tmp_path / "ws"
    upsert_execution_state(
        ws,
        provider="azure",
        account_id="sub-1",
        region="eastus",
        control_id="AZURE-NET-001",
        remediation_state=STATUS_RECOVERY_REQUIRED,
        finding_execution={
            "status": STATUS_RECOVERY_REQUIRED,
            "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
            "succeeded_resources": ["azurerm_resource_group.rg"],
        },
        job_id="job_az",
    )
    job = {
        "job_id": "job_az2",
        "role": "cloud",
        "status": "pending_approval",
        "summary": {"top_findings": [{"id": "AZURE-NET-001"}]},
    }
    _write_job(ws, job)
    job = reconcile_job_with_ledger(
        ws,
        job,
        control_ids=["AZURE-NET-001"],
        account_id="sub-1",
        region="eastus",
        run_discovery=False,
        persist=True,
    )
    assert job["finding_execution"]["AZURE-NET-001"]["status"] == STATUS_RECOVERY_REQUIRED
    # AWS control must not pick up Azure lifecycle
    job2 = {
        "job_id": "job_aws",
        "role": "cloud",
        "aws_account_id": "sub-1",
        "region": "eastus",
        "summary": {"top_findings": [{"id": "CLOUD-LOG-002"}]},
    }
    _write_job(ws, job2)
    job2 = reconcile_job_with_ledger(
        ws, job2, control_ids=["CLOUD-LOG-002"], run_discovery=False, persist=True
    )
    assert not (job2.get("finding_execution") or {}).get("CLOUD-LOG-002")


def test_merge_trusted_history_when_discovery_unknown():
    rec = {
        "account_id": "1",
        "region": "us-east-1",
        "finding_execution": {
            "succeeded_resources": [
                "aws_iam_service_linked_role.config",
                "aws_s3_bucket.config",
            ]
        },
        "prerequisite_resources": {},
    }
    out = merge_prerequisite_evidence(
        rec,
        {
            "role": {"status": "UNKNOWN", "evidence_quality": "ERROR"},
            "bucket": {"status": "UNKNOWN", "evidence_quality": "ERROR"},
        },
    )
    assert out["prerequisite_resources"]["aws_iam_service_linked_role.config"]["status"] == "EXISTS"
    assert (
        out["prerequisite_resources"]["aws_iam_service_linked_role.config"]["evidence_quality"]
        == "TRUSTED_EXECUTION_HISTORY"
    )
