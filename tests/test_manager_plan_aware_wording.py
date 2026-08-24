# Generic recovery Manager Mode wording — questions / prepare from CURRENT plan.

from __future__ import annotations

import json
from pathlib import Path

from change_assurance.plan_manager_context import (
    filter_stale_manager_questions,
    flags_from_plan_addresses,
    manager_questions_for_plan,
    split_prepare_resources,
)
from manager_mode import build_manager_card, _artifact_readiness_block, _plan_aware_manager_questions


def test_flags_clear_iam_when_plan_has_no_iam():
    flags = flags_from_plan_addresses(
        [
            "aws_config_configuration_recorder.sentinel",
            "aws_s3_bucket_policy.config",
        ],
        base_flags={"iam_change": True, "config_recorder_enable": True},
    )
    assert flags["iam_change"] is False
    assert flags["config_recorder_enable"] is True


def test_manager_questions_omit_iam_when_no_iam_in_plan():
    qs = manager_questions_for_plan(
        {"id": "CTRL-NET-9", "title": "Generic control"},
        flags={"iam_change": True, "config_recorder_enable": True},
        plan_addresses=[
            "aws_config_configuration_recorder.x",
            "aws_config_delivery_channel.x",
            "aws_s3_bucket_policy.config",
        ],
    )
    joined = " ".join(qs).lower()
    assert "break-glass" not in joined
    assert "recording scope" in joined
    assert "delivery location" in joined
    assert "cost" in joined


def test_filter_stale_break_glass_question():
    filtered = filter_stale_manager_questions(
        [
            "MANAGER CONTEXT REQUIRED: Will IAM changes affect break-glass or production roles?",
            "MANAGER CONTEXT REQUIRED: Confirm AWS Config recording scope is acceptable.",
        ],
        plan_addresses=["aws_config_configuration_recorder.sentinel"],
        flags={"iam_change": True},
    )
    assert len(filtered) == 1
    assert "recording scope" in filtered[0].lower()


def test_split_prepare_already_created_vs_will_create():
    split = split_prepare_resources(
        resolution_resources=[
            "aws_iam_service_linked_role.config",
            "data.aws_caller_identity.current",
            "aws_s3_bucket.config",
            "aws_s3_bucket_policy.config",
            "aws_config_configuration_recorder.sentinel",
        ],
        already_created=[
            "aws_iam_service_linked_role.config",
            "aws_s3_bucket.config",
        ],
        current_creates=[
            "aws_s3_bucket_policy.config",
            "aws_config_configuration_recorder.sentinel",
        ],
    )
    assert split["already_created"] == [
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
    ]
    assert "aws_iam_service_linked_role.config" not in split["will_create"]
    assert "aws_s3_bucket.config" not in split["will_create"]
    assert "data.aws_caller_identity.current" not in split["will_create"]
    assert split["will_create"] == [
        "aws_s3_bucket_policy.config",
        "aws_config_configuration_recorder.sentinel",
    ]


def test_generic_recovery_card_omits_iam_question_and_splits_prepare(tmp_path: Path):
    """Another generic recovery case (not CLOUD-LOG-002-only)."""
    job = {
        "job_id": "job_generic_recovery",
        "status": "pending_approval",
        "manager_decision": None,
        "finding_decisions": {"CTRL-REC-1": "pending_recovery"},
        "approval_status": "APPROVAL_INVALIDATED",
        "execution_authorized": False,
        "prerequisite_resolutions": {
            "CTRL-REC-1": {
                "resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                    "aws_s3_bucket_policy.config",
                    "aws_config_configuration_recorder.sentinel",
                    "aws_config_delivery_channel.sentinel",
                ]
            }
        },
        "reviewed_terraform_plans": {
            "CTRL-REC-1": {
                "plan_kind": "recovery",
                "status": "CURRENT",
                "summary": {"create": 3, "modify": 0, "destroy": 0},
                "resource_addresses": [
                    "aws_s3_bucket_policy.config",
                    "aws_config_configuration_recorder.sentinel",
                    "aws_config_delivery_channel.sentinel",
                ],
                "source_artifact_sha256": "abc123",
            }
        },
        "finding_execution": {
            "CTRL-REC-1": {
                "status": "RECOVERY_REQUIRED",
                "execution_status": "PARTIAL EXECUTION — RECOVERY REQUIRED",
                "succeeded_resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                ],
                "recovery_resources": [
                    "aws_s3_bucket_policy.config",
                    "aws_config_configuration_recorder.sentinel",
                    "aws_config_delivery_channel.sentinel",
                ],
                "recovery_plan_summary": {"create": 3, "modify": 0, "destroy": 0},
                "recovery_plan_status": "CURRENT",
                "recovery_plan_sha256": "deadbeef",
            }
        },
    }
    impact = {
        "primary_finding_id": "CTRL-REC-1",
        "recommendation": "RECOMMEND_REVIEW",
        "finding_status": "OPEN",
        "manager_context_required": True,
        "manager_questions": [
            "MANAGER CONTEXT REQUIRED: Will IAM changes affect break-glass or production roles?",
            "MANAGER CONTEXT REQUIRED: Confirm recording scope and delivery location for AWS Config.",
        ],
        "remediation_status": "RECOVERY_REQUIRED",
        "prerequisite_resolution": job["prerequisite_resolutions"]["CTRL-REC-1"],
        "reviewed_plan": job["reviewed_terraform_plans"]["CTRL-REC-1"],
    }
    finding = {"id": "CTRL-REC-1", "title": "Config recorder missing", "severity": "high"}

    qs = _plan_aware_manager_questions(job, finding, impact, impact)
    assert qs
    assert all("break-glass" not in q.lower() for q in qs)
    assert any("recording scope" in q.lower() for q in qs)
    assert any("cost" in q.lower() for q in qs)

    ready = _artifact_readiness_block(impact, impact, job=job, finding=finding)
    assert ready["already_created"] == [
        "aws_iam_service_linked_role.config",
        "aws_s3_bucket.config",
    ]
    assert ready["will_create"] == [
        "aws_s3_bucket_policy.config",
        "aws_config_configuration_recorder.sentinel",
        "aws_config_delivery_channel.sentinel",
    ]
    assert "aws_iam_service_linked_role.config" not in ready["prepare"]
    assert "aws_s3_bucket.config" not in ready["prepare"]

    card = build_manager_card(finding, job, impact, is_primary=True)
    assert card["manager_decision"] == "PENDING"
    assert "PARTIAL" in card["execution"]
    assert all("break-glass" not in q.lower() for q in card["manager_questions"])
    assert card["artifact_readiness"]["already_created"] == ready["already_created"]
    assert card["artifact_readiness"]["will_create"] == ready["will_create"]
    why = (card.get("why_recommend") or "").lower()
    assert "break-glass" not in why

    # Face template wording
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from manager_mode import build_manager_view

    mm = build_manager_view(job, [finding], impact)
    templates_root = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_root)), autoescape=select_autoescape(["html"]))
    env.globals["url_for"] = lambda *a, **k: "/"
    html = env.get_template("face/job.html").render(
        job=job,
        review={
            "manager": mm,
            "impact": impact,
            "findings": [finding],
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
    assert "ALREADY CREATED DURING PRIOR PARTIAL EXECUTION" in html
    assert "CURRENT RECOVERY PLAN WILL CREATE" in html
    assert "Sentinel will prepare: aws_iam_service_linked_role.config" not in html
    assert "break-glass" not in html.lower()
    assert "aws_s3_bucket_policy.config" in html
