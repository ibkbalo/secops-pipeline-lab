# CLOUD-LOG-002 remediation readiness / prerequisites — regression tests.
# No AWS calls. No auto-apply.

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from change_assurance import recommendations
from change_assurance.prerequisites import prerequisites_from_placeholders
from manager_mode import build_manager_card, translate_recommendation
from predeploy import terraform_plan_analysis as tfplan

DIRTY_CONFIG_TF = """\
resource "aws_config_configuration_recorder" "sentinel" {
  name     = "sentinel-recorder"
  role_arn = "arn:aws:iam::123456789012:role/REPLACE_CONFIG_ROLE"
  recording_group {
    all_supported = true
  }
}
resource "aws_config_delivery_channel" "sentinel" {
  name           = "sentinel-delivery"
  s3_bucket_name = "REPLACE_CONFIG_BUCKET"
}
"""

CLEAN_CONFIG_TF = """\
resource "aws_config_configuration_recorder" "sentinel" {
  name     = "sentinel-recorder"
  role_arn = "arn:aws:iam::123456789012:role/approved-config-role"
  recording_group {
    all_supported = true
  }
}
resource "aws_config_delivery_channel" "sentinel" {
  name           = "sentinel-delivery"
  s3_bucket_name = "approved-config-delivery-bucket"
}
"""

SIBLING_DIRTY_TF = 'bucket = "REPLACE_OTHER_BUCKET"\n'


def _kit(tmp_path: Path, files: dict[str, str], manifest_items: list[dict]) -> Path:
    root = tmp_path / "kit"
    root.mkdir()
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps({"items": manifest_items, "dry_run": True}, indent=2),
        encoding="utf-8",
    )
    return root


def test_01_replace_config_role_detected(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"terraform/CLOUD-LOG-002.tf": DIRTY_CONFIG_TF, "runbooks/CLOUD-LOG-002.yml": "title: config\n"},
        [{"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf", "runbooks/CLOUD-LOG-002.yml"]}],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    tokens = {p["token"] for p in a["placeholders"]}
    assert "REPLACE_CONFIG_ROLE" in tokens
    assert a["flags"]["placeholder_unresolved"] is True


def test_02_replace_config_bucket_detected(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"terraform/CLOUD-LOG-002.tf": DIRTY_CONFIG_TF},
        [{"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf"]}],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    tokens = {p["token"] for p in a["placeholders"]}
    assert "REPLACE_CONFIG_BUCKET" in tokens


def test_03_manager_mode_placeholders_present(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"terraform/CLOUD-LOG-002.tf": DIRTY_CONFIG_TF},
        [{"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf"]}],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    finding = {"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled", "severity": "high"}
    impact = {
        "finding_status": "CONFIRMED",
        "recommendation": "REMEDIATION_PREREQUISITES_REQUIRED",
        "deployment_ready": False,
        "relevant_artifacts": a["files"],
        "relevant_placeholders": a["placeholders"],
        "remediation_status": "PREREQUISITES_REQUIRED",
        "remediation_prerequisites": prerequisites_from_placeholders(a["placeholders"]),
    }
    card = build_manager_card(finding, {"job_id": "j1", "role": "cloud", "status": "pending_approval"}, impact, is_primary=True)
    ready = card["artifact_readiness"]
    assert ready["has_placeholders"] is True
    assert ready["unresolved_placeholders"] != ["NONE"]
    assert any("PRESENT" in c["label"] for c in card["ai_checks"])
    assert translate_recommendation(card["recommendation_raw"]) == "PREREQUISITES REQUIRED"


def test_04_not_execution_ready():
    rec = recommendations.recommend(
        finding_status="CONFIRMED",
        validation_status="FAIL",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=True,
    )
    assert rec["recommendation"] == "REMEDIATION_PREREQUISITES_REQUIRED"
    assert rec["deployment_ready"] is False
    assert rec.get("execution_ready") is False
    assert rec.get("remediation_status") == "PREREQUISITES_REQUIRED"


def test_05_terraform_preferred_over_stale_conf(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {
            "terraform/CLOUD-LOG-002.tf": DIRTY_CONFIG_TF,
            "configs/CLOUD-LOG-002.conf": "# stale CloudTrail guidance\n",
            "runbooks/CLOUD-LOG-002.yml": "title: config\n",
        },
        [
            {
                "check_id": "CLOUD-LOG-002",
                "files": [
                    "configs/CLOUD-LOG-002.conf",
                    "terraform/CLOUD-LOG-002.tf",
                    "runbooks/CLOUD-LOG-002.yml",
                ],
            }
        ],
    )
    scope = tfplan.resolve_finding_kit_artifacts(kit, "CLOUD-LOG-002")
    assert any(p.endswith("CLOUD-LOG-002.tf") for p in scope["paths"])
    assert not any(p.endswith(".conf") for p in scope["paths"])
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is True
    assert any("CLOUD-LOG-002.tf" in f for f in a["files"])


def test_06_resolving_prerequisites_clears_placeholders(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {"terraform/CLOUD-LOG-002.tf": CLEAN_CONFIG_TF},
        [{"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf"]}],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is False
    assert a["placeholders"] == []
    rec = recommendations.recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["recommendation"] == "RECOMMEND_APPROVE"
    assert rec["deployment_ready"] is True


def test_07_sibling_placeholders_do_not_block_this_finding(tmp_path: Path):
    kit = _kit(
        tmp_path,
        {
            "terraform/CLOUD-LOG-002.tf": CLEAN_CONFIG_TF,
            "terraform/CLOUD-STO-008.tf": SIBLING_DIRTY_TF,
        },
        [
            {"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf"]},
            {"check_id": "CLOUD-STO-008", "files": ["terraform/CLOUD-STO-008.tf"]},
        ],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-002"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is False
    siblings = tfplan.scan_kit_placeholders(
        kit,
        exclude_paths=list(a.get("artifact_scope", {}).get("paths") or a.get("files") or []),
    )
    assert siblings  # sibling dirty
    assert not any("CLOUD-LOG-002" in str(s.get("file")) for s in siblings)


def test_08_generic_replace_detected():
    sources = {"x.tf": 'name = "REPLACE_ANYTHING_HERE"\nvalue = "TODO"\n'}
    a = tfplan.analyze_terraform_sources(sources)
    assert a["flags"]["placeholder_unresolved"] is True
    tokens = {p["token"] for p in a["placeholders"]}
    assert "REPLACE_ANYTHING_HERE" in tokens
    assert "TODO" in tokens


def test_09_aws_config_runbook_is_control_specific():
    from ai_remediation_engine import FIX_MAP, TEACHING_GUIDES

    fix = FIX_MAP["CLOUD-LOG-002"]
    steps = fix.get("guide_steps") or TEACHING_GUIDES["CLOUD-LOG-002"]["guide_steps"]
    blob = " ".join(
        f"{s.get('action','')} {s.get('detail','')} {s.get('why','')}" for s in steps
    ).lower()
    assert "least-privilege / cis harden" not in blob
    assert "config" in blob and "recorder" in blob
    assert "replace_config_role" in blob or "iam role" in blob
    assert "replace_config_bucket" in blob or "delivery bucket" in blob or "s3" in blob


def test_10_no_auto_execution_flags():
    rec = recommendations.recommend(
        finding_status="CONFIRMED",
        validation_status="FAIL",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=True,
    )
    assert rec.get("manager_approval_required") is True
    assert rec.get("deployment_ready") is False
    # Advisory recommendation must never imply auto-apply
    assert "AUTO" not in str(rec.get("recommendation") or "").upper()


def test_11_prerequisites_labels_for_config_tokens():
    prereqs = prerequisites_from_placeholders(
        [
            {"file": "terraform/CLOUD-LOG-002.tf", "token": "REPLACE_CONFIG_ROLE"},
            {"file": "terraform/CLOUD-LOG-002.tf", "token": "REPLACE_CONFIG_BUCKET"},
        ]
    )
    labels = {p["label"] for p in prereqs}
    assert "AWS Config IAM role" in labels
    assert "S3 delivery bucket" in labels
