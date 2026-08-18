# Per-finding artifact placeholder scoping — Change Assurance regression tests.

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from change_assurance.recommendations import recommend
from predeploy import terraform_plan_analysis as tfplan


PASSWORD_TF = """\
resource "aws_iam_account_password_policy" "sentinel_hardened" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}
"""

DIRTY_LOG_TF = """\
resource "aws_config_configuration_recorder" "sentinel" {
  name     = "sentinel"
  role_arn = "arn:aws:iam::aws:role/REPLACE_CONFIG_ROLE"
}
"""

DIRTY_STO_TF = """\
resource "aws_s3_bucket_versioning" "example" {
  bucket = "REPLACE_BUCKET_NAME"
  versioning_configuration { status = "Enabled" }
}
"""


def _kit_with(tmp_path: Path, files: dict[str, str], manifest_items: list[dict] | None = None) -> Path:
    root = tmp_path / "kit"
    (root / "terraform").mkdir(parents=True)
    (root / "configs").mkdir(parents=True)
    (root / "runbooks").mkdir(parents=True)
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    items = manifest_items or []
    manifest = {
        "kit_name": "kit_test",
        "items": items,
        "dry_run": True,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return root


def test_01_clean_finding_a_not_rejected_by_finding_b_placeholder(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/CLOUD-LOG-003.tf": DIRTY_LOG_TF,
            "runbooks/CLOUD-IAM-001.yml": "title: password\n",
            "runbooks/CLOUD-LOG-003.yml": "title: config\n",
        },
        manifest_items=[
            {
                "check_id": "CLOUD-IAM-001",
                "status": "mapped",
                "files": [
                    "terraform/aws_iam_account_password_policy.tf",
                    "runbooks/CLOUD-IAM-001.yml",
                ],
            },
            {
                "check_id": "CLOUD-LOG-003",
                "status": "mapped",
                "files": ["terraform/CLOUD-LOG-003.tf", "runbooks/CLOUD-LOG-003.yml"],
            },
        ],
    )
    a = tfplan.analyze_kit_terraform(kit, ["CLOUD-IAM-001"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is False
    assert a["validate"]["status"] == "PASS"
    assert any("password_policy" in f for f in a["files"])
    assert not any("CLOUD-LOG-003" in f for f in a["files"])


def test_02_finding_b_with_placeholder_rejected(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/CLOUD-LOG-003.tf": DIRTY_LOG_TF,
        },
        manifest_items=[
            {"check_id": "CLOUD-LOG-003", "files": ["terraform/CLOUD-LOG-003.tf"]},
        ],
    )
    b = tfplan.analyze_kit_terraform(kit, ["CLOUD-LOG-003"], try_cli=False)
    assert b["flags"]["placeholder_unresolved"] is True
    assert b["validate"]["status"] == "FAIL"
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="FAIL",
        blast_level="MEDIUM",
        remediation_risk="MEDIUM",
        destructive=False,
        placeholders=True,
    )
    assert rec["recommendation"] == "RECOMMEND_REJECT"


def test_03_shared_artifact_with_placeholder_affects_group(tmp_path: Path):
    dirty_shared = PASSWORD_TF.replace("14", "REPLACE_MIN_LEN")
    kit = _kit_with(
        tmp_path,
        {"terraform/aws_iam_account_password_policy.tf": dirty_shared},
    )
    for fid in ("CLOUD-IAM-001", "CLOUD-IAM-002", "CLOUD-IAM-005"):
        analysis = tfplan.analyze_kit_terraform(kit, [fid], try_cli=False)
        assert analysis["flags"]["placeholder_unresolved"] is True, fid


def test_04_shared_clean_artifact_all_mapped_findings_pass_placeholder_gate(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/CLOUD-STO-007.tf": DIRTY_STO_TF,
        },
    )
    for fid in ("CLOUD-IAM-001", "CLOUD-IAM-002", "CLOUD-IAM-003", "CLOUD-IAM-004", "CLOUD-IAM-005"):
        analysis = tfplan.analyze_kit_terraform(kit, [fid], try_cli=False)
        assert analysis["flags"]["placeholder_unresolved"] is False, fid
        assert analysis["validate"]["status"] == "PASS", fid


def test_05_unrelated_config_placeholder_does_not_block_tf_finding(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "configs/CLOUD-NET-007.conf": 'vpc_id = "REPLACE_VPC_ID"\n',
            "configs/CLOUD-IAM-001.conf": "# password policy notes\n",
        },
        manifest_items=[
            {
                "check_id": "CLOUD-IAM-001",
                "files": [
                    "terraform/aws_iam_account_password_policy.tf",
                    "configs/CLOUD-IAM-001.conf",
                ],
            },
            {"check_id": "CLOUD-NET-007", "files": ["configs/CLOUD-NET-007.conf"]},
        ],
    )
    analysis = tfplan.analyze_kit_terraform(kit, ["CLOUD-IAM-001"], try_cli=False)
    assert analysis["flags"]["placeholder_unresolved"] is False
    assert analysis["validate"]["status"] == "PASS"


def test_06_unknown_artifact_mapping_review_not_fake_pass(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {"terraform/CLOUD-LOG-003.tf": DIRTY_LOG_TF},
    )
    analysis = tfplan.analyze_kit_terraform(kit, ["CLOUD-ZZZ-999"], try_cli=False)
    assert analysis["artifact_scope"]["uncertain"] is True
    assert analysis["validate"]["status"] == "VALIDATION_UNAVAILABLE"
    assert analysis["flags"]["placeholder_unresolved"] is False
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="VALIDATION_UNAVAILABLE",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
        artifact_mapping_uncertain=True,
    )
    assert rec["recommendation"] == "RECOMMEND_REVIEW"
    assert any("ARTIFACT_MAPPING_UNCERTAIN" in r for r in rec["reasons"])


def test_07_whole_job_not_fully_approvable_with_sibling_placeholders(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/CLOUD-LOG-003.tf": DIRTY_LOG_TF,
        },
        manifest_items=[
            {"check_id": "CLOUD-IAM-001", "files": ["terraform/aws_iam_account_password_policy.tf"]},
            {"check_id": "CLOUD-LOG-003", "files": ["terraform/CLOUD-LOG-003.tf"]},
        ],
    )
    iam = tfplan.analyze_kit_terraform(kit, ["CLOUD-IAM-001"], try_cli=False)
    assert iam["flags"]["placeholder_unresolved"] is False
    siblings = tfplan.scan_kit_placeholders(
        kit,
        exclude_paths=list(iam.get("artifact_scope", {}).get("paths") or iam.get("files") or []),
    )
    assert siblings
    # Finding-level may proceed; job-level must stay blocked
    assert recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )["recommendation"] in {"RECOMMEND_APPROVE", "RECOMMEND_REVIEW"}
    assert bool(siblings) is True  # whole-job has unresolved findings


def test_08_cloud_iam_001_to_005_shared_password_policy(tmp_path: Path):
    kit = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/AWS-016.tf": 'log_destination = "REPLACE_FLOW_LOGS"\n',
        },
    )
    for fid in ("CLOUD-IAM-001", "CLOUD-IAM-002", "CLOUD-IAM-003", "CLOUD-IAM-004", "CLOUD-IAM-005"):
        scope = tfplan.resolve_finding_kit_artifacts(kit, fid)
        assert any("aws_iam_account_password_policy.tf" in p for p in scope["tf_paths"]), fid
        analysis = tfplan.analyze_kit_terraform(kit, [fid], try_cli=False)
        assert analysis["flags"]["placeholder_unresolved"] is False, fid
        assert "AWS-016" not in " ".join(analysis["files"])


def test_09_existing_placeholder_detection_still_works():
    sources = {"a.tf": 'bucket = "REPLACE_CLOUDTRAIL_BUCKET"\n'}
    analysis = tfplan.analyze_terraform_sources(sources)
    assert analysis["flags"]["placeholder_unresolved"] is True
    assert analysis["placeholders"][0]["token"] == "REPLACE_CLOUDTRAIL_BUCKET"


def test_10_no_auto_execution_flags_in_recommend():
    rec = recommend(
        finding_status="CONFIRMED",
        validation_status="PASS",
        blast_level="LOW",
        remediation_risk="LOW",
        destructive=False,
        placeholders=False,
    )
    assert rec["manager_approval_required"] is True
    # recommend() never authorizes execution
    assert "execution_authorized" not in rec or rec.get("execution_authorized") is not True


def test_11_zip_kit_scoped_like_dir(tmp_path: Path):
    root = _kit_with(
        tmp_path,
        {
            "terraform/aws_iam_account_password_policy.tf": PASSWORD_TF,
            "terraform/CLOUD-LOG-003.tf": DIRTY_LOG_TF,
        },
        manifest_items=[
            {"check_id": "CLOUD-IAM-001", "files": ["terraform/aws_iam_account_password_policy.tf"]},
        ],
    )
    zpath = tmp_path / "kit.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for p in root.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(root)).replace("\\", "/"))
    analysis = tfplan.analyze_kit_terraform(zpath, ["CLOUD-IAM-001"], try_cli=False)
    assert analysis["flags"]["placeholder_unresolved"] is False
    assert analysis["validate"]["status"] == "PASS"
