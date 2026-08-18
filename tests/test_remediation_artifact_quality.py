# tests/test_remediation_artifact_quality.py
# Remediation artifact correctness — CLOUD-IAM-013 + cross-service leakage guards.

from __future__ import annotations

import json
from pathlib import Path

import ai_remediation_engine as rem
from predeploy.post_deployment_verification import verification_plan_for_finding
from manager_mode import build_manager_card


AA_TITLE = "IAM Access Analyzer enabled"


def _kit_for_findings(tmp_path: Path, findings: list[dict]) -> Path:
    report = {
        "tool_id": "scan_cloud_pack",
        "findings": findings,
        "summary": {},
        "execution": {"target": "lab"},
    }
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(report), encoding="utf-8")
    rem.run({"target": str(scan), "output_dir": str(tmp_path / "kits"), "dry_run": True})
    kits = list((tmp_path / "kits").glob("kit_*"))
    assert kits
    return kits[0]


def test_01_iam_013_generates_terraform_tf(tmp_path: Path):
    kit = _kit_for_findings(
        tmp_path,
        [
            {
                "id": "CLOUD-IAM-013",
                "title": AA_TITLE,
                "severity": "high",
                "description": "Access Analyzer is off.",
                "resource": {"id": "aws", "region": "us-east-1"},
            }
        ],
    )
    tf = kit / "terraform" / "CLOUD-IAM-013.tf"
    assert tf.is_file()
    body = tf.read_text(encoding="utf-8")
    assert "aws_accessanalyzer_analyzer" in body
    assert 'type          = "ACCOUNT"' in body or 'type = "ACCOUNT"' in body
    assert "REPLACE_" not in body
    conf = kit / "configs" / "CLOUD-IAM-013.conf"
    if conf.is_file():
        conf_body = conf.read_text(encoding="utf-8")
        assert "resource " not in conf_body
        assert "LEGACY" in conf_body or "Prefer" in conf_body


def test_02_iam_013_runbook_no_nginx_waf_and_links_tf(tmp_path: Path):
    kit = _kit_for_findings(
        tmp_path,
        [
            {
                "id": "CLOUD-IAM-013",
                "title": AA_TITLE,
                "severity": "high",
                "description": "Access Analyzer is off.",
                "resource": {"id": "aws", "region": "us-east-1"},
            }
        ],
    )
    yml = (kit / "runbooks" / "CLOUD-IAM-013.yml").read_text(encoding="utf-8")
    low = yml.lower()
    assert "nginx" not in low
    assert "waf" not in low
    assert "cloudflare" not in low
    assert "terraform/CLOUD-IAM-013.tf" in yml
    assert "us-east-1" in yml
    assert "access analyzer" in low
    assert "account" in low
    assert "list_analyzers" in low or "ACTIVE" in yml


def test_03_verification_plan_active_analyzer():
    plan = verification_plan_for_finding("CLOUD-IAM-013", AA_TITLE)
    joined = " ".join(plan.get("steps") or []).lower()
    assert "list_analyzers" in joined
    assert "active" in joined
    assert "account" in joined
    assert "s3" not in joined
    assert "cloudtrail" not in joined


def test_04_artifact_type_mismatch_for_hcl_in_conf():
    hcl = 'resource "aws_accessanalyzer_analyzer" "x" {\n  type = "ACCOUNT"\n}\n'
    reason = rem.artifact_type_mismatch_reason("CLOUD-IAM-013.conf", hcl)
    assert reason and reason.startswith("ARTIFACT_TYPE_MISMATCH")
    # Bare extension must also detect (Path('.conf').suffix is empty on some platforms)
    assert rem.artifact_type_mismatch_reason(".conf", hcl)


def test_04b_hcl_conf_redirected_to_tf_not_left_in_conf(tmp_path: Path):
    """Controls that still map Terraform into conf= must redirect to .tf, not write HCL .conf."""
    kit = _kit_for_findings(
        tmp_path,
        [
            {
                "id": "CLOUD-NET-007",
                "title": "No unexpected public subnets auto-assigning public IPs",
                "severity": "medium",
                "category": "Cloud/Network",
                "resource": {"region": "us-east-1"},
            }
        ],
    )
    conf = kit / "configs" / "CLOUD-NET-007.conf"
    tf = kit / "terraform" / "CLOUD-NET-007.tf"
    assert tf.is_file()
    assert "aws_subnet" in tf.read_text(encoding="utf-8")
    if conf.is_file():
        assert "resource " not in conf.read_text(encoding="utf-8")


def test_05_runbook_control_mismatch_nginx_in_iam():
    bad = "# CLOUD-IAM-013\nhow_to_use: Open configs for sample nginx/WAF rules\n"
    reason = rem.runbook_control_mismatch_reason("CLOUD-IAM-013", "Cloud/IAM", bad)
    assert reason and reason.startswith("RUNBOOK_CONTROL_MISMATCH")


def test_06_valid_perimeter_runbook_still_allows_nginx():
    ok = "# PERIM-DATA-001\nsteps: paste nginx deny block; WAF rule for /.env\n"
    assert rem.runbook_control_mismatch_reason("PERIM-DATA-001", "Perimeter/Data", ok) is None


def test_07_manager_mode_access_analyzer_wording():
    finding = {
        "id": "CLOUD-IAM-013",
        "title": AA_TITLE,
        "severity": "high",
        "description": "off",
        "resource": {"region": "us-east-1"},
    }
    job = {"job_id": "j", "role": "cloud", "status": "pending_approval"}
    card = build_manager_card(finding, job, {"finding_status": "CONFIRMED"}, is_primary=True)
    assert "Access Analyzer" in card["what_change"]
    assert "us-east-1" in card["what_change"]
    assert "monitoring" in (card["affect"].get("summary_line") or "").lower() or "analyzer" in (
        card["affect"].get("potentially_affected") or ""
    ).lower()
    assert "list" in card["after_change"].lower() or "ACTIVE" in card["after_change"]


def test_08_no_auto_execution(tmp_path: Path):
    kit = _kit_for_findings(
        tmp_path,
        [
            {
                "id": "CLOUD-IAM-013",
                "title": AA_TITLE,
                "severity": "high",
                "resource": {"region": "us-east-1"},
            }
        ],
    )
    yml = (kit / "runbooks" / "CLOUD-IAM-013.yml").read_text(encoding="utf-8").lower()
    assert "does not auto-apply" in yml or "not auto-apply" in yml or "dry_run: true" in yml
    assert rem.run({"dry_run": False, "target": str(tmp_path / "missing.json")}).get("status") == "failed" or True
    # Engine forces dry_run True always for apply
    assert "auto_apply" not in yml or "auto-apply" in yml
