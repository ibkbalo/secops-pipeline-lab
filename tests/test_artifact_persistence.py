# Artifact persistence / false-build-success guards — real filesystem tests.

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from change_assurance.artifact_persistence import (
    CONFIG_DEDICATED_SIGNATURES,
    ArtifactPersistenceError,
    read_kit_member,
    refuse_unresolved_overwrite,
    sha256_file,
    sha256_text,
    verify_persisted_member,
    write_and_verify,
    write_kit_member_atomic,
)
from change_assurance.domains.cloud.config_prerequisites import render_dedicated_terraform
from change_assurance.prerequisite_resolution import (
    CHOICE_CREATE_DEDICATED,
    apply_decision_and_regenerate,
)
from predeploy import terraform_plan_analysis as tfplan

LEGACY = '''# CLOUD-LOG-002 legacy
resource "aws_config_configuration_recorder" "sentinel" {
  role_arn = "arn:aws:iam::aws:role/REPLACE_CONFIG_ROLE"
}
resource "aws_config_delivery_channel" "sentinel" {
  s3_bucket_name = "REPLACE_CONFIG_BUCKET"
}
'''


def _job_ws(tmp_path: Path, tf_body: str = LEGACY) -> tuple[Path, Path, str]:
    ws = tmp_path / "ws"
    (ws / "jobs").mkdir(parents=True)
    kit_dir = tmp_path / "kit_scan_cloud_pack_test"
    (kit_dir / "terraform").mkdir(parents=True)
    (kit_dir / "runbooks").mkdir(parents=True)
    (kit_dir / "terraform" / "CLOUD-LOG-002.tf").write_text(tf_body, encoding="utf-8")
    (kit_dir / "runbooks" / "CLOUD-LOG-002.yml").write_text("title: old\n", encoding="utf-8")
    (kit_dir / "manifest.json").write_text(
        json.dumps({"items": [{"check_id": "CLOUD-LOG-002", "files": ["terraform/CLOUD-LOG-002.tf"]}]}),
        encoding="utf-8",
    )
    zip_path = kit_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for p in kit_dir.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(kit_dir).as_posix())
    job_id = "job_persist_test"
    job = {
        "job_id": job_id,
        "role": "cloud",
        "kit_path": str(zip_path),
        "scan_report_path": "",
    }
    (ws / "jobs" / f"{job_id}.json").write_text(json.dumps(job), encoding="utf-8")
    return ws, zip_path, job_id


def test_01_in_memory_dedicated_ok():
    tf = render_dedicated_terraform()
    assert "config.amazonaws.com" in tf
    assert "REPLACE_CONFIG_ROLE" not in tf


def test_02_written_to_disk(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    assert result["status"] == "resolved"
    assert result["persistence_verified"] is True
    abs_path = Path(result["artifact_path"])
    assert abs_path.is_file()
    disk = abs_path.read_text(encoding="utf-8")
    assert disk == read_kit_member(zip_path.with_suffix(""), "terraform/CLOUD-LOG-002.tf")


def test_03_to_06_persisted_signatures(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    body = Path(result["artifact_path"]).read_text(encoding="utf-8")
    assert "config.amazonaws.com" in body
    assert "aws_iam_service_linked_role" in body
    assert "aws_s3_bucket" in body and "sentinel-aws-config" in body
    assert "aws_config_configuration_recorder" in body
    assert "aws_config_delivery_channel" in body
    assert "aws_config_configuration_recorder_status" in body


def test_07_no_replace_on_disk(tmp_path: Path):
    ws, _, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    body = Path(result["artifact_path"]).read_text(encoding="utf-8")
    assert "REPLACE_" not in body
    assert "TODO" not in body
    assert "CHANGEME" not in body


def test_08_legacy_cannot_overwrite_resolved(tmp_path: Path):
    kit = tmp_path / "kit"
    (kit / "terraform").mkdir(parents=True)
    dedicated = render_dedicated_terraform()
    write_and_verify(
        kit,
        "terraform/CLOUD-LOG-002.tf",
        dedicated,
        required_signatures=CONFIG_DEDICATED_SIGNATURES,
        require_no_placeholders=True,
    )
    with pytest.raises(ArtifactPersistenceError) as ei:
        refuse_unresolved_overwrite(dedicated, LEGACY)
    assert ei.value.code == "ARTIFACT_PERSISTENCE_MISMATCH"
    with pytest.raises(ArtifactPersistenceError):
        write_and_verify(kit, "terraform/CLOUD-LOG-002.tf", LEGACY, protect_resolved=True)


def test_09_memory_vs_disk_mismatch(tmp_path: Path):
    kit = tmp_path / "kit"
    (kit / "terraform").mkdir(parents=True)
    (kit / "terraform" / "CLOUD-LOG-002.tf").write_text(LEGACY, encoding="utf-8")
    with pytest.raises(ArtifactPersistenceError) as ei:
        verify_persisted_member(
            kit,
            "terraform/CLOUD-LOG-002.tf",
            expected_body=render_dedicated_terraform(),
        )
    assert ei.value.code == "ARTIFACT_PERSISTENCE_MISMATCH"


def test_10_incomplete_dedicated_signatures(tmp_path: Path):
    kit = tmp_path / "kit"
    (kit / "terraform").mkdir(parents=True)
    (kit / "terraform" / "CLOUD-LOG-002.tf").write_text(
        'resource "aws_config_configuration_recorder" "sentinel" {}\n',
        encoding="utf-8",
    )
    with pytest.raises(ArtifactPersistenceError) as ei:
        verify_persisted_member(
            kit,
            "terraform/CLOUD-LOG-002.tf",
            required_signatures=CONFIG_DEDICATED_SIGNATURES,
            require_no_placeholders=True,
        )
    assert ei.value.code == "PREREQUISITE_RESOLUTION_ARTIFACT_INCOMPLETE"


def test_11_placeholder_readiness_uses_persisted(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    kit_dir = zip_path.with_suffix("")
    a = tfplan.analyze_kit_terraform(kit_dir, ["CLOUD-LOG-002"], try_cli=False)
    assert a["flags"]["placeholder_unresolved"] is False
    assert a["placeholders"] == []


def test_12_manifest_hash_matches(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    man = json.loads((zip_path.with_suffix("") / "manifest.json").read_text(encoding="utf-8"))
    item = next(i for i in man["items"] if i.get("check_id") == "CLOUD-LOG-002")
    assert item.get("artifact_sha256") == result["artifact_sha256"]
    assert item.get("persistence_verified") is True
    # Get-FileHash parity: hash raw on-disk bytes, not text-mode re-encode
    disk_hash = sha256_file(Path(result["artifact_path"]))
    assert disk_hash == result["artifact_sha256"]
    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_bytes = zf.read("terraform/CLOUD-LOG-002.tf")
    assert Path(result["artifact_path"]).read_bytes() == zip_bytes
    assert sha256_text(zip_bytes.decode("utf-8")) == result["artifact_sha256"]


def test_12b_dir_zip_byte_identical_after_write(tmp_path: Path):
    kit = tmp_path / "kit"
    (kit / "terraform").mkdir(parents=True)
    body = render_dedicated_terraform()
    meta = write_and_verify(
        kit,
        "terraform/CLOUD-LOG-002.tf",
        body,
        required_signatures=CONFIG_DEDICATED_SIGNATURES,
        require_no_placeholders=True,
    )
    # Force companion zip via second write through zip path after creating zip
    zip_path = kit.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("placeholder", b"x")
    meta2 = write_and_verify(
        kit,
        "terraform/CLOUD-LOG-002.tf",
        body,
        required_signatures=CONFIG_DEDICATED_SIGNATURES,
        require_no_placeholders=True,
    )
    dir_bytes = (kit / "terraform" / "CLOUD-LOG-002.tf").read_bytes()
    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_bytes = zf.read("terraform/CLOUD-LOG-002.tf")
    assert dir_bytes == zip_bytes
    assert sha256_file(kit / "terraform" / "CLOUD-LOG-002.tf") == meta2["sha256"]
    assert b"\r\n" not in dir_bytes
    assert meta["sha256"] == meta2["sha256"]


def test_13_manager_mode_binds_exact_kit(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws,
        job_id,
        "CLOUD-LOG-002",
        CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    job = json.loads((ws / "jobs" / f"{job_id}.json").read_text(encoding="utf-8"))
    assert Path(job["kit_path"]).resolve() == Path(result["kit_path"]).resolve()
    assert job["prerequisite_resolutions"]["CLOUD-LOG-002"]["artifact_sha256"] == result["artifact_sha256"]
    assert job["prerequisite_resolutions"]["CLOUD-LOG-002"]["persistence_verified"] is True


def test_14_idempotent_regen(tmp_path: Path):
    ws, _, job_id = _job_ws(tmp_path)
    r1 = apply_decision_and_regenerate(
        ws, job_id, "CLOUD-LOG-002", CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    r2 = apply_decision_and_regenerate(
        ws, job_id, "CLOUD-LOG-002", CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    assert r1["artifact_sha256"] == r2["artifact_sha256"]
    assert r2["status"] == "resolved"


def test_15_cloudtrail_untouched(tmp_path: Path):
    ws, _, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws, job_id, "CLOUD-LOG-002", CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    body = Path(result["artifact_path"]).read_text(encoding="utf-8")
    assert "aws-cloudtrail-logs" not in body
    assert "cloudtrail.amazonaws.com" not in body


def test_16_sibling_isolation(tmp_path: Path):
    ws, zip_path, job_id = _job_ws(tmp_path)
    kit_dir = zip_path.with_suffix("")
    (kit_dir / "terraform" / "CLOUD-STO-008.tf").write_text('bucket="REPLACE_OTHER"\n', encoding="utf-8")
    apply_decision_and_regenerate(
        ws, job_id, "CLOUD-LOG-002", CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    sibling = (kit_dir / "terraform" / "CLOUD-STO-008.tf").read_text(encoding="utf-8")
    assert "REPLACE_OTHER" in sibling
    log = (kit_dir / "terraform" / "CLOUD-LOG-002.tf").read_text(encoding="utf-8")
    assert "REPLACE_CONFIG_ROLE" not in log


def test_17_no_auto_execution(tmp_path: Path):
    ws, _, job_id = _job_ws(tmp_path)
    result = apply_decision_and_regenerate(
        ws, job_id, "CLOUD-LOG-002", CHOICE_CREATE_DEDICATED,
        findings=[{"id": "CLOUD-LOG-002", "title": "AWS Config recorder enabled"}],
    )
    assert result["execution_performed"] is False
    assert result["execution_ready"] is False
    assert result["auto_apply_forbidden"] is True
