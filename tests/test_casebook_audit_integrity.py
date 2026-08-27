# Casebook audit integrity — attribution required for SUCCESS remediations.

from __future__ import annotations

import json
from pathlib import Path

import security_casebook as cb


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _scan(path: Path, findings: list[dict]) -> None:
    _write(
        path,
        {
            "findings": findings,
            "execution": {"mode": "live", "target": "aws-111122223333", "status": "ok"},
            "metadata": {"aws_profile": "sentinel-demo", "aws_region": "us-east-1"},
        },
    )


def _base_findings() -> list[dict]:
    return [
        {
            "id": "CTRL-A",
            "title": "Generic Control A Enablement",
            "severity": "high",
            "evidence": {"engine": "generic"},
        },
        {
            "id": "CTRL-B",
            "title": "Generic Control B Hardening",
            "severity": "high",
            "evidence": {"engine": "generic"},
        },
        {
            "id": "CTRL-C",
            "title": "Unrelated drift",
            "severity": "medium",
            "evidence": {"engine": "generic"},
        },
        {
            "id": "CTRL-D",
            "title": "Noise finding",
            "severity": "low",
            "evidence": {"engine": "generic"},
        },
    ]


def _job_with(
    workspace: Path,
    job_id: str,
    findings: list[dict],
    *,
    decisions: dict | None = None,
    finding_execution: dict | None = None,
    with_tf_for: list[str] | None = None,
) -> dict:
    before = workspace / "scans" / f"{job_id}_before.json"
    _scan(before, findings)
    job = {
        "job_id": job_id,
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before),
        "kit_path": str(workspace / "kits" / "demo"),
        "finding_decisions": decisions
        or {f["id"]: "approved" for f in findings},
        "execution_authorized": True,
        "execution_performed": False,
        "created_at": "2026-08-20T00:00:00Z",
        "decided_at": "2026-08-21T00:00:00Z",
    }
    if finding_execution is not None:
        job["finding_execution"] = finding_execution
    _write(workspace / "jobs" / f"{job_id}.json", job)
    if with_tf_for:
        tf = workspace / "drafts" / job_id / "kit_extract" / "terraform"
        tf.mkdir(parents=True)
        for cid in with_tf_for:
            (tf / f"{cid}.tf").write_text(f'resource "null_resource" "{cid.lower().replace("-", "_")}" {{}}\n', encoding="utf-8")
        _write(
            workspace / "approvals" / f"{job_id}.json",
            {
                "finding_id": with_tf_for[0],
                "terraform_plan_hash": "deadbeef",
                "manager_decision": "approved",
                "finding_decisions": {c: "approved" for c in with_tf_for},
            },
        )
    return job


def test_01_disappear_without_execution_no_success_case(tmp_path: Path):
    findings = _base_findings()
    job = _job_with(
        tmp_path,
        "job_no_exec",
        findings,
        decisions={"CTRL-A": "approved"},
        with_tf_for=["CTRL-A"],
    )
    after = [f for f in findings if f["id"] != "CTRL-A"]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    assert case is None
    assert cb.list_successful_cases(tmp_path) == []


def test_02_disappear_after_unrelated_remediation_no_false_case(tmp_path: Path):
    findings = _base_findings()
    # Execution exists only for CTRL-A; CTRL-B disappears without lifecycle.
    job = _job_with(
        tmp_path,
        "job_unrelated",
        findings,
        decisions={"CTRL-A": "approved", "CTRL-B": "approved"},
        finding_execution={
            "CTRL-A": {
                "status": "COMPLETED",
                "succeeded_resources": ["null_resource.ctrl_a"],
            }
        },
        with_tf_for=["CTRL-A", "CTRL-B"],
    )
    after = [f for f in findings if f["id"] not in {"CTRL-A", "CTRL-B"}]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    assert case is not None
    assert case["controls"] == ["CTRL-A"]
    assert case["status"] == cb.STATUS_SUCCESS
    # No SUCCESS case for CTRL-B
    keys = (cb.load_index(tmp_path).get("by_remediation_key") or {})
    assert not any("CTRL-B" in k for k in keys)


def test_03_clear_after_attributed_execution_creates_case(tmp_path: Path):
    findings = _base_findings()
    job = _job_with(
        tmp_path,
        "job_ok",
        findings,
        decisions={"CTRL-A": "approved"},
        finding_execution={
            "CTRL-A": {
                "status": "COMPLETED",
                "succeeded_resources": ["null_resource.ctrl_a"],
            }
        },
        with_tf_for=["CTRL-A"],
    )
    after = [f for f in findings if f["id"] != "CTRL-A"]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    assert case is not None
    assert case["status"] == cb.STATUS_SUCCESS
    assert case["controls"] == ["CTRL-A"]
    assert "Remediation" not in case["title"] or "CTRL-A Remediation" != case["title"]
    assert case["title"] == "Generic Control A Enablement"


def test_04_multiple_disappear_only_attributed_case(tmp_path: Path):
    findings = _base_findings()
    job = _job_with(
        tmp_path,
        "job_multi",
        findings,
        decisions={f["id"]: "approved" for f in findings},
        finding_execution={
            "CTRL-A": {
                "status": "PARTIAL_EXECUTION",
                "succeeded_resources": ["null_resource.ctrl_a"],
            }
        },
        with_tf_for=["CTRL-A", "CTRL-B", "CTRL-C"],
    )
    # A,B,C disappear; only A attributed
    after = [f for f in findings if f["id"] == "CTRL-D"]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    success = cb.list_successful_cases(tmp_path)
    assert len(success) == 1
    assert success[0]["controls"] == ["CTRL-A"]
    assert success[0]["scan_delta"]["before_total"] == 4
    assert success[0]["scan_delta"]["after_total"] == 1
    assert success[0]["findings_remediated"] == 1


def test_05_overall_scan_vs_attributed_remain_separate(tmp_path: Path):
    findings = _base_findings()
    job = _job_with(
        tmp_path,
        "job_attr",
        findings,
        decisions={"CTRL-A": "approved"},
        finding_execution={
            "CTRL-A": {
                "status": "COMPLETED",
                "succeeded_resources": ["null_resource.ctrl_a"],
            }
        },
        with_tf_for=["CTRL-A"],
    )
    after = [f for f in findings if f["id"] != "CTRL-A"]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    ba = case["before_after_summary"]
    assert any("OVERALL ACCOUNT SCAN" in line for line in ba["before_lines"])
    assert any("ATTRIBUTED TO THIS CASE" in line for line in ba["after_lines"])
    assert "CTRL-A" in ba["attribution_line"]
    interview = case["interview"]["result"]
    assert "overall account scan changed from 4 to 3" in interview.lower()
    assert "only CTRL-A is attributed" in interview


def test_06_canonical_human_readable_titles():
    assert cb.case_title_for_controls(["CLOUD-LOG-002"]) == "AWS Config Recorder Enablement"
    assert cb.case_title_for_controls(["CLOUD-IAM-013"]) == "IAM Access Analyzer Enablement"
    title = cb.case_title_for_controls(
        ["CTRL-Z"],
        findings=[{"id": "CTRL-Z", "title": "Widget Encryption Default"}],
    )
    assert title == "Widget Encryption Default"
    assert "CTRL-Z Remediation" != title


def test_07_false_closure_invalidation_preserves_audit(tmp_path: Path):
    findings = _base_findings()
    job = _job_with(tmp_path, "job_false", findings, decisions={"CTRL-B": "approved"})
    after = [f for f in findings if f["id"] != "CTRL-B"]
    after_path = tmp_path / "scans" / "after.json"
    _scan(after_path, after)
    # Force-create a false SUCCESS the old way (explicit create without lifecycle)
    bad = cb.create_case_from_job(
        tmp_path,
        "job_false",
        after_scan_path=after_path,
        after_findings=after,
        title="CTRL-B Remediation",
        intended_control_ids=["CTRL-B"],
        execution_method=cb.EXEC_TERRAFORM,
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        case_id="CASE-2026-0099",
    )
    assert bad["status"] == cb.STATUS_SUCCESS
    out = cb.invalidate_false_closure_case(
        tmp_path,
        "CASE-2026-0099",
        reason="NO_ATTRIBUTABLE_REMEDIATION_LIFECYCLE",
        detail="Test invalidation",
    )
    assert out["status"] == cb.STATUS_FALSE_CLOSURE
    assert out["audit_invalidation"]["prior_claim"]["status"] == "SUCCESS"
    assert "Test invalidation" in out["audit_invalidation"]["detail"]
    assert cb.list_successful_cases(tmp_path) == []
    still = cb.load_case(tmp_path, "CASE-2026-0099")
    assert still["status"] == cb.STATUS_FALSE_CLOSURE
    # Must not recreate SUCCESS over invalidated record
    again = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    assert again is None or again.get("status") == cb.STATUS_FALSE_CLOSURE


def test_08_iam_password_case_unchanged(tmp_path: Path):
    before = [
        {"id": cid, "title": cid, "severity": "high", "evidence": {"engine": "iam"}}
        for cid in cb.IAM_PASSWORD_CONTROLS
    ] + [{"id": "OTHER", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    after = [f for f in before if f["id"] not in set(cb.IAM_PASSWORD_CONTROLS)]
    _job_with(tmp_path, "job_20260815T015357Z_0e17ac50", before)
    after_path = tmp_path / "scans" / "pwd_after.json"
    _scan(after_path, after)
    c1 = cb.create_case_from_job(
        tmp_path,
        "job_20260815T015357Z_0e17ac50",
        after_scan_path=after_path,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0001",
    )
    assert c1["status"] == cb.STATUS_SUCCESS
    assert c1["execution_method"] == cb.EXEC_AWS_CONSOLE
    assert c1["title"] == "AWS IAM Password Policy Hardening"
    report = cb.reconcile_casebook_audit_integrity(tmp_path)
    assert "CASE-2026-0001" in report["preserved"]
    c1b = cb.load_case(tmp_path, "CASE-2026-0001")
    assert c1b["status"] == cb.STATUS_SUCCESS
    assert c1b["execution_method"] == cb.EXEC_AWS_CONSOLE


def test_09_access_analyzer_case_unchanged(tmp_path: Path):
    findings = [
        {
            "id": "CLOUD-IAM-013",
            "title": "IAM Access Analyzer enabled",
            "severity": "high",
            "evidence": {"engine": "iam"},
        },
        {"id": "OTHER", "title": "other", "severity": "low", "evidence": {"engine": "x"}},
    ]
    job = _job_with(
        tmp_path,
        "job_aa",
        findings,
        decisions={"CLOUD-IAM-013": "approved"},
        finding_execution={
            "CLOUD-IAM-013": {
                "status": "COMPLETED",
                "succeeded_resources": ["aws_accessanalyzer_analyzer.sentinel"],
            }
        },
        with_tf_for=["CLOUD-IAM-013"],
    )
    after = [f for f in findings if f["id"] != "CLOUD-IAM-013"]
    after_path = tmp_path / "scans" / "aa_after.json"
    _scan(after_path, after)
    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    assert case["status"] == cb.STATUS_SUCCESS
    assert case["title"] == "IAM Access Analyzer Enablement"
    report = cb.reconcile_casebook_audit_integrity(tmp_path)
    assert case["case_id"] in report["preserved"] or case["case_id"] in report["repaired"]
    loaded = cb.load_case(tmp_path, case["case_id"])
    assert loaded["status"] == cb.STATUS_SUCCESS


def test_10_log002_style_attributed_case_stays_legitimate(tmp_path: Path):
    findings = [
        {
            "id": "CLOUD-LOG-002",
            "title": "AWS Config recorder enabled",
            "severity": "high",
            "evidence": {"engine": "config"},
        },
        {
            "id": "CLOUD-STO-007",
            "title": "EBS encryption by default enabled",
            "severity": "high",
            "evidence": {"engine": "storage"},
        },
    ]
    job = _job_with(
        tmp_path,
        "job_log",
        findings,
        decisions={"CLOUD-LOG-002": "approved", "CLOUD-STO-007": "approved"},
        finding_execution={
            "CLOUD-LOG-002": {
                "status": "RECOVERY_REQUIRED",
                "succeeded_resources": [
                    "aws_iam_service_linked_role.config",
                    "aws_s3_bucket.config",
                ],
                "recovery_plan_sha256": "ab0401",
            }
        },
        with_tf_for=["CLOUD-LOG-002"],
    )
    after = []  # both absent — only LOG-002 attributable
    after_path = tmp_path / "scans" / "log_after.json"
    _scan(after_path, after)
    cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_path)
    )
    success = cb.list_successful_cases(tmp_path)
    assert len(success) == 1
    assert success[0]["controls"] == ["CLOUD-LOG-002"]
    assert success[0]["title"] == "AWS Config Recorder Enablement"
    assert "ATTRIBUTED TO THIS CASE" in "\n".join(success[0]["before_after_summary"]["after_lines"])
