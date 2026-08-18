# tests/test_security_casebook.py
# Completed Security Jobs / Security Casebook

from __future__ import annotations

import json
from pathlib import Path

import security_casebook as cb


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _job(workspace: Path, job_id: str, scan_name: str, findings: list[dict], **extra) -> dict:
    scan_path = workspace / "scans" / scan_name
    _write(
        scan_path,
        {"findings": findings, "execution": {"mode": "live", "target": "aws-111122223333"}},
    )
    job = {
        "job_id": job_id,
        "role": "cloud",
        "title": "Cloud Security Engineer",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(scan_path),
        "kit_path": str(workspace / "kits" / "demo.zip"),
        "finding_decisions": {
            **{f["id"]: "approved" for f in findings[:5]},
            "CLOUD-IAM-013": "approved",
            "CLOUD-LOG-002": "approved",
            "CLOUD-LOG-003": "approved",
        },
        "execution_authorized": True,
        "execution_performed": False,
        "apply_status": "not_executed",
        "created_at": "2026-08-15T01:00:00Z",
        "decided_at": "2026-08-15T02:00:00Z",
        "summary": {"total_findings": len(findings)},
    }
    job.update(extra)
    _write(workspace / "jobs" / f"{job_id}.json", job)
    return job


BEFORE = [
    {"id": "CLOUD-IAM-001", "title": "AWS IAM password policy minimum length >= 14", "severity": "high",
     "description": "too short", "evidence": {"MinimumPasswordLength": 0, "engine": "iam"}},
    {"id": "CLOUD-IAM-002", "title": "AWS IAM password complexity (uppercase + symbols)", "severity": "high",
     "evidence": {"engine": "iam"}},
    {"id": "CLOUD-IAM-003", "title": "AWS IAM password complexity (lowercase + numbers)", "severity": "medium",
     "evidence": {"engine": "iam"}},
    {"id": "CLOUD-IAM-004", "title": "AWS IAM password max age <= 90 days", "severity": "medium",
     "evidence": {"engine": "iam"}},
    {"id": "CLOUD-IAM-005", "title": "AWS IAM password reuse prevention >= 24", "severity": "low",
     "evidence": {"engine": "iam"}},
    {"id": "CLOUD-STO-001", "title": "S3 public access", "severity": "high", "evidence": {"engine": "storage"}},
    {"id": "CLOUD-LOG-001", "title": "CloudTrail missing", "severity": "high", "evidence": {"engine": "logging"}},
    {"id": "CLOUD-NET-001", "title": "Default VPC", "severity": "medium", "evidence": {"engine": "network"}},
]


def _pad_to(n: int, base: list[dict]) -> list[dict]:
    out = list(base)
    i = 0
    while len(out) < n:
        i += 1
        out.append(
            {
                "id": f"CLOUD-PAD-{i:03d}",
                "title": f"Padding finding {i}",
                "severity": "medium" if i % 2 else "low",
                "evidence": {"engine": "iam"},
            }
        )
    return out[:n]


def test_01_severity_and_delta():
    before = _pad_to(19, BEFORE)
    # after removes IAM password controls only → 14
    after = [f for f in before if f["id"] not in set(cb.IAM_PASSWORD_CONTROLS)]
    assert len(before) == 19
    assert len(after) == 14
    delta = cb.compute_scan_delta(before, after)
    assert delta["cleared_count"] == 5
    assert delta["cleared_control_ids"] == list(cb.IAM_PASSWORD_CONTROLS)
    assert delta["before_severity"]["high"] >= 2


def test_02_create_immutable_case(tmp_path: Path):
    before = _pad_to(19, BEFORE)
    after = [f for f in before if f["id"] not in set(cb.IAM_PASSWORD_CONTROLS)]
    # reshape severities to match lab example counts roughly
    job = _job(tmp_path, "job_demo_before", "before.json", before)
    after_path = tmp_path / "scans" / "after.json"
    _write(after_path, {"findings": after})

    case = cb.create_case_from_job(
        tmp_path,
        "job_demo_before",
        after_scan_path=after_path,
        classification=cb.CLASSIFICATION_LAB,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0001",
    )
    assert case["case_id"] == "CASE-2026-0001"
    assert case["job_id"] == "job_demo_before"
    assert case["immutable"] is True
    assert case["classification"] == "LAB"
    assert case["status"] == cb.STATUS_SUCCESS
    assert case["verification_result"] == "PASSED"
    assert case["scan_delta"]["cleared_count"] == 5
    assert case["before"]["findings_total"] == 19
    assert case["after"]["findings_total"] == 14
    assert case["controls"] == list(cb.IAM_PASSWORD_CONTROLS)
    assert set(case["finding_decisions"]) == set(cb.IAM_PASSWORD_CONTROLS)
    assert "CLOUD-IAM-013" not in case["finding_decisions"]
    assert "CLOUD-LOG-002" not in case["finding_decisions"]
    assert case["remediation_artifact_type"] == cb.ARTIFACT_TERRAFORM
    assert case["execution_method"] == cb.EXEC_AWS_CONSOLE
    assert case["execution_performed_by_platform"] is False
    assert case["execution"]["execution_performed_by_platform"] is False
    assert "console" in case["execution"]["method"].lower()
    assert "terraform applied" not in case["portfolio_summary"].lower()
    assert (tmp_path / "cases" / "CASE-2026-0001" / "case.json").is_file()
    assert (tmp_path / "cases" / "CASE-2026-0001" / "README.md").is_file()
    assert (tmp_path / "cases" / "CASE-2026-0001" / "reports" / "internal.md").is_file()
    assert (tmp_path / "cases" / "CASE-2026-0001" / "reports" / "public.md").is_file()
    assert (tmp_path / "cases" / "CASE-2026-0001" / "reports" / "linkedin.txt").is_file()

    # Immutability: second create returns existing
    again = cb.create_case_from_job(
        tmp_path,
        "job_demo_before",
        after_scan_path=after_path,
        case_id="CASE-2026-0002",
    )
    assert again["case_id"] == "CASE-2026-0001"


def test_03_public_redaction():
    text = (
        "Account aws-952654481542 path C:\\DevSecOps-Lab\\secops-pipeline-lab\\kit.zip "
        "key AKIAIOSFODNN7EXAMPLE arn:aws:iam::952654481542:role/Admin ip 10.0.0.5"
    )
    red = cb.redact_text(text)
    assert "952654481542" not in red
    assert "AKIA" not in red
    assert "10.0.0.5" not in red
    assert "C:\\DevSecOps-Lab" not in red
    assert "[AWS ACCOUNT REDACTED]" in red
    assert "[ACCESS KEY REDACTED]" in red or "[ARN REDACTED]" in red


def test_04_no_success_without_clears(tmp_path: Path):
    findings = _pad_to(5, BEFORE[:5])
    _job(tmp_path, "job_same", "same.json", findings)
    scan = tmp_path / "scans" / "same.json"
    case = cb.create_case_from_job(
        tmp_path,
        "job_same",
        after_scan_path=scan,
        intended_control_ids=["CLOUD-IAM-001"],
        case_id="CASE-2026-0009",
    )
    assert case["status"] == cb.STATUS_FAILED
    assert case["verification_result"] == "FAILED"
    assert case["scan_delta"]["cleared_count"] == 0


def test_05_reports_and_linkedin_lab_label(tmp_path: Path):
    before = BEFORE[:5] + [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    after = [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    _job(tmp_path, "job_li", "b.json", before)
    ap = tmp_path / "scans" / "a.json"
    _write(ap, {"findings": after})
    case = cb.create_case_from_job(
        tmp_path,
        "job_li",
        after_scan_path=ap,
        classification=cb.CLASSIFICATION_LAB,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0010",
    )
    public = cb.render_public_report(case)
    assert "LAB" in public
    assert "customer employment" in public.lower() or "not present lab" in public.lower() or "Do not present" in public
    assert "security lab" in case["linkedin_draft"].lower()
    assert "not published" in case["linkedin_draft"].lower()
    assert "terraform applied" not in case["portfolio_summary"].lower()
    assert "Terraform" in case["portfolio_summary"]
    assert "AWS IAM" in case["portfolio_summary"] or "IAM" in case["interview"]["paragraph"]
    interview = case["interview"]["paragraph"]
    assert "lab" in interview.lower() or "findings" in interview.lower()
    assert "terraform applied" not in interview.lower()
    readme = cb.render_readme(case)
    assert "CASE-2026-0010" in readme
    assert "Execution method" in readme
    assert "AWS_CONSOLE" in readme
    pdf = cb.render_md_to_pdf_bytes(public, "PUBLIC TEST")
    assert pdf[:4] == b"%PDF"


def test_06_filter_cases():
    cases = [
        {
            "case_id": "CASE-2026-0001",
            "agent": "Cloud Security Engineer",
            "role": "cloud",
            "domain": "Cloud",
            "status": "SUCCESS",
            "date": "2026-08-15",
            "controls": ["CLOUD-IAM-001"],
            "before": {"severity": {"high": 2}},
            "scan_delta": {"cleared": [{"severity": "high"}]},
            "title": "IAM",
            "job_id": "j1",
        }
    ]
    assert len(cb.filter_cases(cases, control_id="CLOUD-IAM-001")) == 1
    assert len(cb.filter_cases(cases, status="FAILED")) == 0
    assert len(cb.filter_cases(cases, agent="cloud")) == 1


def test_07_scope_excludes_unrelated_job_approvals():
    scoped = cb.scope_finding_decisions(
        {
            "CLOUD-IAM-001": "approved",
            "CLOUD-IAM-002": "approved",
            "CLOUD-IAM-013": "approved",
            "CLOUD-LOG-002": "approved",
            "CLOUD-LOG-003": "approved",
        },
        list(cb.IAM_PASSWORD_CONTROLS),
        cleared_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
    )
    assert set(scoped) == set(cb.IAM_PASSWORD_CONTROLS)
    assert "CLOUD-IAM-013" not in scoped
    assert "CLOUD-LOG-002" not in scoped


def test_08_terraform_review_console_apply_separated(tmp_path: Path):
    before = BEFORE[:5] + [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    after = [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    _job(tmp_path, "job_console", "bc.json", before)
    ap = tmp_path / "scans" / "ac.json"
    _write(ap, {"findings": after})
    case = cb.create_case_from_job(
        tmp_path,
        "job_console",
        after_scan_path=ap,
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0020",
    )
    assert case["remediation_artifact_type"] == "TERRAFORM"
    assert case["execution_method"] == "AWS_CONSOLE"
    assert case["execution_performed_by_platform"] is False
    assert "reviewed and approved" in case["execution"]["method"].lower()
    assert "console" in case["execution"]["method"].lower()
    assert "terraform applied" not in case["portfolio_summary"].lower()
    assert cb.CLOUD_TERRAFORM_FIRST_POLICY["auto_apply"] is False


def test_09_future_terraform_execution_wording(tmp_path: Path):
    before = BEFORE[:5] + [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    after = [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    _job(tmp_path, "job_tf", "bt.json", before)
    ap = tmp_path / "scans" / "at.json"
    _write(ap, {"findings": after})
    case = cb.create_case_from_job(
        tmp_path,
        "job_tf",
        after_scan_path=ap,
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_TERRAFORM,
        case_id="CASE-2026-0021",
    )
    assert case["execution_method"] == "TERRAFORM"
    assert case["execution_performed_by_platform"] is False
    assert "human-triggered terraform apply" in case["execution"]["method"].lower()
    assert "auto-apply" in case["portfolio_summary"].lower() or "did not auto-apply" in case["portfolio_summary"].lower()
    readme = cb.render_readme(case)
    assert "TERRAFORM" in readme
    assert "Executed by platform:** No" in readme or "Executed by platform: No" in readme.replace("**", "")


def test_10_no_platform_auto_execution_flag(tmp_path: Path):
    before = BEFORE[:2] + [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    after = [{"id": "X", "title": "other", "severity": "low", "evidence": {"engine": "x"}}]
    _job(tmp_path, "job_auto", "ba.json", before, execution_performed=True)
    ap = tmp_path / "scans" / "aa.json"
    _write(ap, {"findings": after})
    case = cb.create_case_from_job(
        tmp_path,
        "job_auto",
        after_scan_path=ap,
        intended_control_ids=["CLOUD-IAM-001", "CLOUD-IAM-002"],
        execution_method=cb.EXEC_TERRAFORM,
        case_id="CASE-2026-0022",
    )
    # Casebook must never record platform auto-execution as true.
    assert case["execution_performed_by_platform"] is False
    assert case["execution"]["performed"] is False
    assert cb.CLOUD_TERRAFORM_FIRST_POLICY["auto_apply"] is False
