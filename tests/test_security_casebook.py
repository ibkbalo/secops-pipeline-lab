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


def _iam013_finding() -> dict:
    return {
        "id": "CLOUD-IAM-013",
        "title": "IAM Access Analyzer enabled",
        "severity": "high",
        "description": "No ACTIVE account-level analyzer",
        "evidence": {"engine": "iam", "quality": "direct", "status": "CONFIRMED"},
    }


def _cloud_findings_14() -> list[dict]:
    """14 findings / 6 HIGH including CLOUD-IAM-013 (lab shape)."""
    base = [
        _iam013_finding(),
        {"id": "CLOUD-STO-001", "title": "S3 public", "severity": "high", "evidence": {"engine": "storage"}},
        {"id": "CLOUD-LOG-001", "title": "CloudTrail", "severity": "high", "evidence": {"engine": "logging"}},
        {"id": "CLOUD-NET-001", "title": "SG open", "severity": "high", "evidence": {"engine": "network"}},
        {"id": "CLOUD-IAM-020", "title": "Other IAM", "severity": "high", "evidence": {"engine": "iam"}},
        {"id": "CLOUD-DFT-001", "title": "Default VPC", "severity": "high", "evidence": {"engine": "network"}},
        {"id": "CLOUD-LOG-002", "title": "Log mid", "severity": "medium", "evidence": {"engine": "logging"}},
        {"id": "CLOUD-LOG-003", "title": "Log mid2", "severity": "medium", "evidence": {"engine": "logging"}},
        {"id": "CLOUD-STO-004", "title": "Sto mid", "severity": "medium", "evidence": {"engine": "storage"}},
        {"id": "CLOUD-NET-002", "title": "Net mid", "severity": "medium", "evidence": {"engine": "network"}},
        {"id": "CLOUD-IAM-021", "title": "IAM mid", "severity": "medium", "evidence": {"engine": "iam"}},
        {"id": "CLOUD-DFT-002", "title": "Def mid", "severity": "medium", "evidence": {"engine": "network"}},
        {"id": "CLOUD-LOG-004", "title": "Log low", "severity": "low", "evidence": {"engine": "logging"}},
        {"id": "CLOUD-STO-005", "title": "Sto low", "severity": "low", "evidence": {"engine": "storage"}},
    ]
    assert len(base) == 14
    assert sum(1 for f in base if f["severity"] == "high") == 6
    return base


def _write_live_scan(path: Path, findings: list[dict], *, target="aws-111122223333", region="us-east-1", **extra):
    doc = {
        "findings": findings,
        "execution": {"mode": "live", "target": target, "status": "partial", "error": None},
        "metadata": {"aws_profile": "sentinel-demo", "aws_region": region},
    }
    doc.update(extra)
    _write(path, doc)


def test_11_per_finding_iam013_clear_creates_case(tmp_path: Path):
    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    assert len(after) == 13
    assert sum(1 for f in after if f["severity"] == "high") == 5

    before_scan = tmp_path / "scans" / "before14.json"
    after_scan = tmp_path / "scans" / "after13.json"
    _write_live_scan(before_scan, before)
    _write_live_scan(after_scan, after)

    job = {
        "job_id": "job_aa_before",
        "role": "cloud",
        "title": "Cloud Security Engineer",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "kit_path": str(tmp_path / "kits" / "demo.zip"),
        "finding_decisions": {"CLOUD-IAM-013": "approved", "CLOUD-LOG-002": "approved"},
        "execution_authorized": True,
        "execution_performed": False,
        "apply_status": "not_executed",
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
    }
    _write(tmp_path / "jobs" / "job_aa_before.json", job)
    # Human TF approval binding + draft terraform for CLOUD-IAM-013
    _write(
        tmp_path / "approvals" / "job_aa_before.json",
        {
            "finding_id": "CLOUD-IAM-013",
            "manager_decision": "approved",
            "terraform_plan_hash": "abc123",
            "execution_performed": False,
            "finding_decisions": {"CLOUD-IAM-013": "approved"},
        },
    )
    tf_dir = tmp_path / "drafts" / "job_aa_before" / "kit_extract" / "terraform"
    tf_dir.mkdir(parents=True)
    (tf_dir / "CLOUD-IAM-013.tf").write_text(
        'resource "aws_accessanalyzer_analyzer" "sentinel" {}\n', encoding="utf-8"
    )

    case = cb.maybe_create_case_on_clear(
        tmp_path,
        before_job=job,
        after_findings=after,
        after_scan_path=str(after_scan),
    )
    assert case is not None
    assert case["controls"] == ["CLOUD-IAM-013"]
    assert case["title"] == "IAM Access Analyzer Enablement"
    assert case["status"] == cb.STATUS_SUCCESS
    assert case["before"]["findings_total"] == 14
    assert case["after"]["findings_total"] == 13
    assert case["before"]["severity"]["high"] == 6
    assert case["after"]["severity"]["high"] == 5
    assert case["execution_method"] == cb.EXEC_TERRAFORM
    assert case["platform_execution"] is False
    assert case["execution_performed_by_platform"] is False
    assert case["human_triggered"] is True
    assert case["execution"]["human_triggered"] is True
    assert case["execution"]["platform_execution"] is False
    assert case["finding_decisions"].get("CLOUD-IAM-013") == "approved"
    assert "CLOUD-LOG-002" not in case["finding_decisions"]
    # Remaining unrelated findings do not block case creation
    assert case["after"]["findings_total"] == 13


def test_12_scanner_error_and_access_denied_not_success(tmp_path: Path):
    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    before_scan = tmp_path / "scans" / "b.json"
    _write_live_scan(before_scan, before)
    job = {
        "job_id": "job_err",
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "finding_decisions": {"CLOUD-IAM-013": "approved"},
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
    }
    _write(tmp_path / "jobs" / "job_err.json", job)

    err_scan = tmp_path / "scans" / "err.json"
    _write_live_scan(err_scan, after)
    # Inject execution error
    doc = json.loads(err_scan.read_text(encoding="utf-8"))
    doc["execution"]["error"] = "scanner crash"
    doc["execution"]["status"] = "failed"
    _write(err_scan, doc)
    assert (
        cb.maybe_create_case_on_clear(
            tmp_path, before_job=job, after_findings=after, after_scan_path=str(err_scan)
        )
        is None
    )
    assess = cb.assess_control_resolution(
        control_ids=["CLOUD-IAM-013"],
        before_findings=before,
        after_findings=after,
        before_scan=json.loads(before_scan.read_text(encoding="utf-8")),
        after_scan=doc,
    )
    assert assess["status"] == cb.STATUS_RESOLUTION_UNVERIFIED

    denied_after = list(after) + [
        {
            "id": "CLOUD-IAM-013",
            "title": "IAM Access Analyzer enabled",
            "severity": "high",
            "evidence": {"engine": "iam", "quality": "error", "error": "AccessDenied"},
        }
    ]
    # Still present with AccessDenied — not a clear; also assess unverified if forced absent+denied noise
    denied_scan = tmp_path / "scans" / "denied.json"
    _write_live_scan(denied_scan, denied_after)
    assert (
        cb.maybe_create_case_on_clear(
            tmp_path,
            before_job=job,
            after_findings=denied_after,
            after_scan_path=str(denied_scan),
        )
        is None
    )
    assess_denied = cb.assess_control_resolution(
        control_ids=["CLOUD-IAM-013"],
        before_findings=before,
        after_findings=[f for f in after],  # absent
        before_scan=json.loads(before_scan.read_text(encoding="utf-8")),
        after_scan={
            "findings": after
            + [
                {
                    "id": "DISC-ERR",
                    "title": "discovery",
                    "severity": "info",
                    "evidence": {"engine": "iam", "error": "AccessDenied"},
                }
            ],
            "execution": {"mode": "live", "target": "aws-111122223333", "status": "partial"},
            "metadata": {"aws_profile": "sentinel-demo", "aws_region": "us-east-1"},
        },
    )
    assert assess_denied["status"] == cb.STATUS_RESOLUTION_UNVERIFIED
    assert assess_denied["reason"] == "access_denied"


def test_13_wrong_account_or_region_does_not_close(tmp_path: Path):
    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    before_scan = tmp_path / "scans" / "b.json"
    after_scan = tmp_path / "scans" / "a.json"
    _write_live_scan(before_scan, before, target="aws-111122223333", region="us-east-1")
    _write_live_scan(after_scan, after, target="aws-999988887777", region="us-east-1")
    job = {
        "job_id": "job_wrong_acct",
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "finding_decisions": {"CLOUD-IAM-013": "approved"},
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
    }
    _write(tmp_path / "jobs" / "job_wrong_acct.json", job)
    assert (
        cb.maybe_create_case_on_clear(
            tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_scan)
        )
        is None
    )

    after_scan2 = tmp_path / "scans" / "a2.json"
    _write_live_scan(after_scan2, after, target="aws-111122223333", region="eu-west-1")
    job2 = dict(job)
    job2["job_id"] = "job_wrong_region"
    _write(tmp_path / "jobs" / "job_wrong_region.json", job2)
    job2["scan_report_path"] = str(before_scan)
    assert (
        cb.maybe_create_case_on_clear(
            tmp_path, before_job=job2, after_findings=after, after_scan_path=str(after_scan2)
        )
        is None
    )


def test_14_duplicate_and_completed_count_and_no_auto_exec(tmp_path: Path):
    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    before_scan = tmp_path / "scans" / "b.json"
    after_scan = tmp_path / "scans" / "a.json"
    _write_live_scan(before_scan, before)
    _write_live_scan(after_scan, after)
    job = {
        "job_id": "job_dup",
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "kit_path": str(tmp_path / "kit.zip"),
        "finding_decisions": {"CLOUD-IAM-013": "approved"},
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
    }
    _write(tmp_path / "jobs" / "job_dup.json", job)
    _write(
        tmp_path / "approvals" / "job_dup.json",
        {"finding_id": "CLOUD-IAM-013", "terraform_plan_hash": "x", "manager_decision": "approved"},
    )
    tf = tmp_path / "drafts" / "job_dup" / "kit_extract" / "terraform"
    tf.mkdir(parents=True)
    (tf / "CLOUD-IAM-013.tf").write_text("resource \"aws_accessanalyzer_analyzer\" \"sentinel\" {}", encoding="utf-8")

    # Seed immutable password case (CASE-0001 shape) so Completed Jobs can be 2 after AA.
    pwd_before = _pad_to(19, BEFORE)
    pwd_after = [f for f in pwd_before if f["id"] not in set(cb.IAM_PASSWORD_CONTROLS)]
    _job(tmp_path, "job_20260815T015357Z_0e17ac50", "pwd_before.json", pwd_before)
    pwd_after_path = tmp_path / "scans" / "pwd_after.json"
    _write_live_scan(pwd_after_path, pwd_after)
    c1 = cb.create_case_from_job(
        tmp_path,
        "job_20260815T015357Z_0e17ac50",
        after_scan_path=pwd_after_path,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0001",
    )
    c1_snapshot = json.loads((tmp_path / "cases" / "CASE-2026-0001" / "case.json").read_text(encoding="utf-8"))

    first = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_scan)
    )
    second = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_scan)
    )
    third = cb.reconcile_verified_remediations(
        tmp_path, after_findings=after, after_scan_path=str(after_scan), role="cloud"
    )
    assert first is not None
    assert second["case_id"] == first["case_id"]
    assert len([c for c in cb.list_cases(tmp_path) if "CLOUD-IAM-013" in (c.get("controls") or [])]) == 1
    assert len(cb.list_cases(tmp_path)) == 2
    c1_after = json.loads((tmp_path / "cases" / "CASE-2026-0001" / "case.json").read_text(encoding="utf-8"))
    assert c1_after["controls"] == c1_snapshot["controls"]
    assert c1_after["title"] == c1_snapshot["title"]
    assert c1_after["execution_method"] == c1_snapshot["execution_method"]
    assert first["execution_performed_by_platform"] is False
    assert cb.CLOUD_TERRAFORM_FIRST_POLICY["auto_apply"] is False
    assert all(c.get("execution_performed_by_platform") is False for c in third)

def _seed_aa_assurance(workspace: Path, job_id: str) -> None:
    by = workspace / "assurance" / "by_finding" / job_id
    by.mkdir(parents=True, exist_ok=True)
    _write(
        by / "CLOUD-IAM-013.json",
        {
            "primary_finding_id": "CLOUD-IAM-013",
            "finding_status": "CONFIRMED",
            "recommendation": "RECOMMEND_REVIEW",
            "validation_status": "PASS",
            "deployment_ready": False,
            "remediation_risk": {"level": "LOW", "reasons": ["Regional scope"]},
            "evidence_quality": "DIRECT",
            "relevant_placeholders": [],
            "sibling_placeholder_artifacts": [
                {"file": "configs/CLOUD-STO-008.conf", "token": "REPLACE_BUCKET_NAME"}
            ],
            "artifacts": ["terraform/CLOUD-IAM-013.tf"],
        },
    )
    # Stale job-level bundle (must NOT win for per-finding case)
    _write(
        workspace / "assurance" / f"{job_id}.json",
        {
            "primary_finding_id": "CLOUD-LOG-002",
            "finding_status": "ALREADY_REMEDIATED",
            "recommendation": "NO_ACTION_REQUIRED",
            "validation_status": "PASS",
            "deployment_ready": False,
            "remediation_risk": {"level": "LOW"},
        },
    )


def test_15_iam013_narrative_and_assurance_semantics(tmp_path: Path):
    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    before_scan = tmp_path / "scans" / "b.json"
    after_scan = tmp_path / "scans" / "a.json"
    _write_live_scan(before_scan, before)
    _write_live_scan(after_scan, after)
    job_id = "job_aa_sem"
    job = {
        "job_id": job_id,
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "finding_decisions": {"CLOUD-IAM-013": "approved"},
        "execution_authorized": True,
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
        "kit_path": str(tmp_path / "kit.zip"),
    }
    _write(tmp_path / "jobs" / f"{job_id}.json", job)
    _seed_aa_assurance(tmp_path, job_id)
    tf = tmp_path / "drafts" / job_id / "kit_extract" / "terraform"
    tf.mkdir(parents=True)
    (tf / "CLOUD-IAM-013.tf").write_text(
        'resource "aws_accessanalyzer_analyzer" "sentinel" { type = "ACCOUNT" }\n',
        encoding="utf-8",
    )
    _write(
        tmp_path / "approvals" / f"{job_id}.json",
        {"finding_id": "CLOUD-IAM-013", "terraform_plan_hash": "x", "manager_decision": "approved"},
    )

    case = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_scan)
    )
    assert case is not None
    why = (case.get("narrative") or {}).get("why_mattered") or ""
    assert "external-access" in why.lower() or "external access" in why.lower()
    assert "unused access" not in why.lower()
    assert "unused-access" not in why.lower()
    assert case["ai_recommendation"] == "REVIEW WITH MANAGER"
    assert case["change_risk"] == "LOW"
    ca = case["change_assurance_summary"]
    assert ca["recommendation"] == "RECOMMEND_REVIEW"
    assert ca["recommendation_label"] == "REVIEW WITH MANAGER"
    assert ca["change_risk"] == "LOW"
    assert ca["assurance_scope"] == "finding"
    assert ca["primary_finding_id"] == "CLOUD-IAM-013"
    assert ca["finding_status"] == "CONFIRMED"
    assert ca["deployment_ready"] is True
    assert ca["deployment_ready_scope"] == "finding"
    assert case["interview"]["risk_considered"] == "LOW"
    assert "NO_ACTION" not in case["interview"]["risk_considered"]
    assert cb.validate_case_semantics(case) == []

    import manager_explanations as mx

    meta_why = mx.casebook_why_it_mattered("CLOUD-IAM-013")
    assert meta_why
    assert "unused" not in meta_why.lower()
    assert mx.explanation_control_mismatch_reason("CLOUD-IAM-013", None, why) is None
    bad = "This enables unused-access analysis across the account"
    assert "CASE_NARRATIVE_CONTROL_MISMATCH" in (
        mx.explanation_control_mismatch_reason("CLOUD-IAM-013", None, bad) or ""
    )

    public = cb.render_public_report(case)
    assert "unused access" not in public.lower()
    linkedin = case.get("linkedin_draft") or ""
    portfolio = case.get("portfolio_summary") or ""
    assert "unused access" not in linkedin.lower()
    assert "unused access" not in portfolio.lower()


def test_16_field_type_and_readiness_guards():
    import pytest

    with pytest.raises(ValueError) as ei:
        cb.normalize_risk_level("NO_ACTION_REQUIRED")
    assert cb.CASE_FIELD_TYPE_MISMATCH in str(ei.value)

    with pytest.raises(ValueError) as ei2:
        cb.normalize_risk_level("RECOMMEND_REVIEW")
    assert cb.CASE_FIELD_TYPE_MISMATCH in str(ei2.value)

    code, label = cb.normalize_recommendation("RECOMMEND_REVIEW")
    assert code == "RECOMMEND_REVIEW"
    assert label == "REVIEW WITH MANAGER"

    ready = cb._finding_scoped_deployment_ready(
        {
            "validation_status": "PASS",
            "deployment_ready": False,
            "relevant_placeholders": [],
            "sibling_placeholder_artifacts": [{"file": "x.conf"}],
        },
        assurance_scope="finding",
    )
    assert ready["deployment_ready"] is True
    assert ready["deployment_ready_scope"] == "finding"
    assert ready["whole_job_deployment_ready"] is False


def test_17_case0001_execution_untouched_and_completed_count(tmp_path: Path):
    pwd_before = _pad_to(19, BEFORE)
    pwd_after = [f for f in pwd_before if f["id"] not in set(cb.IAM_PASSWORD_CONTROLS)]
    _job(tmp_path, "job_20260815T015357Z_0e17ac50", "pwd_before.json", pwd_before)
    pwd_after_path = tmp_path / "scans" / "pwd_after.json"
    _write_live_scan(pwd_after_path, pwd_after)
    c1 = cb.create_case_from_job(
        tmp_path,
        "job_20260815T015357Z_0e17ac50",
        after_scan_path=pwd_after_path,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(cb.IAM_PASSWORD_CONTROLS),
        remediation_artifact_type=cb.ARTIFACT_TERRAFORM,
        execution_method=cb.EXEC_AWS_CONSOLE,
        case_id="CASE-2026-0001",
    )
    assert c1["execution_method"] == cb.EXEC_AWS_CONSOLE

    before = _cloud_findings_14()
    after = [f for f in before if f["id"] != "CLOUD-IAM-013"]
    before_scan = tmp_path / "scans" / "b2.json"
    after_scan = tmp_path / "scans" / "a2.json"
    _write_live_scan(before_scan, before)
    _write_live_scan(after_scan, after)
    job_id = "job_aa_count"
    job = {
        "job_id": job_id,
        "role": "cloud",
        "status": "approved",
        "manager_decision": "approved",
        "scan_report_path": str(before_scan),
        "finding_decisions": {"CLOUD-IAM-013": "approved"},
        "created_at": "2026-08-15T15:00:00Z",
        "decided_at": "2026-08-19T13:00:00Z",
        "kit_path": str(tmp_path / "kit.zip"),
    }
    _write(tmp_path / "jobs" / f"{job_id}.json", job)
    _seed_aa_assurance(tmp_path, job_id)
    tf = tmp_path / "drafts" / job_id / "kit_extract" / "terraform"
    tf.mkdir(parents=True)
    (tf / "CLOUD-IAM-013.tf").write_text(
        'resource "aws_accessanalyzer_analyzer" "sentinel" {}', encoding="utf-8"
    )
    _write(
        tmp_path / "approvals" / f"{job_id}.json",
        {"finding_id": "CLOUD-IAM-013", "terraform_plan_hash": "x"},
    )

    c2 = cb.maybe_create_case_on_clear(
        tmp_path, before_job=job, after_findings=after, after_scan_path=str(after_scan)
    )
    assert c2["status"] == cb.STATUS_SUCCESS
    assert c2["verification_result"] == "PASSED"
    assert len(cb.list_cases(tmp_path)) == 2
    c1b = cb.load_case(tmp_path, "CASE-2026-0001")
    assert c1b["execution_method"] == cb.EXEC_AWS_CONSOLE
    assert cb.CLOUD_TERRAFORM_FIRST_POLICY["auto_apply"] is False
