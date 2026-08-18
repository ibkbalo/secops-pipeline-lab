# End-to-end evidence pipeline tests — same path Face uses (load_or_analyze).
# No auto-execution. Mocks live AWS discovery; exercises cache/refresh/persistence.

from __future__ import annotations

import json
from pathlib import Path

import manager_mode
from change_assurance.engine import assurance_cache_incomplete, load_or_assure
from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import assess_finding_evidence
from predeploy.impact_analysis import load_or_analyze


PASSWORD_TITLE = "AWS IAM password policy minimum length >= 14"
JOB_ID = "job_test_live_eq_pipeline"


def _password_discovery(*, min_len: int = 8, include_summary: bool = True, error: str | None = None):
    evidence = []
    if include_summary:
        evidence.append(
            {
                "api_call": "iam.get_account_summary",
                "observed_value": {"Users": 2, "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
                "quality": "INDIRECT",
                "purpose": "account context",
            }
        )
    if error:
        evidence.append(
            {
                "api_call": "iam.get_account_password_policy",
                "observed_value": {"error": error, "error_type": "ClientError", "code": "AccessDenied"},
                "quality": "ERROR",
                "purpose": "error",
            }
        )
    else:
        evidence.append(
            {
                "api_call": "iam.get_account_password_policy",
                "observed_value": {"MinimumPasswordLength": min_len},
                "quality": "DIRECT",
                "purpose": "proof",
            }
        )
    assessment = assess_finding_evidence(
        finding_id="CLOUD-IAM-001",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
        collection_error=error,
    )
    return {
        "kind": "iam",
        "status": "OK" if not error else "FAIL",
        "error": error,
        "summary": {
            "Users": 2,
            "MinimumPasswordLength": None if error else min_len,
            "finding_status": assessment.get("finding_status"),
        },
        "evidence": assessment.get("labeled_evidence") or evidence,
        "evidence_assessment": assessment,
        "scope": "account-wide",
        "potentially_affected_workloads": "MANAGER CONTEXT REQUIRED",
        "flags_hint": {"iam_change": True},
    }


def _patch_discover(monkeypatch, payload):
    import predeploy.aws_dependency_discovery as disc

    monkeypatch.setattr(disc, "discover_for_findings", lambda *a, **k: payload)


def _job_and_findings(tmp_path: Path):
    job = {"job_id": JOB_ID, "role": "cloud", "kit_path": None, "status": "pending_approval"}
    findings = [
        {
            "id": "CLOUD-IAM-001",
            "title": PASSWORD_TITLE,
            "severity": "high",
            "description": "Password minimum length below CIS floor.",
        }
    ]
    return job, findings


def test_01_live_style_discovery_includes_password_policy():
    disc = _password_discovery(min_len=8)
    sources = [e["api_call"] for e in disc["evidence"]]
    assert "iam.get_account_password_policy" in sources
    assert "iam.get_account_summary" in sources
    assert disc["evidence_assessment"]["evidence_quality"] == "DIRECT"
    assert disc["evidence_assessment"]["finding_status"] == "CONFIRMED"


def test_02_direct_evidence_survives_assurance_serialization(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    report = load_or_assure(tmp_path, job, findings, refresh=True)
    path = tmp_path / "assurance" / f"{JOB_ID}.json"
    assert path.is_file()
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored.get("evidence_assessment")
    assert stored["evidence_assessment"]["evidence_source"] == "iam.get_account_password_policy"
    sources = [e.get("source") or e.get("api_call") for e in stored.get("evidence") or []]
    assert any("password_policy" in str(s) for s in sources)
    assert any(e.get("quality") == "DIRECT" for e in stored.get("evidence") or [])
    for key in ("observed", "expected", "result", "evidence_source"):
        assert key in stored["evidence_assessment"]


def test_03_predeploy_wrapper_preserves_direct_evidence(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    legacy = load_or_analyze(tmp_path, job, findings, refresh=True)
    ca = legacy.get("change_assurance") or {}
    assert ca.get("evidence_assessment", {}).get("evidence_source") == "iam.get_account_password_policy"
    qualities = {e.get("source") or e.get("api_call"): e.get("quality") for e in (ca.get("evidence") or [])}
    assert any("password_policy" in str(k) and v == "DIRECT" for k, v in qualities.items())
    assert any("account_summary" in str(k) and v == "INDIRECT" for k, v in qualities.items())


def test_04_face_payload_contains_direct_evidence(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    impact = load_or_analyze(tmp_path, job, findings, refresh=True)
    view = manager_mode.build_manager_view(job, findings, impact)
    proof = view["primary"]["evidence_proof"]
    assert proof
    assert "password" in str(proof["evidence_source"]).lower()
    assert proof.get("evidence_source_raw") is None or "password_policy" in str(proof.get("evidence_source_raw") or proof["evidence_source"])
    assert proof["quality"] == "DIRECT"
    assert proof["result"] == "FAIL"
    assert "8" in str(proof["observed"])


def test_05_manager_mode_prefers_direct_over_indirect():
    job = {"job_id": "j", "role": "cloud", "status": "pending_approval"}
    finding = {"id": "CLOUD-IAM-001", "title": PASSWORD_TITLE, "severity": "high", "description": "x"}
    impact = {
        "finding_status": "CONFIRMED",
        "recommendation": "RECOMMEND_REVIEW",
        "primary_finding_id": "CLOUD-IAM-001",
        "change_assurance": {
            "evidence_assessment": {
                "finding_status": "CONFIRMED",
                "evidence_quality": "DIRECT",
                "observed": {"MinimumPasswordLength": 8},
                "expected": "14 or greater",
                "result": "FAIL",
                "evidence_source": "iam.get_account_password_policy",
                "human_label": "Minimum password length",
                "manager_summary": {
                    "headline": "EVIDENCE DIRECT",
                    "observed": {"MinimumPasswordLength": 8},
                    "expected": "14 or greater",
                    "result": "FAIL",
                    "evidence_source": "iam.get_account_password_policy",
                    "human_label": "Minimum password length",
                },
                "labeled_evidence": [
                    {"api_call": "iam.get_account_summary", "quality": "INDIRECT"},
                    {"api_call": "iam.get_account_password_policy", "quality": "DIRECT",
                     "observed_value": {"MinimumPasswordLength": 8}},
                ],
            },
            "evidence": [
                {"source": "iam.get_account_summary", "quality": "INDIRECT"},
                {"source": "iam.get_account_password_policy", "quality": "DIRECT"},
            ],
        },
    }
    card = manager_mode.build_manager_card(finding, job, impact, is_primary=True)
    src = str(card["evidence_proof"]["evidence_source"])
    raw = str(card["evidence_proof"].get("evidence_source_raw") or src)
    assert "password" in src.lower()
    assert "password_policy" in raw or "password policy" in src.lower()
    assert card["evidence_proof"]["direct_items"][0]["api_call"] == "iam.get_account_password_policy"


def test_06_explicit_refresh_replaces_stale_indirect_only(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    # Seed stale pre-EQ cache (summary only, CONFIRMED, no assessment)
    assure_dir = tmp_path / "assurance"
    assure_dir.mkdir(parents=True)
    stale = {
        "type": "change_assurance_report",
        "job_id": JOB_ID,
        "finding_status": "CONFIRMED",
        "primary_finding_id": "CLOUD-IAM-001",
        "evidence": [
            {
                "api_call": "iam.get_account_summary",
                "source": "iam.get_account_summary",
                "observed_value": {"Users": 2, "GroupPolicySizeQuota": 5120},
                "confidence": "HIGH",
            }
        ],
        "legacy_impact": {
            "finding_status": "CONFIRMED",
            "evidence": [
                {"api_call": "iam.get_account_summary", "observed_value": {"Users": 2}, "confidence": "HIGH"}
            ],
            "discovery": {"evidence": [{"api_call": "iam.get_account_summary", "observed_value": {"Users": 2}}]},
        },
    }
    (assure_dir / f"{JOB_ID}.json").write_text(json.dumps(stale), encoding="utf-8")
    assert assurance_cache_incomplete(stale) is True

    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    # Even without refresh flag, incomplete cache must re-collect
    legacy = load_or_analyze(tmp_path, job, findings, refresh=False)
    sources = [e.get("source") or e.get("api_call") for e in (legacy.get("change_assurance") or {}).get("evidence") or []]
    assert any("password_policy" in str(s) for s in sources)

    # Explicit refresh overwrites again
    _patch_discover(monkeypatch, _password_discovery(min_len=10))
    legacy2 = load_or_analyze(tmp_path, job, findings, refresh=True)
    obs = (legacy2.get("change_assurance") or {}).get("evidence_assessment", {}).get("observed") or {}
    assert obs.get("MinimumPasswordLength") == 10


def test_07_no_password_policy_configured_direct_fail():
    evidence = [
        {"api_call": "iam.get_account_summary", "observed_value": {"Users": 1}, "quality": "INDIRECT"},
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"PasswordPolicy": "NOT_CONFIGURED", "MinimumPasswordLength": 0},
            "quality": "DIRECT",
        },
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-001",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] == "CONFIRMED"
    assert result["evidence_quality"] == "DIRECT"
    assert result["result"] == "FAIL"


def test_08_access_denied_not_confirmed():
    evidence = [
        {"api_call": "iam.get_account_summary", "observed_value": {"Users": 2}, "quality": "INDIRECT"},
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"error": "AccessDenied", "code": "AccessDenied"},
            "quality": "ERROR",
        },
    ]
    result = assess_finding_evidence(
        finding_id="CLOUD-IAM-001",
        title=PASSWORD_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    assert result["finding_status"] in {"ERROR", "UNVERIFIED"}
    assert result["finding_status"] != "CONFIRMED"
    assert result["evidence_quality"] == "ERROR"


def test_09_account_summary_remains_indirect_context(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    legacy = load_or_analyze(tmp_path, job, findings, refresh=True)
    labeled = (legacy.get("change_assurance") or {}).get("evidence_assessment", {}).get("labeled_evidence") or []
    by_api = {e["api_call"]: e["quality"] for e in labeled}
    assert by_api.get("iam.get_account_summary") == "INDIRECT"
    assert by_api.get("iam.get_account_password_policy") == "DIRECT"


def test_10_other_mapped_controls_still_resolve():
    cases = [
        ("CLOUD-IAM-006", "AWS IAM root MFA enabled", "AccountMFAEnabled", "iam.get_account_summary", 0, "CONFIRMED"),
        (
            "CLOUD-STO-001",
            "S3 account public access block fully enabled",
            "BlockPublicAcls",
            "s3control.get_public_access_block",
            False,
            "CONFIRMED",
        ),
        ("CLOUD-LOG-001", "CloudTrail trail present", "trail_count", "cloudtrail.describe_trails", 0, "CONFIRMED"),
        ("CLOUD-NET-001", "Security group open to the world", "open_world_count", "ec2.describe_security_groups", 2, "CONFIRMED"),
    ]
    for fid, title, field, source, bad_val, expect_status in cases:
        observed = {field: bad_val}
        if field.startswith("Block"):
            observed = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        result = assess_finding_evidence(
            finding_id=fid,
            title=title,
            evidence=[{"api_call": source, "observed_value": observed}],
            specs=cloud_specs(),
        )
        assert result["spec_matched"] is True, title
        assert result["finding_status"] == expect_status, title
        assert result["evidence_quality"] == "DIRECT", title


def test_11_no_auto_execution_flags(tmp_path: Path, monkeypatch):
    job, findings = _job_and_findings(tmp_path)
    _patch_discover(monkeypatch, _password_discovery(min_len=8))
    report = load_or_assure(tmp_path, job, findings, refresh=True)
    assert report.get("auto_apply_forbidden") is True
    assert report.get("execution_authorized") is False
    assert report.get("execution_performed") is False
