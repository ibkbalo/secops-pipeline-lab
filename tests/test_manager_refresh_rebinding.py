# Manager Mode refresh / stale assurance rebinding — CLOUD-IAM-013 class of bugs.
# No auto-execution. Casebook remains untouched.

from __future__ import annotations

import json
from pathlib import Path

import manager_mode
from change_assurance.engine import (
    ANALYSIS_LOGIC_VERSION,
    assurance_bundle_stale_for_finding,
    load_or_assure,
)
from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import assess_finding_evidence
from predeploy.impact_analysis import load_or_analyze
from predeploy.post_deployment_verification import verification_plan_for_finding


AA_TITLE = "IAM Access Analyzer enabled"
JOB_ID = "job_test_refresh_aa_013"
SIBLING_ID = "CLOUD-STO-001"


def _aa_discovery(*, analyzers=None):
    analyzers = analyzers if analyzers is not None else []
    observed = {
        "analyzers": analyzers,
        "analyzer_count": len(analyzers),
        "active_account_analyzer_count": 0,
        "region": "us-east-1",
        "human_observed": "No Access Analyzer found in us-east-1",
    }
    evidence = [
        {
            "api_call": "iam.get_account_summary",
            "observed_value": {"Users": 2, "AccountMFAEnabled": 1},
            "quality": "INDIRECT",
            "purpose": "account context",
        },
        {
            "api_call": "accessanalyzer.list_analyzers",
            "observed_value": observed,
            "expected_value": {"type": "ACCOUNT", "status": "ACTIVE"},
            "quality": "DIRECT",
            "purpose": "proof",
            "region": "us-east-1",
        },
    ]
    assessment = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    return {
        "kind": "iam",
        "status": "OK",
        "summary": {"finding_status": assessment.get("finding_status"), "active_account_analyzer_count": 0},
        "evidence": assessment.get("labeled_evidence") or evidence,
        "evidence_assessment": assessment,
        "scope": "regional",
        "region": "us-east-1",
        "flags_hint": {"access_analyzer_enable": True},
        "potentially_affected_workloads": "Monitoring/analyzer resource only",
    }


def _stale_indirect_only():
    evidence = [
        {
            "api_call": "iam.get_account_summary",
            "observed_value": {"Users": 2, "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
            "quality": "INDIRECT",
            "purpose": "account context",
        },
        {
            "api_call": "iam.get_account_password_policy",
            "observed_value": {"MinimumPasswordLength": 14},
            "quality": "DIRECT",
            "purpose": "proof",
        },
    ]
    assessment = assess_finding_evidence(
        finding_id="CLOUD-IAM-013",
        title=AA_TITLE,
        evidence=evidence,
        specs=cloud_specs(),
    )
    # Force the stale shape Face was showing (no AA contract match / insufficient)
    assessment = dict(assessment)
    assessment["finding_status"] = "UNVERIFIED"
    assessment["evidence_quality"] = "INSUFFICIENT"
    assessment["control_key"] = None
    assessment["evidence_source"] = None
    assessment["manager_summary"] = {
        "headline": "EVIDENCE INSUFFICIENT",
        "message": "The current evidence does not directly prove this security finding.",
        "result": "UNVERIFIED",
    }
    return {
        "kind": "iam",
        "status": "OK",
        "summary": {"finding_status": "UNVERIFIED"},
        "evidence": evidence,
        "evidence_assessment": assessment,
        "scope": "account-wide",
        "flags_hint": {"iam_change": True},
    }


def _kit_with_tf(tmp_path: Path) -> Path:
    kit = tmp_path / "kit_aa"
    (kit / "terraform").mkdir(parents=True)
    (kit / "configs").mkdir(parents=True)
    (kit / "runbooks").mkdir(parents=True)
    (kit / "terraform" / "CLOUD-IAM-013.tf").write_text(
        'resource "aws_accessanalyzer_analyzer" "sentinel" {\n  type = "ACCOUNT"\n}\n',
        encoding="utf-8",
    )
    (kit / "configs" / "CLOUD-IAM-013.conf").write_text(
        "# LEGACY — prefer terraform/CLOUD-IAM-013.tf\n",
        encoding="utf-8",
    )
    (kit / "runbooks" / "CLOUD-IAM-013.yml").write_text("# CLOUD-IAM-013\n", encoding="utf-8")
    return kit


def _job(tmp_path: Path, kit: Path | None = None) -> tuple[dict, list[dict]]:
    job = {
        "job_id": JOB_ID,
        "role": "cloud",
        "kit_path": str(kit) if kit else None,
        "status": "pending_approval",
        "auto_apply": False,
    }
    findings = [
        {
            "id": "CLOUD-IAM-013",
            "title": AA_TITLE,
            "severity": "high",
            "description": "Access Analyzer off",
            "resource": {"region": "us-east-1"},
        },
        {
            "id": SIBLING_ID,
            "title": "S3 account-level Block Public Access enabled",
            "severity": "high",
            "description": "sibling",
        },
    ]
    return job, findings


def _patch_discover(monkeypatch, payload):
    import predeploy.aws_dependency_discovery as disc

    monkeypatch.setattr(disc, "discover_for_findings", lambda *a, **k: payload)


def test_01_stale_indirect_refresh_becomes_direct(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    assure = tmp_path / "assurance"
    assure.mkdir(parents=True)
    stale = {
        "type": "change_assurance_report",
        "job_id": JOB_ID,
        "role": "cloud",
        "domain": "cloud_security",
        "finding_status": "UNVERIFIED",
        "primary_finding_id": "CLOUD-IAM-013",
        "analysis_logic_version": "ancient",
        "evidence": _stale_indirect_only()["evidence"],
        "evidence_assessment": _stale_indirect_only()["evidence_assessment"],
        "relevant_artifacts": ["configs/CLOUD-IAM-013.conf"],
        "verification": {
            "steps": ["Re-run the originating Hands pack live", "Confirm CLOUD-IAM-013 no longer appears as failed"]
        },
        "artifact_scope": {"paths": ["configs/CLOUD-IAM-013.conf"], "mapping": "filename"},
        "legacy_impact": {"role": "cloud", "artifact_scope": {"paths": ["configs/CLOUD-IAM-013.conf"]}},
    }
    (assure / f"{JOB_ID}.json").write_text(json.dumps(stale), encoding="utf-8")
    assert assurance_bundle_stale_for_finding(
        stale, findings[0], kit_path=str(kit), focus_finding_id="CLOUD-IAM-013"
    )

    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    ca = legacy.get("change_assurance") or {}
    assert isinstance(ca, dict)
    assert ca.get("finding_status") == "CONFIRMED"
    assert (ca.get("evidence_assessment") or {}).get("evidence_quality") == "DIRECT"
    src = str((ca.get("evidence_assessment") or {}).get("evidence_source") or "")
    assert "list_analyzers" in src


def test_02_unverified_to_confirmed_and_tf_artifact(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    assert legacy.get("finding_status") == "CONFIRMED"
    arts = legacy.get("relevant_artifacts") or (legacy.get("change_assurance") or {}).get("relevant_artifacts") or []
    joined = " ".join(str(a) for a in arts)
    assert "terraform/CLOUD-IAM-013.tf" in joined
    assert "configs/CLOUD-IAM-013.conf" not in joined or "terraform/CLOUD-IAM-013.tf" in joined


def test_03_verification_and_manager_explanation(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    steps = " ".join(str(s) for s in ((legacy.get("verification") or {}).get("steps") or [])).lower()
    assert "list_analyzers" in steps
    assert "active" in steps
    card = manager_mode.build_manager_card(findings[0], job, legacy, is_primary=True)
    assert "Access Analyzer" in card["what_change"]
    assert "monitoring" in (card["affect"].get("summary_line") or card["affect"].get("potential_issue") or "").lower()
    learn = " ".join(str(v) for v in (card.get("learning") or {}).values()).lower()
    assert "access analyzer" in learn
    assert "break-glass" not in learn


def test_04_refresh_idempotent_no_duplicate_evidence(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    _patch_discover(monkeypatch, _aa_discovery())
    a = load_or_analyze(tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013")
    b = load_or_analyze(tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013")
    assert a.get("finding_status") == b.get("finding_status") == "CONFIRMED"
    ev = (b.get("change_assurance") or {}).get("evidence") or b.get("evidence") or []
    aa_rows = [e for e in ev if "list_analyzers" in str(e.get("api_call") or e.get("source") or "")]
    assert len(aa_rows) == 1


def test_05_no_mixed_old_new_artifacts(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    arts = [
        str(x).replace("\\", "/")
        for x in (
            legacy.get("relevant_artifacts")
            or (legacy.get("change_assurance") or {}).get("relevant_artifacts")
            or []
        )
    ]
    confs = [a for a in arts if a.endswith("CLOUD-IAM-013.conf")]
    tfs = [a for a in arts if a.endswith("CLOUD-IAM-013.tf")]
    assert tfs
    assert not confs


def test_06_sibling_finding_not_corrupted(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    assert legacy.get("primary_finding_id") == "CLOUD-IAM-013"
    # Sibling card must not inherit AA proof as if it were STO evidence
    card = manager_mode.build_manager_card(findings[1], job, legacy, is_primary=False)
    assert card["finding_id"] == SIBLING_ID
    assert card.get("evidence_proof") is None


def test_07_casebook_immutable_on_refresh(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    cases = tmp_path / "cases"
    cases.mkdir(parents=True)
    marker = cases / "CASE-KEEP.json"
    marker.write_text(json.dumps({"id": "CASE-KEEP", "immutable": True}), encoding="utf-8")
    before = marker.read_text(encoding="utf-8")
    _patch_discover(monkeypatch, _aa_discovery())
    load_or_analyze(tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013")
    assert marker.read_text(encoding="utf-8") == before
    # Snapshot of prior assurance may exist under assurance/snapshots — casebook untouched
    assert list(cases.glob("*")) == [marker]


def test_08_no_auto_execution_flag(tmp_path: Path, monkeypatch):
    kit = _kit_with_tf(tmp_path)
    job, findings = _job(tmp_path, kit)
    job["auto_apply"] = False
    _patch_discover(monkeypatch, _aa_discovery())
    legacy = load_or_analyze(
        tmp_path, job, findings, refresh=True, focus_finding_id="CLOUD-IAM-013"
    )
    assert legacy.get("auto_apply_forbidden") is True
    assert (legacy.get("change_assurance") or {}).get("execution_authorized") in (None, False)


def test_09_analysis_logic_version_stale_detection():
    finding = {"id": "CLOUD-IAM-013", "title": AA_TITLE}
    report = {
        "primary_finding_id": "CLOUD-IAM-013",
        "analysis_logic_version": "old",
        "evidence": [{"api_call": "accessanalyzer.list_analyzers", "quality": "DIRECT"}],
        "verification": verification_plan_for_finding("CLOUD-IAM-013", AA_TITLE),
    }
    assert assurance_bundle_stale_for_finding(report, finding, focus_finding_id="CLOUD-IAM-013")
    report["analysis_logic_version"] = ANALYSIS_LOGIC_VERSION
    assert assurance_bundle_stale_for_finding(report, finding, focus_finding_id="CLOUD-IAM-013") is None


def test_10_control_specific_verification_plan():
    plan = verification_plan_for_finding("CLOUD-IAM-013", AA_TITLE)
    joined = " ".join(plan.get("steps") or []).lower()
    assert "list_analyzers" in joined
    assert "account" in joined
