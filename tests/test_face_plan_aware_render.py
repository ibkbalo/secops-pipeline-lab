# Integration: persisted reviewed plan → Face Manager Mode HTML must not fall back
# to legacy stubs (see change_assurance / none_detected).

from __future__ import annotations

import json
from pathlib import Path

import pytest

from change_assurance.engine import assure_job, load_or_assure
from change_assurance.plan_ingestion import normalize_terraform_plan, manager_affect_from_plan, risk_rationale_from_plan
from manager_mode import build_manager_view

FIXTURE = Path(__file__).parent / "fixtures" / "CLOUD-LOG-002-review.tfplan.json"
SRC_SHA = "da297d53055b31ca5d91d17b42dca58da79f8582e3b146d93e074b36964fe7fc"


@pytest.fixture
def plan_json():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_face_manager_html_uses_reviewed_plan_not_legacy_stubs(tmp_path, plan_json, monkeypatch):
    """
    Reproduce the live failure mode: job has reviewed_terraform_plans bound,
    but Manager Mode / rendered affect must not show see change_assurance or
    none_detected.
    """
    ws = tmp_path / "brain_workspace"
    (ws / "jobs").mkdir(parents=True)
    (ws / "assurance").mkdir(parents=True)
    kit = tmp_path / "kit_scan_cloud_pack_live"
    (kit / "terraform").mkdir(parents=True)
    tf = kit / "terraform" / "CLOUD-LOG-002.tf"
    tf.write_text(
        '# CLOUD-LOG-002\nresource "aws_config_configuration_recorder" "sentinel" {}\n',
        encoding="utf-8",
    )
    # Match expected SHA only for binding metadata; content can differ in unit scope
    job_id = "job_live_plan_render"
    job = {
        "job_id": job_id,
        "role": "cloud",
        "kit_path": str(kit),
        "region": "us-east-1",
        "aws_account_id": "000000000001",
        "reviewed_terraform_plans": {
            "CLOUD-LOG-002": {
                "finding_id": "CLOUD-LOG-002",
                "plan_json": plan_json,
                "source_artifact_path": str(tf),
                "source_artifact_sha256": SRC_SHA,
                "account_id": "000000000001",
                "region": "us-east-1",
            }
        },
        "prerequisite_resolutions": {
            "CLOUD-LOG-002": {
                "status": "PREREQUISITES_RESOLVED",
                "artifact_path": str(tf),
                "artifact_sha256": SRC_SHA,
                "persistence_verified": True,
            }
        },
    }
    (ws / "jobs" / f"{job_id}.json").write_text(json.dumps(job), encoding="utf-8")
    findings = [
        {
            "id": "CLOUD-LOG-002",
            "title": "AWS Config recorder enabled",
            "severity": "high",
            "resource": {"region": "us-east-1"},
        }
    ]

    # Avoid live AWS discovery in this integration path
    import change_assurance.domains.cloud.adapter as cloud_adapter

    def _fake_verify(self, finding, context):
        return {
            "finding_status": "OPEN",
            "still_present": True,
            "discovery": {
                "scope": "regional",
                "region": "us-east-1",
                "account_id": "000000000001",
                "summary": {},
                "flags_hint": {"config_recorder_enable": True},
                "potentially_affected_workloads": "see change_assurance",
            },
            "evidence_assessment": {"evidence_quality": "DIRECT", "finding_status": "OPEN"},
        }

    monkeypatch.setattr(cloud_adapter.CloudSecurityAdapter, "verify_finding", _fake_verify)
    monkeypatch.setattr(
        cloud_adapter.CloudSecurityAdapter,
        "gather_evidence",
        lambda self, finding, context: [],
    )

    report = assure_job(job, findings, focus_finding_id="CLOUD-LOG-002")
    assert report.get("reviewed_plan")
    assert (report["reviewed_plan"].get("summary") or {}).get("create") == 9
    assert not any(
        isinstance(d, dict) and str(d.get("type") or "").lower() == "none_detected"
        for d in (report.get("dependencies") or [])
    )

    # Persist + reload through Face-like path
    from change_assurance.engine import persist_assurance

    persist_assurance(ws, report)
    impact = load_or_assure(ws, job, findings, refresh=False, focus_finding_id="CLOUD-LOG-002")
    mm = build_manager_view(job, findings, impact, focus_finding_id="CLOUD-LOG-002")
    primary = mm.get("primary") or {}
    affect = primary.get("affect") or {}

    assert affect.get("plan_reviewed") is True
    assert affect.get("plan_create") == 9
    assert affect.get("plan_modify") == 0
    assert affect.get("plan_destroy") == 0
    joined = json.dumps(affect) + json.dumps(primary.get("recommendation_label"))
    assert "see change_assurance" not in joined
    assert "none_detected" not in joined.lower()
    assert any("service-linked" in str(x) for x in (affect.get("known_dependencies") or []))
    assert "REVIEW" in str(primary.get("recommendation_label") or "").upper()
    assert primary.get("execution") == "NOT PERFORMED"

    # Template render path (Jinja) — same strings Face serves
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates_root = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_root)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    def _url_for(endpoint, **kwargs):
        return f"/{endpoint}"

    env.globals["url_for"] = _url_for
    tpl = env.get_template("face/job.html")
    html = tpl.render(
        job=job,
        review={
            "manager": mm,
            "impact": impact,
            "findings": findings,
            "findings_count": 1,
            "kit_exists": True,
            "kit_files": ["terraform/CLOUD-LOG-002.tf"],
            "explain": {},
            "risk_score": 1,
            "risk_label": "low",
            "risk_class": "ok",
            "compliance": {},
        },
        FACE_VERSION="test",
    )
    assert "9 CREATE" in html
    assert "0 CHANGE" in html
    assert "0 DESTROY" in html
    assert "aws_iam_service_linked_role.config" in html
    assert "see change_assurance" not in html
    assert "none_detected" not in html
    assert "REVIEW WITH MANAGER" in html or "REVIEW" in html
