# face_app.py
# Sentinel Stacks — Face (Manager Console) v0.1.0-f1
# Beautiful local dashboard over Brain B3.
# Data plane: local brain_workspace only. Never auto-applies.

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

import ai_brain_agent
import ai_brain_llm
import compliance_map

ROOT = Path(__file__).resolve().parent
FACE_VERSION = "0.8.0-casebook"


def _cloud_live_ready() -> bool:
    """True when live AWS collectors can authenticate (profile sentinel-demo by default)."""
    try:
        from ai_cloud_live_aws import aws_live_ready

        return aws_live_ready(os.environ.get("AWS_PROFILE") or "sentinel-demo")
    except Exception:
        return False

# Face agent catalog — each Hands pack is one named AI agent + its engines.
AGENT_CATALOG: list[dict] = [
    {
        "key": "security-engineer",
        "title": "Security Engineer Agent",
        "short": "SE",
        "tag": "AI AGENT",
        "focus": "Perimeter · phishing · API · identity",
        "id_prefix": "PERIM-",
        "engines": [
            "network", "data_exposure", "api", "vuln", "identity",
            "governance", "phishing", "traffic", "protocol", "asset",
        ],
    },
    {
        "key": "devsecops",
        "title": "DevSecOps Agent",
        "short": "DSO",
        "tag": "AI AGENT",
        "focus": "Secrets · CI/CD · SCA · containers · IaC",
        "id_prefix": "DEVSEC-",
        "engines": [
            "secrets", "cicd", "sca", "container", "iac",
            "policy", "sast", "supply_chain", "sbom", "release",
        ],
    },
    {
        "key": "cloud",
        "title": "Cloud Security Agent",
        "short": "CLD",
        "tag": "AI AGENT",
        "focus": "AWS/Azure posture · identity · network · data",
        "id_prefix": "CLOUD-",
        "engines": [
            "iam", "network", "storage", "logging", "encryption",
            "compute", "containers", "serverless", "compliance", "public_exposure",
        ],
    },
    {
        "key": "ai-security",
        "title": "AI Security Agent",
        "short": "AIS",
        "tag": "AI AGENT",
        "focus": "LLM · RAG · MCP · model supply chain",
        "id_prefix": "AISEC-",
        "engines": [
            "prompt_injection", "llm_api_keys", "rag_data_leakage", "output_filtering",
            "agent_tool_abuse", "mcp_permissions", "model_supply_chain",
            "training_poison", "model_governance", "inference_hardening",
        ],
    },
]

app = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
)
app.config["TEMPLATES_AUTO_RELOAD"] = True


def _brain(action: str, **kwargs):
    params = {"action": action, "workspace": str(ai_brain_agent.DEFAULT_WORKSPACE)}
    params.update(kwargs)
    return ai_brain_agent.run(params)


def _index():
    paths = ai_brain_agent._ensure_workspace(ai_brain_agent.DEFAULT_WORKSPACE)
    return ai_brain_agent._read_json(paths["index"])


def _job(job_id: str) -> dict | None:
    paths = ai_brain_agent._ensure_workspace(ai_brain_agent.DEFAULT_WORKSPACE)
    jp = paths["jobs"] / f"{job_id}.json"
    if not jp.is_file():
        return None
    return ai_brain_agent._read_json(jp)


def _latest_brief() -> dict | None:
    paths = ai_brain_agent._ensure_workspace(ai_brain_agent.DEFAULT_WORKSPACE)
    index = ai_brain_agent._read_json(paths["index"])
    bid = index.get("last_brief_id")
    if not bid:
        # newest file fallback
        briefs = sorted(paths["briefs"].glob("brief_*.json"), reverse=True)
        if not briefs:
            return None
        return ai_brain_agent._read_json(briefs[0])
    bp = paths["briefs"] / f"{bid}.json"
    if not bp.is_file():
        return None
    return ai_brain_agent._read_json(bp)


def _dashboard_context():
    status = _brain("status")
    pending = _brain("pending")
    index = (status.get("metadata") or {}).get("index") or _index()
    jobs = (pending.get("metadata") or {}).get("jobs") or []
    brief = _latest_brief()
    llm = ai_brain_llm.provider_status()

    # Sort pending: more findings / worse risk first
    def sort_key(j):
        s = j.get("summary") or {}
        counts = s.get("severity_counts") or {}
        return (
            -(int(counts.get("critical") or 0)),
            -(int(counts.get("high") or 0)),
            -(int(s.get("total_findings") or 0)),
        )

    jobs_sorted = sorted(jobs, key=sort_key)

    role_counts: dict[str, int] = {}
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings_total = 0
    jobs_by_agent: dict[str, list] = {a["key"]: [] for a in AGENT_CATALOG}
    for j in jobs_sorted:
        role = j.get("role") or "unknown"
        role_counts[role] = role_counts.get(role, 0) + 1
        if role in jobs_by_agent:
            jobs_by_agent[role].append(j)
        s = j.get("summary") or {}
        findings_total += int(s.get("total_findings") or 0)
        counts = s.get("severity_counts") or {}
        for k in sev_totals:
            sev_totals[k] += int(counts.get(k) or 0)

    agents = []
    for a in AGENT_CATALOG:
        ajobs = jobs_by_agent.get(a["key"]) or []
        a_crit = sum(int(((j.get("summary") or {}).get("severity_counts") or {}).get("critical") or 0) for j in ajobs)
        a_high = sum(int(((j.get("summary") or {}).get("severity_counts") or {}).get("high") or 0) for j in ajobs)
        a_findings = sum(int((j.get("summary") or {}).get("total_findings") or 0) for j in ajobs)
        # Per-agent risk = worst job score among this agent's pending jobs
        a_scores = [compliance_map.job_risk_score(j) for j in ajobs]
        a_risk = min(a_scores) if a_scores else 100
        a_label, a_css = compliance_map.risk_label(a_risk)
        agents.append(
            {
                **a,
                "jobs": ajobs,
                "pending": len(ajobs),
                "critical": a_crit,
                "high": a_high,
                "findings": a_findings,
                "risk_score": a_risk,
                "risk_label": a_label,
                "risk_class": a_css,
                "status": "WORKING" if ajobs else "IDLE",
            }
        )

    # Annotate jobs with risk for cards
    for j in jobs_sorted:
        score = compliance_map.job_risk_score(j)
        label, css = compliance_map.risk_label(score)
        j["risk_score"] = score
        j["risk_label"] = label
        j["risk_class"] = css

    # Simple posture label for MSSP header
    if sev_totals["critical"] > 0:
        posture = "CRITICAL"
        posture_class = "posture-critical"
    elif sev_totals["high"] > 0:
        posture = "ELEVATED"
        posture_class = "posture-elevated"
    elif findings_total > 0:
        posture = "MODERATE"
        posture_class = "posture-moderate"
    else:
        posture = "CLEAR"
        posture_class = "posture-clear"

    try:
        import worker_alert

        alerts = worker_alert.list_alerts(ai_brain_agent.DEFAULT_WORKSPACE, limit=20)
        backlog = worker_alert.backlog_from_jobs(jobs_sorted)
    except Exception:
        alerts = []
        backlog = []

    compliance = compliance_map.fleet_compliance(jobs_sorted, _raw_findings_for_job)

    try:
        import worker_report

        evidence_notes = worker_report.list_evidence(ai_brain_agent.DEFAULT_WORKSPACE, limit=8)
        ciso_reports = worker_report.list_ciso_reports(ai_brain_agent.DEFAULT_WORKSPACE, limit=5)
    except Exception:
        evidence_notes = []
        ciso_reports = []

    try:
        import security_casebook

        security_casebook.ensure_iam_password_policy_case(ai_brain_agent.DEFAULT_WORKSPACE)
        completed_cases = security_casebook.list_cases(ai_brain_agent.DEFAULT_WORKSPACE)[:8]
        completed_n = len(security_casebook.list_cases(ai_brain_agent.DEFAULT_WORKSPACE))
    except Exception:
        completed_cases = []
        completed_n = 0

    return {
        "face_version": FACE_VERSION,
        "brain_version": ai_brain_agent.VERSION,
        "index": index,
        "jobs": jobs_sorted,
        "brief": brief,
        "llm": llm,
        "role_counts": role_counts,
        "agents": agents,
        "sev_totals": sev_totals,
        "findings_total": findings_total,
        "posture": posture,
        "posture_class": posture_class,
        "pending_n": len(index.get("pending_job_ids") or []),
        "approved_n": len(index.get("approved_job_ids") or []),
        "rejected_n": len(index.get("rejected_job_ids") or []),
        "last_cycle": index.get("last_cycle_id"),
        "workspace": str(ai_brain_agent.DEFAULT_WORKSPACE),
        "alerts": alerts,
        "backlog": backlog,
        "alert_n": len(alerts),
        "compliance": compliance,
        "fleet_risk_score": compliance.get("fleet_risk_score", 100),
        "fleet_risk_label": compliance.get("fleet_risk_label", "LOW"),
        "fleet_risk_class": compliance.get("fleet_risk_class", "risk-low"),
        "evidence_notes": evidence_notes,
        "ciso_reports": ciso_reports,
        "completed_cases": completed_cases,
        "completed_n": completed_n,
    }


@app.route("/")
def dashboard():
    return render_template("face/dashboard.html", **_dashboard_context())


def _normalize_finding(f: dict) -> dict:
    """Make finding fields safe for templates (remediation always a dict)."""
    rem = f.get("remediation")
    if not isinstance(rem, dict):
        rem = {"steps": [str(rem)] if rem else []}
    steps = rem.get("steps")
    if isinstance(steps, str):
        steps = [steps]
    elif not isinstance(steps, list):
        steps = []
    steps = [str(s) for s in steps if s is not None]
    compliance = compliance_map.normalize_compliance(f.get("compliance"))
    frameworks = sorted({compliance_map.classify_control(t) for t in compliance})
    return {
        "id": str(f.get("id") or "UNKNOWN"),
        "severity": str(f.get("severity") or "info").lower(),
        "title": str(f.get("title") or f.get("name") or "Untitled finding"),
        "description": str(f.get("description") or "No description."),
        "compliance": compliance,
        "frameworks": frameworks,
        "remediation": {
            "steps": steps,
            "effort": rem.get("effort"),
        },
    }


def _raw_findings_for_job(job: dict) -> list[dict]:
    """Load findings from scan report (with compliance) for rollups."""
    scan_path = Path(str(job.get("scan_report_path") or ""))
    if not scan_path.is_file():
        return []
    try:
        report = json.loads(scan_path.read_text(encoding="utf-8-sig"))
        raw = report.get("findings") or []
        return [f for f in raw if isinstance(f, dict)]
    except Exception:
        return []


def _brain_explain_job(job: dict, findings: list[dict]) -> dict:
    """Instant Brain explanation: what was found + how to fix (no network wait)."""
    summary = job.get("summary") or {}
    counts = summary.get("severity_counts") or {}
    crit = int(counts.get("critical") or 0)
    high = int(counts.get("high") or 0)
    total = len(findings) or int(summary.get("total_findings") or 0)
    role = job.get("role") or "security"
    mapped = job.get("remediation_mapped")

    headline = (
        f"Brain reviewed this {role} job: {total} finding(s) "
        f"({crit} critical, {high} high). "
        "Below is what matters and how to fix it. "
        "Download the hardening kit ZIP, unzip it, then follow the runbooks."
    )
    if crit or high:
        recommendation = "approve"
        why = (
            f"Priority: fix critical/high first ({crit} critical / {high} high). "
            "Approve only after you understand the issues and have the kit downloaded."
        )
    elif total:
        recommendation = "investigate"
        why = "No critical/high counts — still review findings before approve."
    else:
        recommendation = "reject"
        why = "No actionable findings loaded for this job."

    issue_fixes: list[dict] = []
    for f in findings[:20]:
        steps = (f.get("remediation") or {}).get("steps") or []
        how = " → ".join(steps[:4]) if steps else (
            f"Open the kit runbook/config for {f.get('id')} and apply the dry-run steps."
        )
        issue_fixes.append(
            {
                "id": f.get("id"),
                "severity": f.get("severity"),
                "issue": f.get("title"),
                "why": f.get("description"),
                "how_to_fix": how,
                "compliance": f.get("compliance") or [],
                "frameworks": f.get("frameworks") or [],
            }
        )

    # Compact offline Brain brief for this single job (instant, local).
    evidence = ai_brain_llm.build_evidence_bundle(jobs=[job], mode="job_review")
    # Enrich top findings from full scan so Brain text is specific.
    if evidence.get("pending_jobs") and findings:
        evidence["pending_jobs"][0]["top_findings"] = [
            {"id": f["id"], "severity": f["severity"], "title": f["title"]}
            for f in findings[:12]
        ]
        evidence["pending_jobs"][0]["finding_ids"] = [f["id"] for f in findings[:12]]
        evidence["pending_jobs"][0]["total_findings"] = total
    reasoned = ai_brain_llm.offline_reason(evidence)

    return {
        "headline": headline,
        "recommendation": recommendation,
        "why": why,
        "executive_summary": reasoned.get("executive_summary") or headline,
        "ceo_brief": reasoned.get("ceo_brief") or "",
        "issue_fixes": issue_fixes,
        "mapped": mapped,
        "provider": "offline",
        "model": "heuristic-v1",
        "confidence": reasoned.get("confidence") or "medium",
    }


def _load_job_review(job: dict) -> dict:
    """Load findings, Brain explain, and kit file list for manager review."""
    findings: list[dict] = []
    scan_path = Path(str(job.get("scan_report_path") or ""))
    if scan_path.is_file():
        try:
            report = json.loads(scan_path.read_text(encoding="utf-8-sig"))
            raw = report.get("findings") or []
            if isinstance(raw, list):
                findings = [_normalize_finding(f) for f in raw if isinstance(f, dict)]
        except Exception:
            findings = []

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        findings,
        key=lambda f: (rank.get(f.get("severity") or "info", 9), f.get("id") or ""),
    )

    kit_path = Path(str(job.get("kit_path") or ""))
    kit_exists = kit_path.is_file()
    kit_files: list[str] = []
    if kit_exists and kit_path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(kit_path, "r") as zf:
                kit_files = sorted(
                    n for n in zf.namelist()
                    if not n.endswith("/") and not n.endswith("\\")
                )[:80]
        except Exception:
            kit_files = []
    elif kit_path.is_dir():
        kit_exists = True
        kit_files = sorted(
            str(p.relative_to(kit_path)).replace("\\", "/")
            for p in kit_path.rglob("*")
            if p.is_file()
        )[:80]

    explain = _brain_explain_job(job, findings)
    risk = compliance_map.job_risk_score(job, findings)
    risk_label, risk_class = compliance_map.risk_label(risk)
    compliance = compliance_map.rollup_compliance(
        findings,
        job_id=job.get("job_id"),
        role=job.get("role"),
    )

    impact = None
    try:
        from predeploy.impact_analysis import load_or_analyze
        from flask import has_request_context

        refresh = False
        if has_request_context():
            refresh = str(request.args.get("refresh_impact") or "") in {"1", "true", "yes"}
        impact = load_or_analyze(
            ai_brain_agent.DEFAULT_WORKSPACE,
            job,
            findings,
            refresh=refresh,
            try_terraform_cli=False,
        )
        # Overlay Brain recommendation with pre-deploy readiness (still not authorization).
        if impact and impact.get("recommendation"):
            explain = dict(explain)
            explain["recommendation"] = str(impact.get("recommendation")).replace("RECOMMEND_", "").lower()
            explain["predeploy_recommendation"] = impact.get("recommendation")
            explain["deployment_ready"] = impact.get("deployment_ready")
            explain["blast_radius"] = (impact.get("blast_radius") or {}).get("level")
            explain["why"] = (
                f"Pre-deploy: {impact.get('recommendation')} · "
                f"blast {(impact.get('blast_radius') or {}).get('level')} · "
                f"finding {impact.get('finding_status')}. "
                "Manager approval still required — recommendation is not authorization."
            )
            explain["confidence"] = impact.get("confidence") or explain.get("confidence")
    except Exception as impact_exc:
        impact = {
            "error": str(impact_exc),
            "recommendation": "RECOMMEND_REVIEW",
            "manager_approval_required": True,
            "report_text": f"Impact analysis unavailable: {impact_exc}",
        }

    focus_id = None
    try:
        from flask import has_request_context

        if has_request_context():
            focus_id = request.args.get("finding") or None
    except Exception:
        focus_id = None

    manager = None
    try:
        import manager_mode

        manager = manager_mode.build_manager_view(job, findings, impact, focus_finding_id=focus_id)
    except Exception as mm_exc:
        manager = {"error": str(mm_exc), "mode": "manager"}

    return {
        "findings": findings,
        "findings_count": len(findings),
        "kit_files": kit_files,
        "kit_path": str(job.get("kit_path") or ""),
        "kit_name": kit_path.name if kit_path.name else "",
        "kit_exists": kit_exists,
        "scan_path": str(job.get("scan_report_path") or ""),
        "explain": explain,
        "risk_score": risk,
        "risk_label": risk_label,
        "risk_class": risk_class,
        "compliance": compliance,
        "impact": impact,
        "manager": manager,
    }


@app.route("/job/<job_id>")
def job_detail(job_id: str):
    job = _job(job_id)
    if not job:
        return redirect(url_for("dashboard"))
    try:
        review = _load_job_review(job)
    except Exception as exc:
        review = {
            "findings": [],
            "findings_count": 0,
            "kit_files": [],
            "kit_path": str(job.get("kit_path") or ""),
            "kit_name": "",
            "kit_exists": False,
            "scan_path": str(job.get("scan_report_path") or ""),
            "explain": {
                "headline": f"Brain could not fully load this job: {exc}",
                "recommendation": "investigate",
                "why": "Open the kit if available, or re-run a cycle.",
                "executive_summary": str(exc),
                "ceo_brief": "",
                "issue_fixes": [],
                "provider": "offline",
                "model": "error",
                "confidence": "low",
            },
        }
    return render_template(
        "face/job.html",
        job=job,
        review=review,
        face_version=FACE_VERSION,
        brain_version=ai_brain_agent.VERSION,
    )


@app.route("/job/<job_id>/kit")
def download_kit(job_id: str):
    """Download the hardening kit ZIP for this job."""
    job = _job(job_id)
    if not job:
        abort(404)
    kit_path = Path(str(job.get("kit_path") or ""))
    if not kit_path.is_file():
        abort(404)
    return send_file(
        kit_path,
        as_attachment=True,
        download_name=kit_path.name,
        mimetype="application/zip",
    )


@app.route("/job/<job_id>/impact")
def download_impact(job_id: str):
    """Download pre-deployment impact analysis markdown."""
    md = ai_brain_agent.DEFAULT_WORKSPACE / "impact" / f"{job_id}.md"
    if not md.is_file():
        job = _job(job_id)
        if not job:
            abort(404)
        from predeploy.impact_analysis import analyze_job, persist_analysis

        findings: list[dict] = []
        scan_path = Path(str(job.get("scan_report_path") or ""))
        if scan_path.is_file():
            try:
                report = json.loads(scan_path.read_text(encoding="utf-8-sig"))
                findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]
            except Exception:
                findings = []
        doc = analyze_job(job, findings, try_terraform_cli=False)
        persist_analysis(ai_brain_agent.DEFAULT_WORKSPACE, doc)
        md = Path((doc.get("paths") or {}).get("markdown") or md)
    if not md.is_file():
        abort(404)
    return send_file(md, as_attachment=True, download_name=md.name)


@app.route("/api/job/<job_id>/impact", methods=["GET", "POST"])
def api_job_impact(job_id: str):
    job = _job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    from predeploy.impact_analysis import analyze_job, load_or_analyze, persist_analysis

    refresh = request.method == "POST" or str(request.args.get("refresh") or "") in {"1", "true"}
    findings: list[dict] = []
    scan_path = Path(str(job.get("scan_report_path") or ""))
    if scan_path.is_file():
        try:
            report = json.loads(scan_path.read_text(encoding="utf-8-sig"))
            findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]
        except Exception:
            findings = []
    if refresh:
        doc = analyze_job(job, findings, try_terraform_cli=False)
        persist_analysis(ai_brain_agent.DEFAULT_WORKSPACE, doc)
        return jsonify(doc)
    return jsonify(load_or_analyze(ai_brain_agent.DEFAULT_WORKSPACE, job, findings, refresh=False))


@app.route("/api/status")
def api_status():
    return jsonify(_brain("status"))


@app.route("/api/pending")
def api_pending():
    return jsonify(_brain("pending"))


@app.route("/api/approve/<job_id>", methods=["POST"])
def api_approve(job_id: str):
    note = None
    if request.is_json:
        note = (request.get_json(silent=True) or {}).get("note")
    result = _brain("approve", job_id=job_id, note=note)
    if request.accept_mimetypes.best == "application/json" or request.is_json:
        return jsonify(result)
    return redirect(url_for("dashboard"))


@app.route("/api/reject/<job_id>", methods=["POST"])
def api_reject(job_id: str):
    note = None
    if request.is_json:
        note = (request.get_json(silent=True) or {}).get("note")
    result = _brain("reject", job_id=job_id, note=note)
    if request.accept_mimetypes.best == "application/json" or request.is_json:
        return jsonify(result)
    return redirect(url_for("dashboard"))


@app.route("/api/brief", methods=["POST", "GET"])
def api_brief():
    provider = request.args.get("provider") or (request.get_json(silent=True) or {}).get("provider")
    result = _brain("brief", llm_provider=provider or "offline", llm=True)
    if request.method == "GET" and not request.args.get("json"):
        return redirect(url_for("dashboard"))
    return jsonify(result)


@app.route("/api/cycle", methods=["POST"])
def api_cycle():
    data = request.get_json(silent=True) or {}
    live = _cloud_live_ready()
    # Explicit mock:false from Face → live Cloud. Never silently fall back to mock
    # when the client asked for live (surface the collect error instead).
    if "mock" in data:
        mock = bool(data.get("mock"))
    else:
        mock = not live
    if data.get("roles"):
        roles = data.get("roles")
    elif not mock:
        roles = "cloud"
    else:
        roles = "security-engineer,devsecops,cloud,ai-security"
    # If client requested live but AWS is not ready, fail clearly (do not mock).
    if not mock and not live and "cloud" in str(roles):
        return (
            jsonify(
                {
                    "status": "failed",
                    "error": (
                        "Live AWS not ready. Check: pip install boto3; "
                        "aws sts get-caller-identity --profile sentinel-demo"
                    ),
                    "live_ready": False,
                }
            ),
            503,
        )
    result = _brain(
        "cycle",
        mock=mock,
        roles=roles,
        llm=bool(data.get("llm", True)),
        llm_provider=data.get("provider") or "offline",
    )
    result["live_ready"] = live
    result["cycle_mock"] = mock
    return jsonify(result)


@app.route("/api/ciso-report", methods=["POST", "GET"])
def api_ciso_report():
    result = _brain("ciso-report", account="aws-952654481542")
    return jsonify(result)


@app.route("/reports/evidence/<evidence_id>")
def download_evidence(evidence_id: str):
    safe = Path(evidence_id).name
    if not safe.startswith("evidence_"):
        abort(404)
    paths = ai_brain_agent._ensure_workspace(ai_brain_agent.DEFAULT_WORKSPACE)
    md = paths["reports"] / "evidence" / f"{safe}.md"
    if not md.is_file():
        abort(404)
    return send_file(md, as_attachment=True, download_name=md.name)


@app.route("/reports/ciso/<report_id>")
def download_ciso(report_id: str):
    safe = Path(report_id).name
    if not safe.startswith("ciso_"):
        abort(404)
    paths = ai_brain_agent._ensure_workspace(ai_brain_agent.DEFAULT_WORKSPACE)
    md = paths["reports"] / "ciso" / f"{safe}.md"
    if not md.is_file():
        abort(404)
    return send_file(md, as_attachment=True, download_name=md.name)


@app.route("/completed")
def completed_jobs():
    import security_casebook

    ws = ai_brain_agent.DEFAULT_WORKSPACE
    try:
        security_casebook.ensure_iam_password_policy_case(ws)
    except Exception:
        pass
    cases = security_casebook.list_cases(ws)
    filtered = security_casebook.filter_cases(
        cases,
        agent=request.args.get("agent") or None,
        domain=request.args.get("domain") or None,
        severity=request.args.get("severity") or None,
        status=request.args.get("status") or None,
        control_id=request.args.get("control") or request.args.get("finding") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
        q=request.args.get("q") or None,
    )
    return render_template(
        "face/completed_jobs.html",
        face_version=FACE_VERSION,
        cases=filtered,
        total=len(cases),
        filters={
            "agent": request.args.get("agent") or "",
            "domain": request.args.get("domain") or "",
            "severity": request.args.get("severity") or "",
            "status": request.args.get("status") or "",
            "control": request.args.get("control") or request.args.get("finding") or "",
            "date_from": request.args.get("date_from") or "",
            "date_to": request.args.get("date_to") or "",
            "q": request.args.get("q") or "",
        },
    )


@app.route("/completed/<case_id>")
def completed_case(case_id: str):
    import security_casebook

    case = security_casebook.load_case(ai_brain_agent.DEFAULT_WORKSPACE, case_id)
    if not case:
        abort(404)
    return render_template(
        "face/completed_case.html",
        face_version=FACE_VERSION,
        case=case,
    )


@app.route("/completed/<case_id>/download/<fmt>")
def download_case_report(case_id: str, fmt: str):
    import security_casebook

    ws = ai_brain_agent.DEFAULT_WORKSPACE
    case = security_casebook.load_case(ws, case_id)
    if not case:
        abort(404)
    directory = security_casebook.case_dir(ws, case_id)
    # Refresh exports so downloads stay available even if PDF was missing earlier.
    security_casebook.write_case_exports(case, directory)
    reports = directory / "reports"
    mapping = {
        "readme": (directory / "README.md", f"{case_id}_README.md", "text/markdown"),
        "internal-md": (reports / "internal.md", f"{case_id}_internal.md", "text/markdown"),
        "public-md": (reports / "public.md", f"{case_id}_public.md", "text/markdown"),
        "internal-pdf": (reports / "internal.pdf", f"{case_id}_internal.pdf", "application/pdf"),
        "public-pdf": (reports / "public.pdf", f"{case_id}_public.pdf", "application/pdf"),
        "linkedin": (reports / "linkedin.txt", f"{case_id}_linkedin.txt", "text/plain"),
        "interview": (reports / "interview.md", f"{case_id}_interview.md", "text/markdown"),
        "portfolio": (reports / "portfolio_summary.txt", f"{case_id}_portfolio.txt", "text/plain"),
    }
    item = mapping.get(fmt)
    if not item:
        abort(404)
    path, download_name, mime = item
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=download_name, mimetype=mime)


@app.route("/api/cases/archive/<job_id>", methods=["POST"])
def api_archive_case(job_id: str):
    """Create a permanent case from an approved job + after-scan verification."""
    import security_casebook

    data = request.get_json(silent=True) or {}
    after = data.get("after_scan_path") or request.args.get("after_scan_path")
    classification = data.get("classification") or "LAB"
    title = data.get("title")
    try:
        case = security_casebook.create_case_from_job(
            ai_brain_agent.DEFAULT_WORKSPACE,
            job_id,
            after_scan_path=after,
            classification=classification,
            title=title,
            intended_control_ids=data.get("intended_control_ids"),
        )
    except Exception as exc:
        return jsonify({"status": "failed", "error": str(exc)}), 400
    if request.accept_mimetypes.best == "application/json" or request.is_json:
        return jsonify({"status": "ok", "case_id": case.get("case_id"), "case": case})
    return redirect(url_for("completed_case", case_id=case.get("case_id")))


@app.route("/api/alerts")
def api_alerts():
    import worker_alert

    return jsonify(
        {
            "alerts": worker_alert.list_alerts(ai_brain_agent.DEFAULT_WORKSPACE, limit=50),
            "version": worker_alert.VERSION,
        }
    )


@app.route("/api/backlog")
def api_backlog():
    import worker_alert

    pending = _brain("pending")
    jobs = (pending.get("metadata") or {}).get("jobs") or []
    return jsonify({"backlog": worker_alert.backlog_from_jobs(jobs)})


def main():
    print(f"Sentinel Stacks Face {FACE_VERSION}")
    print(f"Brain {ai_brain_agent.VERSION}")
    print(f"Workspace: {ai_brain_agent.DEFAULT_WORKSPACE}")
    print("Open: http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False)


if __name__ == "__main__":
    main()
