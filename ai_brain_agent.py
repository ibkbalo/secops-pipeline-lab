# ai_brain_agent.py
# Sentinel Stacks — Shared Role Brain (multi-role agent loop)
# TOOL_STANDARDS.md v1.0
# Phase B1: one Brain for all four Hands packs —
#   discover roles → run packs → triage → draft remediation kits →
#   queue jobs for MANAGER APPROVAL (never auto-apply).
# Phase B2: ALWAYS-ON watch loop + job dedupe + manager audit log.
# Phase B3: LLM reasoning node (OpenAI / Anthropic / offline fallback) —
#   brief + reason over Hands evidence; still never auto-applies.
# Data plane: local workspace only (customer-controlled).
# Control plane / SaaS entitlement: stub hooks only (subscription later).
#
# Product model:
#   Hands = specialist tools (already built)
#   Brain = always-on workforce that proposes work (+ LLM judgment)
#   Manager (you) = approve / reject before any real action
#   Face = GUI later

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import ai_brain_llm

TOOL_ID = "orchestrate_role_brain"
VERSION = "0.4.2-w3"
DOMAIN = "command-center"
SUBDOMAIN = "brain/role-orchestration"
SENTINEL = "command"
TIER = 2
TAGS = [
    "brain",
    "orchestration",
    "multi-role",
    "approval-gate",
    "autonomous-workforce",
    "customer-local",
    "watch-loop",
    "llm-reasoning",
    "enterprise",
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Canonical role workers — one Brain, four Hands.
ROLE_WORKERS: dict[str, dict[str, Any]] = {
    "security-engineer": {
        "title": "Security Engineer",
        "module_file": "ai_security_engineer_pack.py",
        "tool_id": "scan_security_engineer_pack",
        "mock_flag": True,
        "id_prefix": "PERIM-",
    },
    "devsecops": {
        "title": "DevSecOps",
        "module_file": "ai_devsecops_pack.py",
        "tool_id": "scan_devsecops_pack",
        "mock_flag": True,
        "id_prefix": "DEVSEC-",
    },
    "cloud": {
        "title": "Cloud Security Engineer",
        "module_file": "ai_cloud_pack.py",
        "tool_id": "scan_cloud_pack",
        "mock_flag": True,
        "id_prefix": "CLOUD-",
    },
    "ai-security": {
        "title": "AI Security Engineer",
        "module_file": "ai_ai_security_pack.py",
        "tool_id": "scan_ai_security_pack",
        "mock_flag": True,
        "id_prefix": "AISEC-",
    },
}

DEFAULT_ROLES = list(ROLE_WORKERS.keys())
ROOT = Path(__file__).resolve().parent
DEFAULT_WORKSPACE = ROOT / "brain_workspace"

# Subscription / ownership hooks (stub — no remote calls yet).
LICENSE_HOOK = {
    "ownership": "vendor_ip",
    "customer_model": "subscription_rent",
    "data_plane": "customer_local",
    "control_plane": "deferred_face_later",
    "entitlement": "dev_local",
    "auto_apply_forbidden": True,
}

DEFAULT_WATCH_INTERVAL_SECONDS = 300


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{_stamp()}_{uuid.uuid4().hex[:8]}"


def _ascii(s: str) -> str:
    return (s or "").encode("ascii", "replace").decode("ascii")


def _load_module(module_file: str):
    path = ROOT / module_file
    if not path.is_file():
        raise FileNotFoundError(f"module not found: {path}")
    name = path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ensure_workspace(workspace: Path) -> dict[str, Path]:
    workspace.mkdir(parents=True, exist_ok=True)
    paths = {
        "root": workspace,
        "cycles": workspace / "cycles",
        "jobs": workspace / "jobs",
        "scans": workspace / "scans",
        "briefs": workspace / "briefs",
        "alerts": workspace / "alerts",
        "drafts": workspace / "drafts",
        "reports": workspace / "reports",
        "index": workspace / "index.json",
        "audit": workspace / "audit.jsonl",
        "watch": workspace / "watch_state.json",
    }
    for key in ("cycles", "jobs", "scans", "briefs", "alerts", "drafts", "reports"):
        paths[key].mkdir(exist_ok=True)
    (paths["reports"] / "evidence").mkdir(exist_ok=True)
    (paths["reports"] / "ciso").mkdir(exist_ok=True)
    if not paths["index"].is_file():
        _write_json(
            paths["index"],
            {
                "version": VERSION,
                "created_at": _now(),
                "pending_job_ids": [],
                "approved_job_ids": [],
                "rejected_job_ids": [],
                "last_cycle_id": None,
                "open_fingerprints": {},
                "license": LICENSE_HOOK,
            },
        )
    if not paths["audit"].is_file():
        paths["audit"].write_text("", encoding="utf-8")
    return paths


def _append_audit(paths: dict[str, Path], event: dict[str, Any]) -> None:
    event = dict(event)
    event.setdefault("timestamp", _now())
    event.setdefault("brain_version", VERSION)
    with paths["audit"].open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=True) + "\n")


def _findings_fingerprint(findings: list[dict]) -> str:
    ids = sorted(str(f.get("id") or "") for f in findings if isinstance(f, dict))
    raw = "|".join(ids)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _find_open_job_for_fingerprint(
    paths: dict[str, Path], role_key: str, fingerprint: str
) -> dict[str, Any] | None:
    index = _read_json(paths["index"])
    open_fp = index.get("open_fingerprints") or {}
    key = f"{role_key}:{fingerprint}"
    existing_id = open_fp.get(key)
    if not existing_id:
        # Fallback: scan pending jobs
        for jid in index.get("pending_job_ids") or []:
            jp = paths["jobs"] / f"{jid}.json"
            if not jp.is_file():
                continue
            job = _read_json(jp)
            if job.get("role") == role_key and job.get("fingerprint") == fingerprint:
                return job
        return None
    jp = paths["jobs"] / f"{existing_id}.json"
    if jp.is_file():
        job = _read_json(jp)
        if job.get("status") == "pending_approval":
            return job
    return None


def _pending_jobs_for_role(paths: dict[str, Path], role_key: str) -> list[dict[str, Any]]:
    index = _read_json(paths["index"])
    out: list[dict[str, Any]] = []
    for jid in index.get("pending_job_ids") or []:
        jp = paths["jobs"] / f"{jid}.json"
        if not jp.is_file():
            continue
        job = _read_json(jp)
        if job.get("role") == role_key and job.get("status") == "pending_approval":
            out.append(job)
    return out


def _supersede_job(
    paths: dict[str, Path],
    job: dict[str, Any],
    *,
    reason: str,
    cycle_id: str | None = None,
    replaced_by: str | None = None,
) -> None:
    """Close a pending job as superseded by a newer scan (not manager reject)."""
    job_id = str(job.get("job_id") or "")
    if not job_id:
        return
    job["status"] = "superseded"
    job["manager_decision"] = "superseded"
    job["apply_status"] = "not_executed"
    job["apply_note"] = reason
    job["updated_at"] = _now()
    job["superseded_at"] = _now()
    if cycle_id:
        job["superseded_by_cycle_id"] = cycle_id
    if replaced_by:
        job["replaced_by_job_id"] = replaced_by
    _write_json(paths["jobs"] / f"{job_id}.json", job)

    index = _read_json(paths["index"])
    pending = [x for x in (index.get("pending_job_ids") or []) if x != job_id]
    index["pending_job_ids"] = pending
    open_fp = dict(index.get("open_fingerprints") or {})
    fp_key = f"{job.get('role')}:{job.get('fingerprint')}"
    if open_fp.get(fp_key) == job_id:
        open_fp.pop(fp_key, None)
    # Also drop any stale entries pointing at this job id
    for k, v in list(open_fp.items()):
        if v == job_id:
            open_fp.pop(k, None)
    index["open_fingerprints"] = open_fp
    superseded = list(index.get("superseded_job_ids") or [])
    if job_id not in superseded:
        superseded.append(job_id)
    index["superseded_job_ids"] = superseded
    index["updated_at"] = _now()
    _write_json(paths["index"], index)
    _append_audit(
        paths,
        {
            "event": "job_superseded",
            "job_id": job_id,
            "role": job.get("role"),
            "reason": reason,
            "cycle_id": cycle_id,
            "replaced_by": replaced_by,
        },
    )


def _supersede_pending_for_role(
    paths: dict[str, Path],
    role_key: str,
    *,
    reason: str,
    cycle_id: str | None = None,
    keep_job_id: str | None = None,
    replaced_by: str | None = None,
) -> list[str]:
    """Ensure at most one pending job per role (keep_job_id optional)."""
    closed: list[str] = []
    for job in _pending_jobs_for_role(paths, role_key):
        jid = str(job.get("job_id") or "")
        if keep_job_id and jid == keep_job_id:
            continue
        _supersede_job(
            paths,
            job,
            reason=reason,
            cycle_id=cycle_id,
            replaced_by=replaced_by,
        )
        closed.append(jid)
    return closed


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"expected object in {path}")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _risk_score(counts: dict[str, int]) -> int:
    # Same spirit as packs: start 100, subtract weighted hits, floor 0.
    score = 100
    score -= counts.get("critical", 0) * 25
    score -= counts.get("high", 0) * 10
    score -= counts.get("medium", 0) * 4
    score -= counts.get("low", 0) * 1
    return max(0, min(100, score))


def _top_findings(findings: list[dict], limit: int = 8) -> list[dict[str, Any]]:
    ranked = sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 9),
            str(f.get("id") or ""),
        ),
    )
    out = []
    for f in ranked[:limit]:
        out.append(
            {
                "id": f.get("id"),
                "severity": f.get("severity"),
                "title": f.get("title") or f.get("name"),
            }
        )
    return out


def _normalize_roles(roles: list[str] | str | None) -> list[str]:
    if roles is None:
        return list(DEFAULT_ROLES)
    if isinstance(roles, str):
        roles = [r.strip() for r in roles.split(",") if r.strip()]
    out: list[str] = []
    for r in roles:
        key = r.strip().lower().replace("_", "-")
        aliases = {
            "se": "security-engineer",
            "security": "security-engineer",
            "security-engineer": "security-engineer",
            "devsec": "devsecops",
            "devsecops": "devsecops",
            "cloud": "cloud",
            "cloud-security": "cloud",
            "ai": "ai-security",
            "aisec": "ai-security",
            "ai-security": "ai-security",
            "ai-security-engineer": "ai-security",
        }
        mapped = aliases.get(key)
        if not mapped:
            raise ValueError(f"unknown role '{r}'. choose from: {', '.join(DEFAULT_ROLES)}")
        if mapped not in out:
            out.append(mapped)
    return out


def _run_role_pack(role_key: str, mock: bool, target: str | None) -> dict[str, Any]:
    worker = ROLE_WORKERS[role_key]
    mod = _load_module(worker["module_file"])
    if not hasattr(mod, "run"):
        raise RuntimeError(f"{worker['module_file']} has no run(params)")
    params: dict[str, Any] = {}
    if mock:
        params["mock"] = True
    elif role_key == "cloud":
        # Live AWS inventory via boto3 (profile sentinel-demo by default).
        if target:
            params["target"] = target
        else:
            params["target"] = "live"
        params["profile"] = os.environ.get("AWS_PROFILE") or "sentinel-demo"
        params["region"] = os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    elif target:
        params["target"] = target
    else:
        # Other roles still need a target or mock fixture for now.
        params["mock"] = True
    return mod.run(params)


def _run_remediation(scan_report: dict, output_dir: Path) -> dict[str, Any]:
    mod = _load_module("ai_remediation_engine.py")
    return mod.run(
        {
            "scan_report": scan_report,
            "output_dir": str(output_dir),
            "dry_run": True,
            "severity_threshold": "info",
        }
    )


def _triage_role(
    role_key: str,
    scan_report: dict[str, Any],
    remediation_report: dict[str, Any] | None,
) -> dict[str, Any]:
    findings = [f for f in (scan_report.get("findings") or []) if isinstance(f, dict)]
    counts = _severity_counts(findings)
    rem_meta = (remediation_report or {}).get("metadata") or {}
    rem_sum = (remediation_report or {}).get("summary") or {}
    mapped = rem_sum.get("fixes_mapped", rem_meta.get("mapped"))
    unmapped = rem_sum.get("fixes_unmapped", rem_meta.get("unmapped"))
    return {
        "role": role_key,
        "title": ROLE_WORKERS[role_key]["title"],
        "tool_id": scan_report.get("tool_id"),
        "pack_version": scan_report.get("version"),
        "scan_status": (scan_report.get("execution") or {}).get("status"),
        "total_findings": len(findings),
        "severity_counts": counts,
        "risk_score": _risk_score(counts),
        "top_findings": _top_findings(findings),
        "remediation": {
            "ran": remediation_report is not None,
            "status": ((remediation_report or {}).get("execution") or {}).get("status"),
            "mapped": mapped,
            "unmapped": unmapped,
            "kit_path": rem_meta.get("kit_path"),
            "requires_approval": True,
            "dry_run": True,
        },
        "manager_action_required": len(findings) > 0,
        "proposal": (
            f"Review {len(findings)} findings from {ROLE_WORKERS[role_key]['title']} "
            f"and approve the dry-run hardening kit before any apply."
            if findings
            else f"{ROLE_WORKERS[role_key]['title']} reported a clean scan — no kit approval needed."
        ),
    }


def run_cycle(params: dict[str, Any]) -> dict[str, Any]:
    """Run one Brain cycle: Hands → triage → remediate draft → pending jobs."""
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)

    try:
        roles = _normalize_roles(params.get("roles"))
    except ValueError as e:
        return _brain_report(
            action="cycle",
            status="failed",
            error=str(e),
            workspace=workspace,
            started=started,
        )

    mock = bool(params.get("mock", True))
    target = params.get("target")
    do_remediate = bool(params.get("remediate", True))
    # Default True: do not flood inbox when the same finding set is still pending.
    dedupe = bool(params.get("dedupe", True))
    cycle_id = _new_id("cycle")
    role_results: list[dict[str, Any]] = []
    jobs_created: list[dict[str, Any]] = []
    jobs_deduped: list[dict[str, Any]] = []
    evidence_notes: list[dict[str, Any]] = []
    errors: list[str] = []
    all_findings_count = 0

    def _emit_evidence_for_role(
        role_key: str,
        prior_jobs: list[dict[str, Any]],
        new_findings: list[dict],
        *,
        after_job_id: str | None = None,
        scan_report: dict | None = None,
        after_scan_path: str | None = None,
    ) -> None:
        if not prior_jobs:
            return
        try:
            import worker_report
        except Exception as exc:
            errors.append(f"{role_key}: evidence_import:{exc}")
            return
        before: list[dict] = []
        before_job_id = None
        for pj in prior_jobs:
            before_job_id = before_job_id or pj.get("job_id")
            before.extend(worker_report._load_findings(pj.get("scan_report_path")))
        cleared = worker_report.cleared_findings(before, new_findings)
        if not cleared:
            return
        acc = None
        mode = None
        if scan_report:
            mode = (scan_report.get("execution") or {}).get("mode")
            acc = (scan_report.get("execution") or {}).get("target")
            meta = scan_report.get("metadata") or {}
            acc = meta.get("aws_profile") and f"aws:{acc}" or acc
        note = worker_report.write_evidence_note(
            workspace,
            role=role_key,
            cleared=cleared,
            cycle_id=cycle_id,
            before_job_id=str(before_job_id) if before_job_id else None,
            after_job_id=after_job_id,
            account=str(acc) if acc else None,
            scan_mode=str(mode) if mode else None,
        )
        if note:
            evidence_notes.append(note)
        # Permanent casebook archive when clears are verified against an approved prior job.
        # Pending jobs alone are not enough — remediation is usually approved before re-scan.
        try:
            import security_casebook

            candidates = list(prior_jobs)
            for jp in paths["jobs"].glob("job_*.json"):
                try:
                    pj = _read_json(jp)
                except Exception:
                    continue
                if pj.get("role") != role_key:
                    continue
                if pj.get("status") not in {"approved", "partially_approved"}:
                    continue
                if any(c.get("job_id") == pj.get("job_id") for c in candidates):
                    continue
                candidates.append(pj)
            for pj in candidates:
                security_casebook.maybe_create_case_on_clear(
                    workspace,
                    before_job=pj,
                    after_findings=new_findings,
                    after_scan_path=after_scan_path,
                    classification=security_casebook.CLASSIFICATION_LAB,
                )
        except Exception as exc:
            errors.append(f"{role_key}: casebook:{exc}")

    for role_key in roles:
        try:
            scan_report = _run_role_pack(role_key, mock=mock, target=target if not mock else None)
        except Exception as e:
            errors.append(f"{role_key}: scan failed: {e}")
            role_results.append(
                {
                    "role": role_key,
                    "title": ROLE_WORKERS[role_key]["title"],
                    "scan_status": "failed",
                    "error": str(e),
                    "total_findings": 0,
                    "manager_action_required": False,
                }
            )
            continue

        scan_path = paths["scans"] / f"{cycle_id}_{role_key}.json"
        _write_json(scan_path, scan_report)

        rem_report = None
        findings_list = [f for f in (scan_report.get("findings") or []) if isinstance(f, dict)]
        if do_remediate and findings_list:
            try:
                rem_report = _run_remediation(scan_report, ROOT / "hardening_kits")
            except Exception as e:
                errors.append(f"{role_key}: remediation failed: {e}")

        triage = _triage_role(role_key, scan_report, rem_report)
        triage["scan_report_path"] = str(scan_path)
        fingerprint = _findings_fingerprint(findings_list)
        triage["fingerprint"] = fingerprint
        role_results.append(triage)
        all_findings_count += int(triage.get("total_findings") or 0)

        if not triage.get("manager_action_required"):
            prior = _pending_jobs_for_role(paths, role_key)
            _emit_evidence_for_role(
                role_key,
                prior,
                findings_list,
                scan_report=scan_report,
                after_scan_path=str(scan_path),
            )
            # Clean (or no actionable findings): close stale pending jobs for this role.
            closed = _supersede_pending_for_role(
                paths,
                role_key,
                reason=(
                    "Superseded by newer scan with no manager action required "
                    "(findings cleared or below triage threshold)."
                ),
                cycle_id=cycle_id,
            )
            if closed:
                triage["jobs_superseded"] = closed
            continue

        if dedupe:
            existing = _find_open_job_for_fingerprint(paths, role_key, fingerprint)
            if existing:
                existing["updated_at"] = _now()
                existing["last_seen_cycle_id"] = cycle_id
                existing["scan_report_path"] = str(scan_path)
                existing["summary"] = {
                    "total_findings": triage["total_findings"],
                    "severity_counts": triage["severity_counts"],
                    "risk_score": triage["risk_score"],
                    "top_findings": triage["top_findings"],
                }
                existing["proposal"] = triage["proposal"]
                existing["remediation_mapped"] = (triage.get("remediation") or {}).get("mapped")
                existing["remediation_unmapped"] = (triage.get("remediation") or {}).get("unmapped")
                kit = (triage.get("remediation") or {}).get("kit_path")
                if kit:
                    existing["kit_path"] = kit
                existing["dedupe_hits"] = int(existing.get("dedupe_hits") or 0) + 1
                _write_json(paths["jobs"] / f"{existing['job_id']}.json", existing)
                # Still only one pending job per role — close any siblings.
                _supersede_pending_for_role(
                    paths,
                    role_key,
                    reason="Superseded: duplicate pending job for same role; keeping refreshed open job.",
                    cycle_id=cycle_id,
                    keep_job_id=existing["job_id"],
                    replaced_by=existing["job_id"],
                )
                jobs_deduped.append(
                    {
                        "job_id": existing["job_id"],
                        "role": role_key,
                        "fingerprint": fingerprint,
                        "reason": "same_open_findings_still_pending",
                    }
                )
                triage["job_deduped"] = existing["job_id"]
                continue

        # Findings changed → evidence for clears, then replace prior pending job(s).
        prior = _pending_jobs_for_role(paths, role_key)
        closed = _supersede_pending_for_role(
            paths,
            role_key,
            reason=(
                "Superseded by newer live/mock scan with an updated finding set. "
                "Open the newest job for current evidence."
            ),
            cycle_id=cycle_id,
        )

        job_id = _new_id("job")
        _emit_evidence_for_role(
            role_key,
            prior,
            findings_list,
            after_job_id=job_id,
            scan_report=scan_report,
            after_scan_path=str(scan_path),
        )
        job = {
            "job_id": job_id,
            "cycle_id": cycle_id,
            "created_at": _now(),
            "updated_at": _now(),
            "status": "pending_approval",
            "requires_approval": True,
            "auto_apply": False,
            "role": role_key,
            "title": ROLE_WORKERS[role_key]["title"],
            "fingerprint": fingerprint,
            "dedupe_hits": 0,
            "supersedes_job_ids": closed,
            "summary": {
                "total_findings": triage["total_findings"],
                "severity_counts": triage["severity_counts"],
                "risk_score": triage["risk_score"],
                "top_findings": triage["top_findings"],
            },
            "scan_report_path": str(scan_path),
            "kit_path": (triage.get("remediation") or {}).get("kit_path"),
            "remediation_mapped": (triage.get("remediation") or {}).get("mapped"),
            "remediation_unmapped": (triage.get("remediation") or {}).get("unmapped"),
            "proposal": triage["proposal"],
            "manager_decision": None,
            "manager_note": None,
            "license": LICENSE_HOOK,
        }
        # Link superseded jobs to the replacement id now that we know it.
        for old_id in closed:
            op = paths["jobs"] / f"{old_id}.json"
            if op.is_file():
                old = _read_json(op)
                old["replaced_by_job_id"] = job_id
                _write_json(op, old)
        _write_json(paths["jobs"] / f"{job_id}.json", job)
        jobs_created.append(job)
        triage["job_created"] = job_id
        if closed:
            triage["jobs_superseded"] = closed

    index = _read_json(paths["index"])
    pending = list(index.get("pending_job_ids") or [])
    open_fp = dict(index.get("open_fingerprints") or {})
    for job in jobs_created:
        if job["job_id"] not in pending:
            pending.append(job["job_id"])
        fp_key = f"{job['role']}:{job.get('fingerprint')}"
        open_fp[fp_key] = job["job_id"]
    index["pending_job_ids"] = pending
    index["open_fingerprints"] = open_fp
    if evidence_notes:
        index["last_evidence_id"] = evidence_notes[-1].get("evidence_id")
        index["evidence_count"] = int(index.get("evidence_count") or 0) + len(evidence_notes)
    index["last_cycle_id"] = cycle_id
    index["updated_at"] = _now()
    index["license"] = LICENSE_HOOK
    index["version"] = VERSION
    _write_json(paths["index"], index)

    _append_audit(
        paths,
        {
            "event": "cycle_completed",
            "cycle_id": cycle_id,
            "mode": "mock" if mock else "live",
            "roles": roles,
            "findings": all_findings_count,
            "jobs_created": [j["job_id"] for j in jobs_created],
            "jobs_deduped": jobs_deduped,
            "evidence_notes": [e.get("evidence_id") for e in evidence_notes],
            "errors": errors,
        },
    )

    # Critical/high alerts (local jsonl + optional webhook) — never auto-apply
    alerts_emitted: list[dict[str, Any]] = []
    try:
        import worker_alert

        alert_jobs: list[dict[str, Any]] = list(jobs_created)
        for d in jobs_deduped:
            jid = d.get("job_id")
            if not jid:
                continue
            jp = paths["jobs"] / f"{jid}.json"
            if jp.is_file():
                alert_jobs.append(_read_json(jp))
        alerts_emitted = worker_alert.emit_from_jobs(workspace, alert_jobs)
    except Exception as alert_exc:
        errors.append(f"alert_emit:{alert_exc}")

    cycle_doc = {
        "cycle_id": cycle_id,
        "created_at": _now(),
        "mode": "mock" if mock else "live",
        "roles": roles,
        "role_results": role_results,
        "jobs_created": [j["job_id"] for j in jobs_created],
        "jobs_deduped": jobs_deduped,
        "evidence_notes": [e.get("evidence_id") for e in evidence_notes],
        "errors": errors,
        "alerts_emitted": len(alerts_emitted),
        "totals": {
            "roles_run": len(roles),
            "jobs_pending_approval": len(jobs_created),
            "jobs_deduped": len(jobs_deduped),
            "findings": all_findings_count,
            "alerts": len(alerts_emitted),
            "evidence_notes": len(evidence_notes),
        },
        "license": LICENSE_HOOK,
    }
    _write_json(paths["cycles"] / f"{cycle_id}.json", cycle_doc)

    status = "failed" if (errors and not role_results) else "success"
    if errors and any(r.get("total_findings") for r in role_results):
        status = "success"  # partial ok

    # Optional LLM brief after cycle (B3). Uses pending jobs (created + still open).
    llm_brief = None
    if bool(params.get("llm")):
        pending_jobs = []
        idx_now = _read_json(paths["index"])
        for jid in idx_now.get("pending_job_ids") or []:
            jp = paths["jobs"] / f"{jid}.json"
            if jp.is_file():
                pending_jobs.append(_read_json(jp))
        # Prefer jobs from this cycle if any; else full pending queue.
        focus = jobs_created if jobs_created else pending_jobs
        llm_brief = _generate_and_store_brief(
            paths,
            jobs=focus,
            cycle=cycle_doc,
            provider=params.get("llm_provider"),
            model=params.get("llm_model"),
            mode="brief",
        )
        cycle_doc["llm_brief_id"] = (llm_brief or {}).get("brief_id")
        _write_json(paths["cycles"] / f"{cycle_id}.json", cycle_doc)

    ciso_report = None
    try:
        import worker_report

        pending_for_ciso: list[dict[str, Any]] = []
        idx_ciso = _read_json(paths["index"])
        for jid in idx_ciso.get("pending_job_ids") or []:
            jp = paths["jobs"] / f"{jid}.json"
            if jp.is_file():
                pending_for_ciso.append(_read_json(jp))
        ciso_report = worker_report.maybe_auto_ciso_on_milestone(
            workspace,
            pending_for_ciso,
            account="aws-live" if not mock else "lab-mock",
        )
        if ciso_report:
            idx_ciso["last_ciso_report_id"] = ciso_report.get("report_id")
            idx_ciso["updated_at"] = _now()
            _write_json(paths["index"], idx_ciso)
            cycle_doc["ciso_report_id"] = ciso_report.get("report_id")
            _write_json(paths["cycles"] / f"{cycle_id}.json", cycle_doc)
    except Exception as ciso_exc:
        errors.append(f"ciso_report:{ciso_exc}")

    report = _brain_report(
        action="cycle",
        status=status,
        error="; ".join(errors) if errors and status == "failed" else None,
        workspace=workspace,
        started=started,
        cycle=cycle_doc,
        jobs=jobs_created,
        warnings=errors if status == "success" and errors else None,
    )
    if llm_brief:
        report["metadata"]["llm_brief"] = llm_brief
    if evidence_notes:
        report["metadata"]["evidence_notes"] = evidence_notes
    if ciso_report:
        report["metadata"]["ciso_report"] = {
            "report_id": ciso_report.get("report_id"),
            "paths": ciso_report.get("paths"),
            "milestone_critical_high_clear": ciso_report.get("milestone_critical_high_clear"),
        }
    return report


def _generate_and_store_brief(
    paths: dict[str, Path],
    *,
    jobs: list[dict[str, Any]],
    cycle: dict[str, Any] | None = None,
    provider: str | None = None,
    model: str | None = None,
    mode: str = "brief",
) -> dict[str, Any]:
    evidence = ai_brain_llm.build_evidence_bundle(jobs=jobs, cycle=cycle, mode=mode)
    reasoned = ai_brain_llm.reason(
        evidence,
        provider=provider,
        model=model,
        allow_offline_fallback=True,
    )
    brief_id = _new_id("brief")
    doc = {
        "brief_id": brief_id,
        "created_at": _now(),
        "mode": mode,
        "job_ids": [j.get("job_id") for j in jobs],
        "provider_status": ai_brain_llm.provider_status(),
        "llm_meta": reasoned.get("meta"),
        "result": reasoned.get("result"),
        "ok": reasoned.get("ok"),
        "text": ai_brain_llm.format_brief_text(reasoned.get("result") or {}),
        "requires_manager_approval": True,
        "auto_apply": False,
    }
    _write_json(paths["briefs"] / f"{brief_id}.json", doc)
    _append_audit(
        paths,
        {
            "event": "llm_brief",
            "brief_id": brief_id,
            "provider": (reasoned.get("result") or {}).get("provider"),
            "fallback_used": (reasoned.get("meta") or {}).get("fallback_used"),
            "job_count": len(jobs),
            "ok": reasoned.get("ok"),
        },
    )
    index = _read_json(paths["index"])
    index["last_brief_id"] = brief_id
    index["updated_at"] = _now()
    _write_json(paths["index"], index)
    return doc


def list_pending(params: dict[str, Any]) -> dict[str, Any]:
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    index = _read_json(paths["index"])
    jobs = []
    for jid in index.get("pending_job_ids") or []:
        jp = paths["jobs"] / f"{jid}.json"
        if jp.is_file():
            jobs.append(_read_json(jp))
    report = _brain_report(
        action="pending",
        status="success",
        workspace=workspace,
        started=started,
        jobs=jobs,
        index=index,
    )
    if bool(params.get("llm")) and jobs:
        brief = _generate_and_store_brief(
            paths,
            jobs=jobs,
            provider=params.get("llm_provider"),
            model=params.get("llm_model"),
            mode="brief",
        )
        report["metadata"]["llm_brief"] = brief
    return report


def run_brief(params: dict[str, Any]) -> dict[str, Any]:
    """B3: LLM (or offline) manager/CEO brief over pending jobs or one job."""
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    index = _read_json(paths["index"])

    job_id = str(params.get("job_id") or "").strip()
    jobs: list[dict[str, Any]] = []
    if job_id:
        jp = paths["jobs"] / f"{job_id}.json"
        if not jp.is_file():
            return _brain_report(
                action="brief",
                status="failed",
                error=f"job not found: {job_id}",
                workspace=workspace,
                started=started,
            )
        jobs = [_read_json(jp)]
    else:
        for jid in index.get("pending_job_ids") or []:
            jp = paths["jobs"] / f"{jid}.json"
            if jp.is_file():
                jobs.append(_read_json(jp))

    if not jobs:
        return _brain_report(
            action="brief",
            status="failed",
            error="no pending jobs to brief — run: python ai_brain_agent.py cycle --mock",
            workspace=workspace,
            started=started,
            index=index,
        )

    cycle = None
    cid = index.get("last_cycle_id")
    if cid:
        cp = paths["cycles"] / f"{cid}.json"
        if cp.is_file():
            cycle = _read_json(cp)

    brief = _generate_and_store_brief(
        paths,
        jobs=jobs,
        cycle=cycle,
        provider=params.get("llm_provider"),
        model=params.get("llm_model"),
        mode=str(params.get("mode") or "brief"),
    )
    report = _brain_report(
        action="brief",
        status="success" if brief.get("ok") else "failed",
        workspace=workspace,
        started=started,
        jobs=jobs,
        index=_read_json(paths["index"]),
    )
    report["metadata"]["llm_brief"] = brief
    report["metadata"]["llm_provider_status"] = ai_brain_llm.provider_status()
    report["metadata"]["llm_summary"] = _ascii(
        f"Brain {VERSION} brief {brief.get('brief_id')} via "
        f"{(brief.get('result') or {}).get('provider')}. "
        f"Manager approval still required. Auto-apply forbidden."
    )
    return report


def decide_job(params: dict[str, Any], decision: str) -> dict[str, Any]:
    """Manager approve/reject — records decision only; never applies cloud changes."""
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    job_id = str(params.get("job_id") or "").strip()
    if not job_id:
        return _brain_report(
            action=decision,
            status="failed",
            error="missing job_id",
            workspace=workspace,
            started=started,
        )

    jp = paths["jobs"] / f"{job_id}.json"
    if not jp.is_file():
        return _brain_report(
            action=decision,
            status="failed",
            error=f"job not found: {job_id}",
            workspace=workspace,
            started=started,
        )

    job = _read_json(jp)
    if job.get("status") != "pending_approval":
        return _brain_report(
            action=decision,
            status="failed",
            error=f"job {job_id} is not pending_approval (status={job.get('status')})",
            workspace=workspace,
            started=started,
            jobs=[job],
        )

    # Load change-assurance report for cryptographic approval binding (no execution).
    assurance_report = None
    ca_approval = None
    try:
        from change_assurance.engine import load_or_assure
        from change_assurance import approval_integrity as ca_approval  # noqa: F811

        findings_for_ca: list[dict] = []
        scan_path = Path(str(job.get("scan_report_path") or ""))
        if scan_path.is_file():
            try:
                scan_doc = _read_json(scan_path)
                findings_for_ca = [f for f in (scan_doc.get("findings") or []) if isinstance(f, dict)]
            except Exception:
                findings_for_ca = []
        assurance_report = load_or_assure(workspace, job, findings_for_ca, refresh=False)
    except Exception as ca_exc:
        ca_approval = None
        job["assurance_bind_error"] = str(ca_exc)

    finding_decisions = params.get("finding_decisions") or {}
    if isinstance(finding_decisions, str):
        finding_decisions = {}
    # Default: map job-level decision onto primary finding when none provided
    if decision == "approve" and assurance_report and not finding_decisions:
        primary = assurance_report.get("primary_finding_id")
        focus = assurance_report.get("focus_finding_ids") or ([primary] if primary else [])
        finding_decisions = {str(fid): "approved" for fid in focus if fid}

    if decision == "approve":
        # Per-finding: job is not fully approved if any finding rejected/deferred
        fully = True
        if finding_decisions and assurance_report:
            try:
                from change_assurance.approval_integrity import job_fully_approved

                fully = job_fully_approved(
                    finding_decisions,
                    assurance_report.get("focus_finding_ids")
                    or [assurance_report.get("primary_finding_id")],
                )
            except Exception:
                fully = True
        if not fully:
            job["status"] = "partially_approved"
            job["manager_decision"] = "partial"
            job["apply_status"] = "not_executed"
            job["apply_note"] = (
                "Per-finding decisions recorded. Job is NOT fully approved — "
                "no execution authorization for the whole job."
            )
        else:
            job["status"] = "approved"
            job["manager_decision"] = "approved"
            job["approval_status"] = "APPROVED_FOR_EXECUTION"
            # Apply is intentionally NOT implemented — draft bundle only (dry-run).
            job["apply_status"] = "not_executed"
            job["apply_note"] = (
                "Manager approved the exact reviewed change (APPROVED_FOR_EXECUTION). "
                "Draft fix bundle may be written under brain_workspace/drafts/ (dry-run). "
                "Cloud/repo apply remains forbidden. Authorization is bound to approval hashes."
            )
            try:
                import worker_draft

                draft = worker_draft.create_draft_bundle(workspace, job, enabled=True)
                job["draft_dir"] = draft.get("draft_dir")
                job["draft_meta"] = draft.get("meta")
                if draft.get("ok"):
                    job["apply_note"] = (
                        f"APPROVED_FOR_EXECUTION. Dry-run draft at {draft.get('draft_dir')}. "
                        "No production apply. Binding sealed to artifact/change hashes."
                    )
            except Exception as draft_exc:
                job["draft_error"] = str(draft_exc)
    else:
        job["status"] = "rejected"
        job["manager_decision"] = "rejected"
        job["apply_status"] = "blocked"
        job["apply_note"] = "Manager rejected this proposal. No changes will be applied."

    # Seal approval binding to exact reviewed change (never executes).
    if ca_approval and assurance_report:
        try:
            binding = ca_approval.seal_manager_approval(
                job=job,
                assurance_report=assurance_report,
                decision=decision,
                finding_decisions=finding_decisions,
            )
            path = ca_approval.persist_binding(workspace, job_id, binding)
            job["approval_binding"] = binding
            job["approval_binding_path"] = str(path)
            job["finding_decisions"] = finding_decisions
            job["execution_authorized"] = bool(binding.get("execution_authorized")) and job.get(
                "status"
            ) == "approved"
            job["execution_performed"] = False
        except Exception as bind_exc:
            job["approval_binding_error"] = str(bind_exc)

    job["manager_note"] = params.get("note")
    job["updated_at"] = _now()
    job["decided_at"] = _now()
    _write_json(jp, job)

    index = _read_json(paths["index"])
    pending = [x for x in (index.get("pending_job_ids") or []) if x != job_id]
    index["pending_job_ids"] = pending
    # Clear open fingerprint so a future cycle can re-queue if findings persist.
    open_fp = dict(index.get("open_fingerprints") or {})
    fp_key = f"{job.get('role')}:{job.get('fingerprint')}"
    if open_fp.get(fp_key) == job_id:
        open_fp.pop(fp_key, None)
    index["open_fingerprints"] = open_fp
    if decision == "approve" and job.get("status") == "approved":
        approved = list(index.get("approved_job_ids") or [])
        if job_id not in approved:
            approved.append(job_id)
        index["approved_job_ids"] = approved
    elif decision != "approve":
        rejected = list(index.get("rejected_job_ids") or [])
        if job_id not in rejected:
            rejected.append(job_id)
        index["rejected_job_ids"] = rejected
    index["updated_at"] = _now()
    _write_json(paths["index"], index)

    _append_audit(
        paths,
        {
            "event": f"manager_{decision}",
            "job_id": job_id,
            "role": job.get("role"),
            "decision": decision,
            "note": params.get("note"),
            "kit_path": job.get("kit_path"),
            "findings": (job.get("summary") or {}).get("total_findings"),
            "apply_status": job.get("apply_status"),
            "approval_status": job.get("approval_status"),
            "execution_authorized": job.get("execution_authorized"),
            "execution_performed": False,
            "artifact_hash": (job.get("approval_binding") or {}).get("artifact_hash"),
            "change_hash": (job.get("approval_binding") or {}).get("change_hash"),
        },
    )

    return _brain_report(
        action=decision,
        status="success",
        workspace=workspace,
        started=started,
        jobs=[job],
        index=index,
    )


def brain_status(params: dict[str, Any]) -> dict[str, Any]:
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    index = _read_json(paths["index"])
    last_cycle = None
    cid = index.get("last_cycle_id")
    if cid:
        cp = paths["cycles"] / f"{cid}.json"
        if cp.is_file():
            last_cycle = _read_json(cp)
    return _brain_report(
        action="status",
        status="success",
        workspace=workspace,
        started=started,
        index=index,
        cycle=last_cycle,
    )


def show_job(params: dict[str, Any]) -> dict[str, Any]:
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    job_id = str(params.get("job_id") or "").strip()
    jp = paths["jobs"] / f"{job_id}.json"
    if not job_id or not jp.is_file():
        return _brain_report(
            action="show",
            status="failed",
            error=f"job not found: {job_id}",
            workspace=workspace,
            started=started,
        )
    return _brain_report(
        action="show",
        status="success",
        workspace=workspace,
        started=started,
        jobs=[_read_json(jp)],
    )


def generate_ciso_report(params: dict[str, Any]) -> dict[str, Any]:
    """On-demand official CISO posture report (markdown + json under reports/ciso/)."""
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    import worker_report

    pending_jobs: list[dict[str, Any]] = []
    index = _read_json(paths["index"])
    for jid in index.get("pending_job_ids") or []:
        jp = paths["jobs"] / f"{jid}.json"
        if jp.is_file():
            pending_jobs.append(_read_json(jp))
    doc = worker_report.write_ciso_report(
        workspace,
        pending_jobs=pending_jobs,
        account=params.get("account") or "aws-live",
        title=params.get("title"),
    )
    index["last_ciso_report_id"] = doc.get("report_id")
    index["updated_at"] = _now()
    _write_json(paths["index"], index)
    _append_audit(
        paths,
        {
            "event": "ciso_report_generated",
            "report_id": doc.get("report_id"),
            "milestone": doc.get("milestone_critical_high_clear"),
        },
    )
    report = _brain_report(
        action="ciso-report",
        status="success",
        workspace=workspace,
        started=started,
        index=index,
        jobs=pending_jobs,
    )
    report["metadata"]["ciso_report"] = doc
    report["metadata"]["llm_summary"] = (
        f"CISO report {doc.get('report_id')} written. "
        f"Open={doc.get('open', {}).get('total')} findings "
        f"(C:{doc.get('open', {}).get('critical')} H:{doc.get('open', {}).get('high')}). "
        f"Markdown: {(doc.get('paths') or {}).get('markdown')}"
    )
    return report


def list_audit(params: dict[str, Any]) -> dict[str, Any]:
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)
    limit = int(params.get("limit") or 20)
    lines = paths["audit"].read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    report = _brain_report(
        action="audit",
        status="success",
        workspace=workspace,
        started=started,
        index=_read_json(paths["index"]),
    )
    report["metadata"]["audit_events"] = events
    report["metadata"]["llm_summary"] = (
        f"Brain {VERSION} audit: showing {len(events)} recent events from {paths['audit']}."
    )
    return report


def run_watch(params: dict[str, Any]) -> dict[str, Any]:
    """
    Always-on Brain loop for the production floor.
    Runs cycle → sleep → cycle until stopped (Ctrl+C) or max_cycles reached.
    Manager still approves via pending/approve/reject (or Face later).
    """
    started = datetime.datetime.now(datetime.timezone.utc)
    workspace = Path(str(params.get("workspace") or DEFAULT_WORKSPACE)).expanduser()
    if not workspace.is_absolute():
        workspace = ROOT / workspace
    paths = _ensure_workspace(workspace)

    interval = int(params.get("interval_seconds") or DEFAULT_WATCH_INTERVAL_SECONDS)
    if interval < 5:
        interval = 5
    max_cycles = params.get("max_cycles")
    max_cycles_i = int(max_cycles) if max_cycles is not None else None

    cycle_params = dict(params)
    cycle_params["action"] = "cycle"

    watch_id = _new_id("watch")
    cycles_completed = 0
    last_cycle: dict[str, Any] | None = None
    stop_reason = "running"

    _write_json(
        paths["watch"],
        {
            "watch_id": watch_id,
            "status": "running",
            "started_at": _now(),
            "interval_seconds": interval,
            "max_cycles": max_cycles_i,
            "cycles_completed": 0,
            "brain_version": VERSION,
        },
    )
    _append_audit(
        paths,
        {
            "event": "watch_started",
            "watch_id": watch_id,
            "interval_seconds": interval,
            "max_cycles": max_cycles_i,
            "roles": params.get("roles") or DEFAULT_ROLES,
            "mock": bool(params.get("mock", True)),
        },
    )

    try:
        while True:
            print(
                f"[Brain watch {watch_id}] cycle #{cycles_completed + 1} starting "
                f"(interval={interval}s)...",
                flush=True,
            )
            result = run_cycle(cycle_params)
            cycles_completed += 1
            last_cycle = (result.get("metadata") or {}).get("cycle")
            totals = (last_cycle or {}).get("totals") or {}
            brief = (result.get("metadata") or {}).get("llm_brief") or {}
            brief_note = ""
            if brief:
                prov = (brief.get("result") or {}).get("provider")
                brief_note = f" llm_brief={brief.get('brief_id')} ({prov})"
            print(
                f"[Brain watch {watch_id}] cycle done: findings={totals.get('findings')} "
                f"new_jobs={totals.get('jobs_pending_approval')} "
                f"deduped={totals.get('jobs_deduped')} "
                f"status={result.get('execution', {}).get('status')}{brief_note}",
                flush=True,
            )
            if brief.get("text"):
                print("----- LLM / offline brief -----", flush=True)
                print(brief.get("text"), flush=True)
                print("--------------------------------", flush=True)
            _write_json(
                paths["watch"],
                {
                    "watch_id": watch_id,
                    "status": "running",
                    "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "updated_at": _now(),
                    "interval_seconds": interval,
                    "max_cycles": max_cycles_i,
                    "cycles_completed": cycles_completed,
                    "last_cycle_id": (last_cycle or {}).get("cycle_id"),
                    "brain_version": VERSION,
                },
            )

            if max_cycles_i is not None and cycles_completed >= max_cycles_i:
                stop_reason = "max_cycles_reached"
                break

            print(
                f"[Brain watch {watch_id}] sleeping {interval}s - "
                f"manager can approve with: python ai_brain_agent.py pending",
                flush=True,
            )
            time.sleep(interval)
    except KeyboardInterrupt:
        stop_reason = "interrupted_by_manager"
        print(f"\n[Brain watch {watch_id}] stopped by manager (Ctrl+C)", flush=True)

    _write_json(
        paths["watch"],
        {
            "watch_id": watch_id,
            "status": "stopped",
            "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stopped_at": _now(),
            "stop_reason": stop_reason,
            "interval_seconds": interval,
            "max_cycles": max_cycles_i,
            "cycles_completed": cycles_completed,
            "last_cycle_id": (last_cycle or {}).get("cycle_id"),
            "brain_version": VERSION,
        },
    )
    _append_audit(
        paths,
        {
            "event": "watch_stopped",
            "watch_id": watch_id,
            "stop_reason": stop_reason,
            "cycles_completed": cycles_completed,
        },
    )

    report = _brain_report(
        action="watch",
        status="success",
        workspace=workspace,
        started=started,
        cycle=last_cycle,
        index=_read_json(paths["index"]),
    )
    report["metadata"]["watch"] = {
        "watch_id": watch_id,
        "stop_reason": stop_reason,
        "cycles_completed": cycles_completed,
        "interval_seconds": interval,
    }
    report["metadata"]["llm_summary"] = (
        f"Brain {VERSION} watch {watch_id} stopped ({stop_reason}) after "
        f"{cycles_completed} cycle(s). Interval={interval}s. Manager approval still required."
    )
    return report


def _brain_report(
    *,
    action: str,
    status: str,
    workspace: Path,
    started: datetime.datetime,
    error: str | None = None,
    cycle: dict | None = None,
    jobs: list[dict] | None = None,
    index: dict | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    ended = datetime.datetime.now(datetime.timezone.utc)
    jobs = jobs or []
    pending_n = len([j for j in jobs if j.get("status") == "pending_approval"])
    if index:
        pending_n = len(index.get("pending_job_ids") or [])

    findings_proxy = []
    for j in jobs:
        findings_proxy.append(
            {
                "id": j.get("job_id"),
                "title": f"Brain job: {j.get('title')} ({j.get('status')})",
                "severity": "info" if j.get("status") != "pending_approval" else "high",
                "description": j.get("proposal") or "",
                "resource": {"type": "brain_job", "id": j.get("job_id"), "role": j.get("role")},
                "evidence": {
                    "job_id": j.get("job_id"),
                    "role": j.get("role"),
                    "status": j.get("status"),
                    "kit_path": j.get("kit_path"),
                    "summary": j.get("summary"),
                },
                "remediation": {
                    "requires_approval": True,
                    "steps": [
                        "Review the proposed hardening kit in the local workspace.",
                        "Run: python ai_brain_agent.py pending",
                        "Then: python ai_brain_agent.py approve JOB_ID   OR   reject JOB_ID",
                        "Apply remains disabled until a controlled actuation module ships.",
                    ],
                    "effort": "manager",
                },
            }
        )

    totals = (cycle or {}).get("totals") or {}
    llm = (
        f"Brain {VERSION} action={action} status={status}. "
        f"Workspace={workspace}. Pending approvals={pending_n}. "
        f"Cycle findings={totals.get('findings', 'n/a')}. "
        f"Jobs in this response={len(jobs)}. "
        f"Data plane=local; auto-apply=forbidden; manager approval required."
    )
    if error:
        llm = f"Brain {VERSION} action={action} FAILED: {error}"

    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {
            "timestamp": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round((ended - started).total_seconds(), 3),
            "target": str(workspace),
            "status": status,
            "mode": "brain",
            "action": action,
            "error": error,
        },
        "summary": {
            "total_findings": len(findings_proxy),
            "critical": 0,
            "high": pending_n if action in {"cycle", "pending", "status"} else 0,
            "medium": 0,
            "low": 0,
            "info": max(0, len(findings_proxy) - (pending_n if action in {"cycle", "pending", "status"} else 0)),
            "risk_score": 100 if pending_n == 0 else max(0, 100 - pending_n * 10),
            "checks_run": int(totals.get("roles_run") or 0),
            "checks_passed": 0,
            "pending_approvals": pending_n,
            "jobs_in_response": len(jobs),
        },
        "findings": findings_proxy,
        "metadata": {
            "llm_summary": _ascii(llm),
            "domain": DOMAIN,
            "subdomain": SUBDOMAIN,
            "sentinel": SENTINEL,
            "tier": TIER,
            "tags": TAGS,
            "brain_phase": "B3",
            "brain_llm": True,
            "workspace": str(workspace),
            "cycle": cycle,
            "jobs": jobs,
            "index": index,
            "warnings": warnings or [],
            "roles_available": DEFAULT_ROLES,
            "license": LICENSE_HOOK,
            "llm_provider_status": ai_brain_llm.provider_status(),
            "product_model": {
                "hands": "four role packs",
                "brain": "orchestrator + watch + LLM reasoning",
                "manager": "human approval gate",
                "face": "next",
                "billing": "subscription_rent (control plane later)",
                "data_plane": "customer_local",
            },
            "next_phase": "Face - manager GUI for pending approvals + briefs",
        },
    }


def run(params: dict | None = None) -> dict[str, Any]:
    """TOOL_STANDARDS entry point."""
    params = dict(params or {})
    action = str(params.get("action") or "cycle").lower().strip()
    if action in {"cycle", "run", "scan"}:
        return run_cycle(params)
    if action in {"watch", "serve"}:
        return run_watch(params)
    if action in {"pending", "list"}:
        return list_pending(params)
    if action in {"brief", "reason"}:
        params = dict(params)
        params["mode"] = "reason" if action == "reason" else params.get("mode") or "brief"
        return run_brief(params)
    if action == "approve":
        return decide_job(params, "approve")
    if action == "reject":
        return decide_job(params, "reject")
    if action == "status":
        return brain_status(params)
    if action == "show":
        return show_job(params)
    if action == "audit":
        return list_audit(params)
    if action in {"ciso-report", "ciso_report", "report"}:
        return generate_ciso_report(params)
    return _brain_report(
        action=action,
        status="failed",
        error=(
            f"unknown action '{action}'. "
            "use: cycle|watch|pending|brief|reason|approve|reject|status|show|audit|ciso-report"
        ),
        workspace=Path(str(params.get("workspace") or DEFAULT_WORKSPACE)),
        started=datetime.datetime.now(datetime.timezone.utc),
    )


def _print_human_cycle(result: dict[str, Any]) -> None:
    meta = result.get("metadata") or {}
    cycle = meta.get("cycle") or {}
    totals = cycle.get("totals") or {}
    print(f"Brain {VERSION} cycle={cycle.get('cycle_id')}")
    print(f"status={result.get('execution', {}).get('status')} workspace={meta.get('workspace')}")
    print(
        f"findings_total={totals.get('findings')} "
        f"jobs_new={totals.get('jobs_pending_approval')} "
        f"jobs_deduped={totals.get('jobs_deduped')}"
    )
    print("-" * 60)
    for rr in cycle.get("role_results") or []:
        extra = ""
        if rr.get("job_deduped"):
            extra = f" deduped_job={rr.get('job_deduped')}"
        elif rr.get("job_created"):
            extra = f" new_job={rr.get('job_created')}"
        print(
            f"  [{rr.get('role')}] {rr.get('title')}: "
            f"findings={rr.get('total_findings')} risk={rr.get('risk_score')} "
            f"kit_mapped={(rr.get('remediation') or {}).get('mapped')} "
            f"approval_needed={rr.get('manager_action_required')}{extra}"
        )
    jobs = meta.get("jobs") or []
    if jobs:
        print("-" * 60)
        print("New jobs queued for manager approval:")
        for j in jobs:
            print(
                f"  {j.get('job_id')}  role={j.get('role')}  "
                f"findings={j.get('summary', {}).get('total_findings')}"
            )
    brief = meta.get("llm_brief") or {}
    if brief.get("text"):
        print("-" * 60)
        print("LLM / offline brief:")
        print(brief["text"])
    print("-" * 60)
    print("Manager next steps:")
    print("  python ai_brain_agent.py brief")
    print("  python ai_brain_agent.py pending")
    print("  python ai_brain_agent.py approve JOB_ID_HERE")
    print("  python ai_brain_agent.py reject  JOB_ID_HERE")
    print("Production floor (always-on + brief):")
    print("  python ai_brain_agent.py watch --mock --interval 300 --llm")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sentinel Stacks Brain B3 — multi-role agent, watch loop, "
            "LLM reasoning (OpenAI/Anthropic/offline), manager approval"
        ),
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="cycle",
        choices=[
            "cycle",
            "watch",
            "pending",
            "brief",
            "reason",
            "approve",
            "reject",
            "status",
            "show",
            "audit",
            "run",
            "serve",
        ],
        help="Brain action (default: cycle)",
    )
    parser.add_argument("job_id", nargs="?", help="Job id for approve/reject/show/brief")
    parser.add_argument("--mock", action="store_true", default=False, help="Force mock Hands packs")
    parser.add_argument("--live", action="store_true", help="Do not force mock (use target if given)")
    parser.add_argument("--roles", default=",".join(DEFAULT_ROLES), help="Comma-separated roles")
    parser.add_argument("--target", default=None, help="Optional live target for packs")
    parser.add_argument("--workspace", default=str(DEFAULT_WORKSPACE), help="Local brain workspace")
    parser.add_argument("--no-remediate", action="store_true", help="Skip remediation kit drafting")
    parser.add_argument("--no-dedupe", action="store_true", help="Allow duplicate pending jobs")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Run LLM/offline brief after cycle/pending/watch cycles",
    )
    parser.add_argument(
        "--provider",
        default=None,
        choices=["openai", "anthropic", "offline"],
        help="LLM provider (default: auto from env keys, else offline)",
    )
    parser.add_argument("--model", default=None, help="Override LLM model name")
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_WATCH_INTERVAL_SECONDS,
        help=f"Watch sleep seconds between cycles (default {DEFAULT_WATCH_INTERVAL_SECONDS})",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Watch: stop after N cycles (omit for 24/7 until Ctrl+C)",
    )
    parser.add_argument("--json", action="store_true", help="Print full TOOL_STANDARDS JSON")
    parser.add_argument("--note", default=None, help="Manager note for approve/reject")
    parser.add_argument("--limit", type=int, default=20, help="Audit: number of recent events")

    args = parser.parse_args(argv)
    action = "cycle" if args.action == "run" else args.action
    if action == "serve":
        action = "watch"
    mock = True
    if args.live:
        mock = False
    if args.mock:
        mock = True
    # Default cycle/watch uses mock for safe offline demos.
    if action in {"cycle", "watch"} and not args.live and not args.mock:
        mock = True

    params: dict[str, Any] = {
        "action": action,
        "roles": args.roles,
        "mock": mock,
        "target": args.target,
        "workspace": args.workspace,
        "remediate": not args.no_remediate,
        "dedupe": not args.no_dedupe,
        "job_id": args.job_id,
        "note": args.note,
        "interval_seconds": args.interval,
        "max_cycles": args.max_cycles,
        "limit": args.limit,
        "llm": bool(args.llm) or action in {"brief", "reason"},
        "llm_provider": args.provider,
        "llm_model": args.model,
    }
    # Watch inherits --llm into each cycle.
    if action == "watch" and args.llm:
        params["llm"] = True

    result = run(params)

    human_actions = {
        "cycle",
        "pending",
        "status",
        "approve",
        "reject",
        "show",
        "audit",
        "watch",
        "brief",
        "reason",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    elif action == "cycle":
        _print_human_cycle(result)
        if result.get("execution", {}).get("status") == "failed":
            print(json.dumps(result, indent=2))
    elif action == "watch":
        watch = (result.get("metadata") or {}).get("watch") or {}
        print(
            f"Watch stopped: id={watch.get('watch_id')} "
            f"cycles={watch.get('cycles_completed')} reason={watch.get('stop_reason')}"
        )
        print("Check queue: python ai_brain_agent.py pending")
        print("LLM brief:   python ai_brain_agent.py brief")
        print("Audit trail: python ai_brain_agent.py audit")
    elif action == "pending":
        jobs = (result.get("metadata") or {}).get("jobs") or []
        print(f"Pending approvals: {len(jobs)}")
        for j in jobs:
            s = j.get("summary") or {}
            print(
                f"  {j.get('job_id')}  {j.get('role')}  findings={s.get('total_findings')}  "
                f"risk={s.get('risk_score')}  kit={j.get('kit_path')}"
            )
        if not jobs:
            print("  (none)")
        else:
            example = jobs[0].get("job_id")
            print(f"Example approve: python ai_brain_agent.py approve {example}")
        brief = (result.get("metadata") or {}).get("llm_brief") or {}
        if brief.get("text"):
            print("-" * 60)
            print(brief["text"])
    elif action in {"brief", "reason"}:
        if result.get("execution", {}).get("status") != "success":
            print(result.get("execution", {}).get("error") or "failed")
            return 1
        brief = (result.get("metadata") or {}).get("llm_brief") or {}
        print(f"Brief id: {brief.get('brief_id')}")
        print(f"Saved under: brain_workspace/briefs/{brief.get('brief_id')}.json")
        print("-" * 60)
        print(brief.get("text") or "(empty brief)")
        print("-" * 60)
        print("Remember: this is advice only. You still approve/reject jobs.")
    elif action == "status":
        idx = (result.get("metadata") or {}).get("index") or {}
        llm_st = (result.get("metadata") or {}).get("llm_provider_status") or {}
        print(f"Brain {VERSION} (B3 LLM + watch - Face next)")
        print(f"workspace: {result.get('metadata', {}).get('workspace')}")
        print(f"last_cycle: {idx.get('last_cycle_id')}")
        print(f"last_brief: {idx.get('last_brief_id')}")
        print(f"pending: {len(idx.get('pending_job_ids') or [])}")
        print(f"approved: {len(idx.get('approved_job_ids') or [])}")
        print(f"rejected: {len(idx.get('rejected_job_ids') or [])}")
        print(
            f"llm_provider: {llm_st.get('selected')} "
            f"(openai_key={llm_st.get('openai_key_present')} "
            f"anthropic_key={llm_st.get('anthropic_key_present')})"
        )
        print(f"data_plane: {LICENSE_HOOK['data_plane']}  entitlement: {LICENSE_HOOK['entitlement']}")
        print("Brief:     python ai_brain_agent.py brief")
        print("Always-on: python ai_brain_agent.py watch --mock --interval 300 --llm")
    elif action == "audit":
        events = (result.get("metadata") or {}).get("audit_events") or []
        print(f"Audit events (newest of last {len(events)}):")
        for ev in events:
            print(
                f"  {ev.get('timestamp')}  {ev.get('event')}  "
                f"{ev.get('job_id') or ev.get('cycle_id') or ev.get('watch_id') or ev.get('brief_id') or ''}"
            )
        if not events:
            print("  (none yet)")
    elif action in {"approve", "reject", "show"}:
        jobs = (result.get("metadata") or {}).get("jobs") or []
        if result.get("execution", {}).get("status") != "success":
            print(result.get("execution", {}).get("error") or "failed")
            return 1
        j = jobs[0] if jobs else {}
        print(f"{action} ok: {j.get('job_id')} status={j.get('status')}")
        if j.get("apply_note"):
            print(j["apply_note"])
    elif action not in human_actions:
        print(json.dumps(result, indent=2))

    return 0 if result.get("execution", {}).get("status") != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
