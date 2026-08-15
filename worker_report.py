# worker_report.py
# Sentinel Stacks — evidence notes (per fix) + CISO posture reports
# Local files under brain_workspace/reports/ — never auto-emails or mutates cloud.

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0-r1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _reports_dir(workspace: Path) -> Path:
    d = Path(workspace) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    (d / "evidence").mkdir(exist_ok=True)
    (d / "ciso").mkdir(exist_ok=True)
    return d


def _finding_key(f: dict[str, Any]) -> str:
    """Stable-ish key across ID renumbering: prefer title + engine."""
    title = str(f.get("title") or "").strip().lower()
    eng = str((f.get("evidence") or {}).get("engine") or "").strip().lower()
    return f"{eng}|{title}" if title else str(f.get("id") or "")


def _sev_counts(findings: list[dict]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity") or "info").lower()
        if s in out:
            out[s] += 1
    return out


def _load_findings(scan_path: str | Path | None) -> list[dict]:
    if not scan_path:
        return []
    p = Path(scan_path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    return [f for f in (data.get("findings") or []) if isinstance(f, dict)]


def cleared_findings(
    before: list[dict],
    after: list[dict],
) -> list[dict[str, Any]]:
    """Findings present before but not after (by title/engine key)."""
    after_keys = {_finding_key(f) for f in after if _finding_key(f)}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in before:
        key = _finding_key(f)
        if not key or key in after_keys or key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "description": f.get("description"),
                "engine": (f.get("evidence") or {}).get("engine"),
                "compliance": f.get("compliance") or [],
            }
        )
    return out


def write_evidence_note(
    workspace: Path | str,
    *,
    role: str,
    cleared: list[dict[str, Any]],
    cycle_id: str | None = None,
    before_job_id: str | None = None,
    after_job_id: str | None = None,
    account: str | None = None,
    scan_mode: str | None = None,
) -> dict[str, Any] | None:
    """
    Per-fix audit evidence for CISO/ticket trail.
    One note can cover one or many cleared findings from a re-scan.
    """
    if not cleared:
        return None

    workspace = Path(workspace)
    root = _reports_dir(workspace)
    eid = f"evidence_{_stamp()}_{role.replace('-', '_')}"
    created = _now()
    titles = [str(c.get("title") or c.get("id") or "finding") for c in cleared]

    md_lines = [
        f"# Fix evidence — {role}",
        "",
        f"- **Evidence ID:** `{eid}`",
        f"- **Generated:** {created}",
        f"- **Agent role:** {role}",
        f"- **Account / target:** {account or 'n/a'}",
        f"- **Scan mode:** {scan_mode or 'n/a'}",
        f"- **Cycle:** {cycle_id or 'n/a'}",
        f"- **Prior job:** {before_job_id or 'n/a'}",
        f"- **Current job:** {after_job_id or 'n/a'}",
        "",
        "## Cleared findings",
        "",
    ]
    for c in cleared:
        md_lines.append(f"### {c.get('id') or '—'} — {c.get('title')}")
        md_lines.append(f"- **Severity (when open):** {c.get('severity')}")
        if c.get("description"):
            md_lines.append(f"- **Was:** {c.get('description')}")
        if c.get("compliance"):
            md_lines.append(f"- **Frameworks:** {', '.join(str(x) for x in c['compliance'][:8])}")
        md_lines.append("- **Status now:** Cleared on re-scan (read-only verify)")
        md_lines.append("")

    md_lines.extend(
        [
            "## Verification",
            "",
            "1. Manager / implementer applied the approved hardening plan (outside the agent).",
            "2. Cloud/DevSecOps agent re-scanned read-only.",
            "3. These titles no longer appear in the latest finding set.",
            "",
            "## Notes",
            "",
            "- Sentinel Stacks does **not** auto-apply cloud changes.",
            "- This note is local audit evidence for tickets / CISO packs.",
            "",
        ]
    )

    doc = {
        "version": VERSION,
        "type": "fix_evidence",
        "evidence_id": eid,
        "created_at": created,
        "role": role,
        "account": account,
        "scan_mode": scan_mode,
        "cycle_id": cycle_id,
        "before_job_id": before_job_id,
        "after_job_id": after_job_id,
        "cleared_count": len(cleared),
        "cleared": cleared,
        "summary": f"Cleared {len(cleared)} finding(s): " + "; ".join(titles[:6]),
    }

    json_path = root / "evidence" / f"{eid}.json"
    md_path = root / "evidence" / f"{eid}.md"
    json_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    doc["paths"] = {"json": str(json_path), "markdown": str(md_path)}
    return doc


def write_ciso_report(
    workspace: Path | str,
    *,
    pending_jobs: list[dict[str, Any]] | None = None,
    evidence_notes: list[dict[str, Any]] | None = None,
    account: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """
    Official CISO posture report: open risk + recent fix evidence.
    Generate on demand, or after a milestone (e.g. critical/high cleared).
    """
    workspace = Path(workspace)
    root = _reports_dir(workspace)
    rid = f"ciso_{_stamp()}"
    created = _now()
    pending_jobs = pending_jobs or []
    evidence_notes = evidence_notes or list_evidence(workspace, limit=50)

    open_crit = 0
    open_high = 0
    open_total = 0
    by_role: dict[str, dict[str, int]] = {}
    for j in pending_jobs:
        role = str(j.get("role") or "unknown")
        s = j.get("summary") or {}
        counts = s.get("severity_counts") or {}
        c = int(counts.get("critical") or 0)
        h = int(counts.get("high") or 0)
        t = int(s.get("total_findings") or 0)
        open_crit += c
        open_high += h
        open_total += t
        slot = by_role.setdefault(role, {"critical": 0, "high": 0, "total": 0, "jobs": 0})
        slot["critical"] += c
        slot["high"] += h
        slot["total"] += t
        slot["jobs"] += 1

    cleared_total = sum(int(e.get("cleared_count") or 0) for e in evidence_notes)
    milestone = open_crit == 0 and open_high == 0

    report_title = title or (
        "CISO posture improvement report — critical/high cleared"
        if milestone
        else "CISO cloud security posture report"
    )

    md: list[str] = [
        f"# {report_title}",
        "",
        f"- **Report ID:** `{rid}`",
        f"- **Generated:** {created}",
        f"- **Account / scope:** {account or 'local workspace / live AWS when configured'}",
        f"- **Generator:** Sentinel Stacks worker_report {VERSION}",
        "",
        "## Executive summary",
        "",
        f"Open findings in pending manager jobs: **{open_total}** "
        f"(**{open_crit}** critical / **{open_high}** high).",
        f"Fix evidence notes on file: **{len(evidence_notes)}** "
        f"(**{cleared_total}** finding clearances recorded).",
        "",
    ]
    if milestone:
        md.append(
            "**Milestone:** No critical or high findings remain in open jobs. "
            "Remaining medium/low items (if any) can be scheduled or accepted as risk."
        )
        md.append("")
    else:
        md.append(
            "**Recommendation:** Prioritize remaining critical/high items; "
            "use agent kits for implementers; re-scan after each change."
        )
        md.append("")

    md.extend(["## Open risk by agent", ""])
    if not by_role:
        md.append("_No pending jobs — inbox clear or not yet scanned._")
        md.append("")
    else:
        for role, slot in sorted(by_role.items()):
            md.append(
                f"- **{role}:** {slot['jobs']} open job(s), "
                f"{slot['total']} findings "
                f"(C:{slot['critical']} H:{slot['high']})"
            )
        md.append("")

    md.extend(["## Recent fix evidence", ""])
    if not evidence_notes:
        md.append("_No fix evidence notes yet. Re-scan after remediations to generate them._")
        md.append("")
    else:
        for e in evidence_notes[:15]:
            md.append(
                f"- `{e.get('evidence_id')}` — {e.get('summary') or e.get('role')} "
                f"({e.get('created_at')})"
            )
        md.append("")

    md.extend(
        [
            "## Control statement",
            "",
            "- Agents operate **read-only** against cloud/code targets.",
            "- Hardening kits are **proposals**; managers approve; humans/pipelines apply.",
            "- Auto-apply to production is **forbidden** in this product model.",
            "",
            "## Next actions",
            "",
            "1. Clear remaining critical/high via Face jobs + kits.",
            "2. Re-run AI cycle after each material change (evidence auto-writes).",
            "3. Regenerate this CISO report at engagement milestones.",
            "",
        ]
    )

    doc = {
        "version": VERSION,
        "type": "ciso_report",
        "report_id": rid,
        "created_at": created,
        "title": report_title,
        "account": account,
        "milestone_critical_high_clear": milestone,
        "open": {
            "total": open_total,
            "critical": open_crit,
            "high": open_high,
            "by_role": by_role,
            "pending_job_ids": [j.get("job_id") for j in pending_jobs],
        },
        "evidence": {
            "notes": len(evidence_notes),
            "cleared_findings_recorded": cleared_total,
            "recent_ids": [e.get("evidence_id") for e in evidence_notes[:15]],
        },
    }

    json_path = root / "ciso" / f"{rid}.json"
    md_path = root / "ciso" / f"{rid}.md"
    json_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    md_path.write_text("\n".join(md), encoding="utf-8")
    doc["paths"] = {"json": str(json_path), "markdown": str(md_path)}
    return doc


def list_evidence(workspace: Path | str, limit: int = 20) -> list[dict[str, Any]]:
    root = _reports_dir(Path(workspace)) / "evidence"
    files = sorted(root.glob("evidence_*.json"), reverse=True)
    out: list[dict[str, Any]] = []
    for p in files[:limit]:
        try:
            out.append(json.loads(p.read_text(encoding="utf-8-sig")))
        except Exception:
            continue
    return out


def list_ciso_reports(workspace: Path | str, limit: int = 10) -> list[dict[str, Any]]:
    root = _reports_dir(Path(workspace)) / "ciso"
    files = sorted(root.glob("ciso_*.json"), reverse=True)
    out: list[dict[str, Any]] = []
    for p in files[:limit]:
        try:
            out.append(json.loads(p.read_text(encoding="utf-8-sig")))
        except Exception:
            continue
    return out


def maybe_auto_ciso_on_milestone(
    workspace: Path | str,
    pending_jobs: list[dict[str, Any]],
    *,
    account: str | None = None,
) -> dict[str, Any] | None:
    """If no critical/high remain in pending jobs, write a milestone CISO report."""
    crit = 0
    high = 0
    for j in pending_jobs:
        counts = ((j.get("summary") or {}).get("severity_counts") or {})
        crit += int(counts.get("critical") or 0)
        high += int(counts.get("high") or 0)
    if crit or high:
        return None
    # Only auto if we have at least one evidence note (something was fixed).
    notes = list_evidence(workspace, limit=5)
    if not notes:
        return None
    return write_ciso_report(
        workspace,
        pending_jobs=pending_jobs,
        evidence_notes=list_evidence(workspace, limit=50),
        account=account,
        title="CISO posture improvement report — critical/high cleared",
    )
