# worker_alert.py
# Sentinel Stacks — critical/high alert channel (customer-local)
# Writes brain_workspace/alerts/*.jsonl + optional webhook (SENTINEL_ALERT_WEBHOOK).
# Never auto-applies. Never pages prod changes.

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0-w1"
SEVERITIES = ("critical", "high")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _alerts_dir(workspace: Path) -> Path:
    d = Path(workspace) / "alerts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def emit_alert(
    workspace: Path | str,
    *,
    role: str,
    job_id: str | None,
    severity: str,
    title: str,
    finding_ids: list[str] | None = None,
    detail: str | None = None,
    source: str = "brain_cycle",
) -> dict[str, Any]:
    """Persist one alert locally; optionally POST to webhook."""
    workspace = Path(workspace)
    sev = (severity or "info").lower()
    event = {
        "timestamp": _now(),
        "version": VERSION,
        "role": role,
        "job_id": job_id,
        "severity": sev,
        "title": title,
        "finding_ids": finding_ids or [],
        "detail": detail or "",
        "source": source,
        "auto_apply": False,
    }
    path = _alerts_dir(workspace) / "alerts.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=True) + "\n")

    webhook = (os.environ.get("SENTINEL_ALERT_WEBHOOK") or "").strip()
    webhook_status = "skipped"
    if webhook and sev in SEVERITIES:
        try:
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                webhook,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                webhook_status = f"ok:{resp.status}"
        except Exception as e:
            webhook_status = f"error:{e}"
    event["webhook_status"] = webhook_status
    event["alert_path"] = str(path)
    return event


def emit_from_jobs(workspace: Path | str, jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create alerts for jobs with critical/high findings."""
    out: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        summary = job.get("summary") or {}
        counts = summary.get("severity_counts") or {}
        crit = int(counts.get("critical") or 0)
        high = int(counts.get("high") or 0)
        if crit <= 0 and high <= 0:
            continue
        top = summary.get("top_findings") or []
        fids = [t.get("id") for t in top if isinstance(t, dict) and t.get("id")]
        sev = "critical" if crit else "high"
        title = (
            f"{job.get('role')}: {crit} critical / {high} high — "
            f"job {job.get('job_id')} needs manager review"
        )
        out.append(
            emit_alert(
                workspace,
                role=str(job.get("role") or "unknown"),
                job_id=job.get("job_id"),
                severity=sev,
                title=title,
                finding_ids=[str(x) for x in fids if x],
                detail=str(job.get("proposal") or "")[:500],
                source="brain_cycle",
            )
        )
    return out


def list_alerts(workspace: Path | str, limit: int = 50) -> list[dict[str, Any]]:
    path = Path(workspace) / "alerts" / "alerts.jsonl"
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    events: list[dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(events) >= limit:
            break
    return events


def backlog_from_jobs(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten open job findings into a backlog list with age hints."""
    items: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        created = job.get("created_at") or job.get("updated_at") or ""
        summary = job.get("summary") or {}
        top = summary.get("top_findings") or []
        counts = summary.get("severity_counts") or {}
        items.append(
            {
                "job_id": job.get("job_id"),
                "role": job.get("role"),
                "status": job.get("status"),
                "created_at": created,
                "total_findings": summary.get("total_findings"),
                "critical": int(counts.get("critical") or 0),
                "high": int(counts.get("high") or 0),
                "top_finding_ids": [
                    t.get("id") for t in top if isinstance(t, dict) and t.get("id")
                ][:8],
                "kit_path": job.get("kit_path"),
                "sla_hint": (
                    "breach_risk"
                    if int(counts.get("critical") or 0) > 0
                    else "review_soon"
                    if int(counts.get("high") or 0) > 0
                    else "normal"
                ),
            }
        )
    items.sort(
        key=lambda x: (-(x.get("critical") or 0), -(x.get("high") or 0), str(x.get("created_at") or ""))
    )
    return items
