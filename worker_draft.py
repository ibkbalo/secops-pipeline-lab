# worker_draft.py
# Sentinel Stacks — draft fix bundle after manager Approve
# Writes dry-run patch artifacts under brain_workspace/drafts/ — never mutates prod.
# Optional future: open PR when SENTINEL_DRAFT_OPEN_PR=1 (still audited; default off).

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0-w1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in (name or "draft"))


def create_draft_bundle(
    workspace: Path | str,
    job: dict[str, Any],
    *,
    enabled: bool = True,
) -> dict[str, Any]:
    """
    After Approve: copy teaching kit snippets + a DRAFT_PR.md into drafts/<job_id>/.
    Does not push, merge, or apply to production.
    """
    if not enabled:
        return {"ok": False, "skipped": True, "reason": "draft disabled"}

    workspace = Path(workspace)
    drafts_root = workspace / "drafts"
    drafts_root.mkdir(parents=True, exist_ok=True)
    job_id = str(job.get("job_id") or "unknown")
    out_dir = drafts_root / _safe(job_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    role = job.get("role") or "unknown"
    kit_path = Path(str(job.get("kit_path") or ""))
    copied: list[str] = []
    kit_note = "No kit_path on job."

    if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
        extract_dir = out_dir / "kit_extract"
        extract_dir.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(kit_path, "r") as zf:
                # Prefer runbooks + configs only (teaching artifacts)
                for name in zf.namelist():
                    lower = name.lower().replace("\\", "/")
                    if lower.endswith("/") or lower.endswith("\\"):
                        continue
                    if not any(
                        part in lower
                        for part in ("runbooks/", "configs/", "terraform/", "readme.md", "manifest.json")
                    ):
                        continue
                    zf.extract(name, extract_dir)
                    copied.append(name)
            kit_note = f"Extracted {len(copied)} kit files from {kit_path.name}"
        except Exception as e:
            kit_note = f"Kit extract failed: {e}"
    elif kit_path.is_dir():
        kit_note = f"Kit dir present: {kit_path}"
    else:
        kit_note = f"Kit missing on disk: {kit_path}"

    summary = job.get("summary") or {}
    top = summary.get("top_findings") or []
    pr_body = f"""# Draft fix bundle — {job_id}

**Role:** {role}  
**Generated:** {_now()}  
**Engine:** worker_draft {VERSION}  

## Rules
- This is a **dry-run draft** after manager Approve.
- It does **NOT** auto-apply to production or open a PR unless explicitly enabled later.
- Follow runbooks under `kit_extract/runbooks/` (finding ID = filename).
- Use `kit_extract/configs/` as sample patches to adapt in a real change window.

## Job summary
- Findings: {summary.get('total_findings')}
- Severity: {json.dumps(summary.get('severity_counts') or {})}
- Kit: `{job.get('kit_path')}`
- Note: {kit_note}

## Top findings
"""
    for t in top[:15]:
        if isinstance(t, dict):
            pr_body += f"- `{t.get('id')}` ({t.get('severity')}): {t.get('title')}\n"

    pr_body += """
## Suggested PR title
`security({role}): remediate approved Sentinel job {job_id}`

## Checklist for implementer
1. Open matching runbook for each critical/high ID
2. Adapt config/terraform samples (replace REPLACE_*)
3. Open human PR in the target repo
4. Re-run gate / Brain cycle to verify findings clear
5. Attach evidence to the change ticket
""".format(role=role, job_id=job_id)

    (out_dir / "DRAFT_PR.md").write_text(pr_body, encoding="utf-8")
    meta = {
        "version": VERSION,
        "created_at": _now(),
        "job_id": job_id,
        "role": role,
        "kit_path": str(job.get("kit_path") or ""),
        "files_copied": copied[:100],
        "draft_dir": str(out_dir),
        "open_pr": False,
        "auto_apply": False,
        "note": kit_note,
    }
    (out_dir / "draft_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return {"ok": True, "draft_dir": str(out_dir), "meta": meta}
