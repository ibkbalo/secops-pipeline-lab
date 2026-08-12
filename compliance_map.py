# compliance_map.py
# Sentinel Stacks — map finding compliance tags → framework rollups + risk score
# Used by Face (and optionally Brain). Never auto-applies.

from __future__ import annotations

import re
from typing import Any

VERSION = "0.1.0-c1"

# Display order for Face compliance panel
FRAMEWORKS: list[tuple[str, re.Pattern[str]]] = [
    ("NIST", re.compile(r"NIST|800-53|AI\s*RMF", re.I)),
    ("ISO 27001", re.compile(r"ISO\s*27001", re.I)),
    ("CIS", re.compile(r"\bCIS\b", re.I)),
    ("SOC 2", re.compile(r"SOC\s*2|SOC2", re.I)),
    ("OWASP", re.compile(r"OWASP", re.I)),
    ("PCI DSS", re.compile(r"PCI", re.I)),
]

SEV_PENALTY = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def normalize_compliance(raw: Any) -> list[str]:
    """Flatten finding.compliance into a clean list of control strings."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        out: list[str] = []
        for x in raw:
            if isinstance(x, str) and x.strip():
                out.append(x.strip())
            elif isinstance(x, dict):
                label = x.get("id") or x.get("control") or x.get("name") or x.get("framework")
                if label:
                    out.append(str(label).strip())
        return out
    if isinstance(raw, dict):
        return [str(k) for k in raw.keys()]
    return []


def classify_control(tag: str) -> str:
    for name, rx in FRAMEWORKS:
        if rx.search(tag):
            return name
    return "Other"


def risk_score_from_counts(counts: dict[str, Any] | None) -> int:
    """100 = clean; subtract weighted severity hits (matches Brain spirit)."""
    counts = counts or {}
    score = 100
    for sev, pen in SEV_PENALTY.items():
        score -= int(counts.get(sev) or 0) * pen
    return max(0, min(100, score))


def risk_score_from_findings(findings: list[dict[str, Any]]) -> int:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return risk_score_from_counts(counts)


def risk_label(score: int) -> tuple[str, str]:
    """Return (label, css_class)."""
    if score >= 85:
        return "LOW", "risk-low"
    if score >= 60:
        return "MODERATE", "risk-med"
    if score >= 30:
        return "HIGH", "risk-high"
    return "CRITICAL", "risk-crit"


def job_risk_score(job: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> int:
    summary = job.get("summary") or {}
    existing = summary.get("risk_score")
    counts = summary.get("severity_counts") or {}
    has_hits = any(int(counts.get(k) or 0) > 0 for k in ("critical", "high", "medium", "low"))
    # Recompute when missing or stuck at 0 despite findings
    if existing is None or (int(existing or 0) == 0 and has_hits):
        if findings:
            return risk_score_from_findings(findings)
        return risk_score_from_counts(counts)
    return max(0, min(100, int(existing)))


def rollup_compliance(
    findings: list[dict[str, Any]],
    *,
    job_id: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """
    Group findings by compliance framework.
    Returns frameworks list + control → finding links.
    """
    by_fw: dict[str, dict[str, Any]] = {
        name: {"framework": name, "controls": {}, "finding_ids": set(), "critical": 0, "high": 0}
        for name, _ in FRAMEWORKS
    }
    by_fw["Other"] = {
        "framework": "Other",
        "controls": {},
        "finding_ids": set(),
        "critical": 0,
        "high": 0,
    }

    tagged = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        tags = normalize_compliance(f.get("compliance"))
        if not tags:
            continue
        tagged += 1
        fid = str(f.get("id") or "")
        sev = str(f.get("severity") or "info").lower()
        for tag in tags:
            fw = classify_control(tag)
            bucket = by_fw[fw]
            bucket["finding_ids"].add(fid)
            if sev == "critical":
                bucket["critical"] += 1
            elif sev == "high":
                bucket["high"] += 1
            controls = bucket["controls"]
            entry = controls.setdefault(
                tag,
                {"control": tag, "finding_ids": [], "severities": []},
            )
            if fid and fid not in entry["finding_ids"]:
                entry["finding_ids"].append(fid)
                entry["severities"].append(sev)

    frameworks: list[dict[str, Any]] = []
    for name, _ in FRAMEWORKS:
        b = by_fw[name]
        controls_list = sorted(
            b["controls"].values(),
            key=lambda c: (-len(c["finding_ids"]), c["control"]),
        )
        frameworks.append(
            {
                "framework": name,
                "control_count": len(controls_list),
                "finding_count": len(b["finding_ids"]),
                "critical": b["critical"],
                "high": b["high"],
                "controls": controls_list[:40],
            }
        )
    other = by_fw["Other"]
    if other["controls"]:
        frameworks.append(
            {
                "framework": "Other",
                "control_count": len(other["controls"]),
                "finding_count": len(other["finding_ids"]),
                "critical": other["critical"],
                "high": other["high"],
                "controls": sorted(
                    other["controls"].values(),
                    key=lambda c: (-len(c["finding_ids"]), c["control"]),
                )[:20],
            }
        )

    return {
        "version": VERSION,
        "job_id": job_id,
        "role": role,
        "findings_total": len(findings),
        "findings_with_compliance": tagged,
        "frameworks": frameworks,
        "frameworks_hit": [f["framework"] for f in frameworks if f["finding_count"] > 0],
    }


def fleet_compliance(jobs: list[dict[str, Any]], load_findings) -> dict[str, Any]:
    """
    Roll up compliance across pending jobs.
    load_findings(job) -> list[dict] with compliance tags.
    """
    all_findings: list[dict[str, Any]] = []
    job_risks: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        findings = load_findings(job) or []
        score = job_risk_score(job, findings)
        label, css = risk_label(score)
        job_risks.append(
            {
                "job_id": job.get("job_id"),
                "role": job.get("role"),
                "risk_score": score,
                "risk_label": label,
                "risk_class": css,
            }
        )
        for f in findings:
            if isinstance(f, dict):
                # keep job context lightly
                ff = dict(f)
                ff.setdefault("_job_id", job.get("job_id"))
                all_findings.append(ff)

    rollup = rollup_compliance(all_findings)
    # Fleet risk = worst (lowest) job score, or 100 if none
    scores = [j["risk_score"] for j in job_risks]
    fleet_score = min(scores) if scores else 100
    flabel, fcss = risk_label(fleet_score)
    rollup["fleet_risk_score"] = fleet_score
    rollup["fleet_risk_label"] = flabel
    rollup["fleet_risk_class"] = fcss
    rollup["job_risks"] = job_risks
    return rollup
