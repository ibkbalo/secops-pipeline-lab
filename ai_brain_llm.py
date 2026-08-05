# ai_brain_llm.py
# Sentinel Stacks — Brain LLM reasoning node (B3)
# TOOL_STANDARDS companion for ai_brain_agent.py
#
# Role: reason over Hands evidence + pending jobs.
# Does NOT scan. Does NOT apply fixes. Never auto-approves.
#
# Providers:
#   - openai      (OPENAI_API_KEY)
#   - anthropic   (ANTHROPIC_API_KEY)
#   - offline     (deterministic heuristic when no key / force offline)
#
# Customer-local model: keys come from environment in the customer VPC.

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

VERSION = "0.3.0-b3"
DEFAULT_OPENAI_MODEL = os.environ.get("SENTINEL_OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_ANTHROPIC_MODEL = os.environ.get("SENTINEL_ANTHROPIC_MODEL", "claude-3-5-haiku-latest")

SYSTEM_PROMPT = """You are the Sentinel Stacks Brain — an enterprise security workforce agent.
You advise a human manager. You never apply changes yourself.

Rules:
1) Only use the evidence provided (finding IDs, severities, roles, kit paths).
2) Every priority action must reference real job_id and finding IDs from the input.
3) recommendation must be one of: approve, reject, investigate.
4) requires_manager_approval must always be true.
5) auto_apply must always be false.
6) Be concise, executive-ready, and specific. No invented CVEs or fake finding IDs.
7) Respond with ONLY valid JSON matching the schema.
"""


def detect_provider(preferred: str | None = None) -> str:
    """Pick provider: explicit preferred, else env keys, else offline."""
    pref = (preferred or os.environ.get("SENTINEL_LLM_PROVIDER") or "").strip().lower()
    if pref in {"offline", "none", "heuristic"}:
        return "offline"
    if pref == "openai" and os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if pref == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if pref in {"openai", "anthropic"} and not _key_for(pref):
        return "offline"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "offline"


def _key_for(provider: str) -> str | None:
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    return None


def provider_status() -> dict[str, Any]:
    return {
        "selected": detect_provider(),
        "openai_key_present": bool(os.environ.get("OPENAI_API_KEY")),
        "anthropic_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai_model": DEFAULT_OPENAI_MODEL,
        "anthropic_model": DEFAULT_ANTHROPIC_MODEL,
        "env_provider": os.environ.get("SENTINEL_LLM_PROVIDER"),
        "note": "Keys stay in local env (customer VPC). Brain never commits keys.",
    }


def _http_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: int = 60,
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"LLM HTTP {e.code}: {err_body}") from e
    except Exception as e:
        raise RuntimeError(f"LLM request failed: {e}") from e


def _extract_json_object(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty LLM response")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("no JSON object in LLM response")
    obj = json.loads(match.group(0))
    if not isinstance(obj, dict):
        raise ValueError("LLM JSON root must be object")
    return obj


def _schema_hint() -> dict[str, Any]:
    return {
        "executive_summary": "2-4 sentences for a manager/CISO",
        "ceo_brief": "short end-of-cycle brief for founder/CEO",
        "top_risks": [
            {
                "finding_id": "AISEC-PI-001",
                "role": "ai-security",
                "severity": "critical",
                "why_it_matters": "...",
            }
        ],
        "priority_actions": [
            {
                "job_id": "job_...",
                "role": "security-engineer",
                "finding_ids": ["PERIM-NET-001"],
                "recommendation": "approve",
                "why": "...",
            }
        ],
        "requires_manager_approval": True,
        "auto_apply": False,
        "confidence": "high|medium|low",
    }


def build_evidence_bundle(
    *,
    jobs: list[dict[str, Any]],
    cycle: dict[str, Any] | None = None,
    mode: str = "brief",
) -> dict[str, Any]:
    """Compact evidence for the LLM — finding IDs only from Hands/jobs."""
    compact_jobs = []
    for j in jobs:
        summary = j.get("summary") or {}
        top = summary.get("top_findings") or []
        finding_ids = [t.get("id") for t in top if isinstance(t, dict) and t.get("id")]
        compact_jobs.append(
            {
                "job_id": j.get("job_id"),
                "role": j.get("role"),
                "title": j.get("title"),
                "status": j.get("status"),
                "total_findings": summary.get("total_findings"),
                "severity_counts": summary.get("severity_counts"),
                "risk_score": summary.get("risk_score"),
                "top_findings": top[:8],
                "finding_ids": finding_ids,
                "kit_path": j.get("kit_path"),
                "remediation_mapped": j.get("remediation_mapped"),
                "proposal": j.get("proposal"),
            }
        )
    return {
        "mode": mode,
        "product": "Sentinel Stacks Brain",
        "rules": {
            "requires_manager_approval": True,
            "auto_apply_forbidden": True,
            "evidence_bound": True,
        },
        "cycle_totals": (cycle or {}).get("totals"),
        "pending_jobs": compact_jobs,
        "output_schema": _schema_hint(),
    }


def offline_reason(evidence: dict[str, Any]) -> dict[str, Any]:
    """Deterministic enterprise brief when no LLM key is available."""
    jobs = evidence.get("pending_jobs") or []
    top_risks: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    def sev_rank(s: str) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            (s or "info").lower(), 9
        )

    ranked_jobs = sorted(
        jobs,
        key=lambda j: (
            sev_rank(
                "critical"
                if (j.get("severity_counts") or {}).get("critical")
                else "high"
                if (j.get("severity_counts") or {}).get("high")
                else "medium"
            ),
            -(j.get("total_findings") or 0),
        ),
    )

    for j in ranked_jobs:
        counts = j.get("severity_counts") or {}
        fids = [x for x in (j.get("finding_ids") or []) if x][:5]
        for tf in j.get("top_findings") or []:
            if not isinstance(tf, dict):
                continue
            top_risks.append(
                {
                    "finding_id": tf.get("id"),
                    "role": j.get("role"),
                    "severity": tf.get("severity"),
                    "why_it_matters": tf.get("title") or "Evidence-backed Hands finding",
                }
            )
        crit = int(counts.get("critical") or 0)
        high = int(counts.get("high") or 0)
        if crit or high:
            rec = "approve"
            why = (
                f"{crit} critical / {high} high findings with dry-run kit ready. "
                "Review kit, then approve to accept the remediation plan "
                "(apply still manual/controlled later)."
            )
        elif (j.get("total_findings") or 0) > 0:
            rec = "investigate"
            why = "Medium/low findings present — confirm business impact before approve."
        else:
            rec = "reject"
            why = "No actionable findings in this job."
        actions.append(
            {
                "job_id": j.get("job_id"),
                "role": j.get("role"),
                "finding_ids": fids,
                "recommendation": rec,
                "why": why,
            }
        )

    total_findings = sum(int(j.get("total_findings") or 0) for j in jobs)
    roles = sorted({j.get("role") for j in jobs if j.get("role")})
    exec_summary = (
        f"Offline Brain brief (no LLM key): {len(jobs)} pending job(s) across "
        f"{', '.join(roles) or 'no roles'}; {total_findings} evidence-backed findings. "
        "Recommendations are heuristic from severity counts. Manager approval still required; "
        "auto-apply is forbidden."
    )
    ceo = (
        f"Workforce update: {len(jobs)} open approval(s), {total_findings} findings in queue. "
        "Next: review hardening kits, approve highest critical/high roles first."
    )
    return {
        "provider": "offline",
        "model": "heuristic-v1",
        "executive_summary": exec_summary,
        "ceo_brief": ceo,
        "top_risks": top_risks[:12],
        "priority_actions": actions,
        "requires_manager_approval": True,
        "auto_apply": False,
        "confidence": "medium",
        "evidence_bound": True,
    }


def _normalize_result(raw: dict[str, Any], provider: str, model: str) -> dict[str, Any]:
    out = {
        "provider": provider,
        "model": model,
        "executive_summary": str(raw.get("executive_summary") or "").strip(),
        "ceo_brief": str(raw.get("ceo_brief") or "").strip(),
        "top_risks": raw.get("top_risks") if isinstance(raw.get("top_risks"), list) else [],
        "priority_actions": (
            raw.get("priority_actions") if isinstance(raw.get("priority_actions"), list) else []
        ),
        "requires_manager_approval": True,  # forced
        "auto_apply": False,  # forced
        "confidence": str(raw.get("confidence") or "medium"),
        "evidence_bound": True,
    }
    if not out["executive_summary"]:
        out["executive_summary"] = "Brain LLM returned no executive summary."
    if not out["ceo_brief"]:
        out["ceo_brief"] = out["executive_summary"]
    # Sanitize recommendations
    clean_actions = []
    for a in out["priority_actions"]:
        if not isinstance(a, dict):
            continue
        rec = str(a.get("recommendation") or "investigate").lower()
        if rec not in {"approve", "reject", "investigate"}:
            rec = "investigate"
        clean_actions.append(
            {
                "job_id": a.get("job_id"),
                "role": a.get("role"),
                "finding_ids": a.get("finding_ids") or [],
                "recommendation": rec,
                "why": a.get("why") or "",
            }
        )
    out["priority_actions"] = clean_actions
    return out


def _call_openai(user_payload: dict[str, Any], model: str | None = None) -> dict[str, Any]:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY not set")
    model = model or DEFAULT_OPENAI_MODEL
    resp = _http_json(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        payload={
            "model": model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Analyze this Sentinel Stacks evidence bundle and return JSON.\n\n"
                        + json.dumps(user_payload, indent=2)
                    ),
                },
            ],
        },
    )
    content = (
        ((resp.get("choices") or [{}])[0].get("message") or {}).get("content")
        or ""
    )
    return _normalize_result(_extract_json_object(content), "openai", model)


def _call_anthropic(user_payload: dict[str, Any], model: str | None = None) -> dict[str, Any]:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    model = model or DEFAULT_ANTHROPIC_MODEL
    resp = _http_json(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        payload={
            "model": model,
            "max_tokens": 1800,
            "temperature": 0.2,
            "system": SYSTEM_PROMPT,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Analyze this Sentinel Stacks evidence bundle and return ONLY JSON.\n\n"
                        + json.dumps(user_payload, indent=2)
                    ),
                }
            ],
        },
    )
    parts = resp.get("content") or []
    text = ""
    for p in parts:
        if isinstance(p, dict) and p.get("type") == "text":
            text += p.get("text") or ""
    return _normalize_result(_extract_json_object(text), "anthropic", model)


def reason(
    evidence: dict[str, Any],
    *,
    provider: str | None = None,
    model: str | None = None,
    allow_offline_fallback: bool = True,
) -> dict[str, Any]:
    """
    Run Brain LLM reasoning over an evidence bundle.
    Returns structured recommendation JSON + meta.
    """
    selected = detect_provider(provider)
    meta: dict[str, Any] = {
        "requested_provider": provider,
        "selected_provider": selected,
        "fallback_used": False,
        "error": None,
        "version": VERSION,
    }

    if selected == "offline":
        result = offline_reason(evidence)
        return {"ok": True, "result": result, "meta": meta}

    try:
        if selected == "openai":
            result = _call_openai(evidence, model=model)
        elif selected == "anthropic":
            result = _call_anthropic(evidence, model=model)
        else:
            result = offline_reason(evidence)
        return {"ok": True, "result": result, "meta": meta}
    except Exception as e:
        meta["error"] = str(e)
        if not allow_offline_fallback:
            return {"ok": False, "result": None, "meta": meta}
        meta["fallback_used"] = True
        result = offline_reason(evidence)
        result["executive_summary"] = (
            f"[Fallback after {selected} error] " + result["executive_summary"]
        )
        return {"ok": True, "result": result, "meta": meta}


def format_brief_text(result: dict[str, Any]) -> str:
    lines = [
        f"Provider: {result.get('provider')} ({result.get('model')})",
        f"Confidence: {result.get('confidence')}",
        "",
        "Executive summary:",
        str(result.get("executive_summary") or ""),
        "",
        "CEO brief:",
        str(result.get("ceo_brief") or ""),
        "",
        "Priority actions:",
    ]
    for a in result.get("priority_actions") or []:
        lines.append(
            f"  - [{a.get('recommendation')}] {a.get('job_id')} ({a.get('role')}) "
            f"findings={','.join(a.get('finding_ids') or []) or 'n/a'}"
        )
        if a.get("why"):
            lines.append(f"      why: {a.get('why')}")
    lines.append("")
    lines.append("Manager approval required: YES")
    lines.append("Auto-apply: NO")
    return "\n".join(lines)
