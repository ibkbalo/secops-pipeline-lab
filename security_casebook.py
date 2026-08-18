# security_casebook.py
# Sentinel Stacks — Completed Security Jobs / Security Casebook
# Immutable historical snapshots for audit, training, and portfolio evidence.
# Does not execute remediations or publish to social media.

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.1-cb2"

# Standardized execution / artifact enums (platform never auto-applies).
EXEC_TERRAFORM = "TERRAFORM"
EXEC_AWS_CONSOLE = "AWS_CONSOLE"
EXEC_AWS_CLI = "AWS_CLI"
EXEC_SCRIPT = "SCRIPT"
EXEC_MANUAL = "MANUAL"
EXEC_EXTERNAL_TOOL = "EXTERNAL_TOOL"
EXEC_NOT_EXECUTED = "NOT_EXECUTED"

ARTIFACT_TERRAFORM = "TERRAFORM"
ARTIFACT_CONFIG = "CONFIG"
ARTIFACT_RUNBOOK = "RUNBOOK"
ARTIFACT_SCRIPT = "SCRIPT"
ARTIFACT_OTHER = "OTHER"
ARTIFACT_NONE = "NONE"

# Cloud preference only — not automatic execution.
CLOUD_TERRAFORM_FIRST_POLICY = {
    "preferred_when_safe": EXEC_TERRAFORM,
    "auto_apply": False,
    "allows_manual_console": True,
    "sequence": [
        "Finding",
        "Direct evidence",
        "Terraform remediation generated",
        "terraform validate",
        "terraform plan",
        "Change Assurance",
        "Manager approval",
        "human-triggered terraform apply",
        "Cloud re-scan",
        "verification",
        "Casebook snapshot",
    ],
    "manual_allowed_when": [
        "Terraform is not appropriate",
        "existing infrastructure is not Terraform-managed",
        "provider limitations",
        "emergency/manual action required",
        "manager explicitly chooses another method",
    ],
}

ROLE_LABELS = {
    "cloud": "Cloud Security Engineer",
    "devsecops": "DevSecOps Engineer",
    "security-engineer": "Security Engineer",
    "ai-security": "AI Security Engineer",
}

DOMAIN_LABELS = {
    "cloud": "Cloud",
    "devsecops": "DevSecOps",
    "security-engineer": "Security Engineering",
    "ai-security": "AI Security",
}

STATUS_SUCCESS = "SUCCESS"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "FAILED"
STATUS_ACCEPTED_RISK = "ACCEPTED RISK"

CLASSIFICATION_LAB = "LAB"
CLASSIFICATION_CUSTOMER = "CUSTOMER"
CLASSIFICATION_INTERNAL = "INTERNAL"
CLASSIFICATION_DEMO = "DEMO"

# Password-policy control IDs used by the current Cloud pack.
IAM_PASSWORD_CONTROLS = (
    "CLOUD-IAM-001",
    "CLOUD-IAM-002",
    "CLOUD-IAM-003",
    "CLOUD-IAM-004",
    "CLOUD-IAM-005",
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _year() -> int:
    return datetime.now(timezone.utc).year


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def cases_root(workspace: Path | str) -> Path:
    root = Path(workspace) / "cases"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _index_path(workspace: Path | str) -> Path:
    return cases_root(workspace) / "index.json"


def load_index(workspace: Path | str) -> dict[str, Any]:
    path = _index_path(workspace)
    if not path.is_file():
        return {
            "version": VERSION,
            "created_at": _now(),
            "next_seq": 1,
            "case_ids": [],
            "by_job_id": {},
        }
    return _read_json(path)


def save_index(workspace: Path | str, index: dict[str, Any]) -> None:
    index = dict(index)
    index["version"] = VERSION
    index["updated_at"] = _now()
    _write_json(_index_path(workspace), index)


def next_case_id(workspace: Path | str, year: int | None = None) -> str:
    index = load_index(workspace)
    y = year or _year()
    seq = int(index.get("next_seq") or 1)
    return f"CASE-{y}-{seq:04d}"


def case_dir(workspace: Path | str, case_id: str) -> Path:
    safe = Path(str(case_id)).name
    if not re.fullmatch(r"CASE-\d{4}-\d{4}", safe):
        raise ValueError(f"invalid case_id: {case_id}")
    return cases_root(workspace) / safe


def load_case(workspace: Path | str, case_id: str) -> dict[str, Any] | None:
    path = case_dir(workspace, case_id) / "case.json"
    if not path.is_file():
        return None
    return _read_json(path)


def list_cases(workspace: Path | str) -> list[dict[str, Any]]:
    index = load_index(workspace)
    out: list[dict[str, Any]] = []
    for cid in index.get("case_ids") or []:
        case = load_case(workspace, cid)
        if case:
            out.append(case)
    out.sort(key=lambda c: str(c.get("created_at") or ""), reverse=True)
    return out


def severity_counts(findings: list[dict] | None) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        s = str(f.get("severity") or "info").lower()
        if s in out:
            out[s] += 1
        else:
            out["info"] += 1
    return out


def _finding_key(f: dict[str, Any]) -> str:
    fid = str(f.get("id") or "").strip()
    if fid:
        return f"id:{fid}"
    title = str(f.get("title") or f.get("name") or "").strip().lower()
    eng = str((f.get("evidence") or {}).get("engine") or "").strip().lower()
    return f"t:{eng}|{title}" if title else ""


def compute_scan_delta(
    before_findings: list[dict],
    after_findings: list[dict],
) -> dict[str, Any]:
    """Compare two finding sets. Cleared = present before, absent after."""
    before = [f for f in before_findings if isinstance(f, dict)]
    after = [f for f in after_findings if isinstance(f, dict)]
    after_keys = {_finding_key(f) for f in after if _finding_key(f)}
    cleared: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in before:
        key = _finding_key(f)
        if not key or key in after_keys or key in seen:
            continue
        seen.add(key)
        cleared.append(
            {
                "id": f.get("id"),
                "title": f.get("title") or f.get("name"),
                "severity": f.get("severity"),
                "description": f.get("description"),
                "control_id": f.get("control_id") or f.get("id"),
            }
        )
    remaining = [
        {
            "id": f.get("id"),
            "title": f.get("title") or f.get("name"),
            "severity": f.get("severity"),
        }
        for f in after
        if isinstance(f, dict)
    ]
    before_counts = severity_counts(before)
    after_counts = severity_counts(after)
    return {
        "before_total": len(before),
        "after_total": len(after),
        "before_severity": before_counts,
        "after_severity": after_counts,
        "cleared": cleared,
        "cleared_count": len(cleared),
        "remaining": remaining,
        "remaining_count": len(remaining),
        "cleared_control_ids": [str(c.get("id")) for c in cleared if c.get("id")],
    }


def _load_findings_from_scan(path: str | Path | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = _read_json(p)
    except Exception:
        return []
    return [f for f in (data.get("findings") or []) if isinstance(f, dict)]


def _snapshot_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a finding for historical accuracy (no live references)."""
    return deepcopy(f)


def redact_text(text: str) -> str:
    """Public/portfolio redaction — never claim secrets were published."""
    if not text:
        return text
    out = str(text)
    # AWS account IDs (12 digits), often prefixed
    out = re.sub(r"\baws-?\d{12}\b", "[AWS ACCOUNT REDACTED]", out, flags=re.I)
    out = re.sub(r"\b\d{12}\b", "[AWS ACCOUNT REDACTED]", out)
    # Access keys / tokens
    out = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[ACCESS KEY REDACTED]", out)
    out = re.sub(r"\bASIA[0-9A-Z]{16}\b", "[ACCESS KEY REDACTED]", out)
    out = re.sub(
        r"(?i)(aws_secret_access_key|secret_access_key|password|token|api[_-]?key)\s*[:=]\s*\S+",
        r"\1=[SECRET REDACTED]",
        out,
    )
    # ARNs with account / resource specificity
    out = re.sub(
        r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+",
        "[ARN REDACTED]",
        out,
        flags=re.I,
    )
    out = re.sub(r"arn:aws:[^\s\"']+", "[ARN REDACTED]", out, flags=re.I)
    # Private IPs
    out = re.sub(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b",
        "[PRIVATE IP REDACTED]",
        out,
    )
    # Local filesystem paths
    out = re.sub(r"[A-Za-z]:\\[^\s\"']+", "[PATH REDACTED]", out)
    out = re.sub(r"/home/[^\s\"']+", "[PATH REDACTED]", out)
    out = re.sub(r"/Users/[^\s\"']+", "[PATH REDACTED]", out)
    out = re.sub(r"C:\\DevSecOps-Lab[^\s\"']*", "[PATH REDACTED]", out)
    return out


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, dict):
        return {str(k): redact_obj(v) for k, v in value.items()}
    return value


def _password_policy_narrative(delta: dict[str, Any], before_findings: list[dict]) -> dict[str, Any]:
    """Build human before/after lines for IAM password policy when those controls cleared."""
    cleared_ids = set(delta.get("cleared_control_ids") or [])
    pwd_cleared = [c for c in IAM_PASSWORD_CONTROLS if c in cleared_ids]
    if not pwd_cleared:
        return {"applicable": False}

    before_length = None
    policy_present = None
    for f in before_findings:
        if str(f.get("id")) not in IAM_PASSWORD_CONTROLS:
            continue
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        if "MinimumPasswordLength" in ev:
            try:
                before_length = int(ev.get("MinimumPasswordLength") or 0)
            except (TypeError, ValueError):
                before_length = None
            policy_present = before_length not in (None, 0)
            break

    before_lines = [
        f"{delta['before_total']} findings",
        f"{delta['before_severity'].get('high', 0)} High",
        f"{delta['before_severity'].get('medium', 0)} Medium",
        f"{delta['before_severity'].get('low', 0)} Low",
        "IAM password policy: Not configured"
        if before_length in (None, 0)
        else "IAM password policy: Present but below baseline",
        f"Minimum password length: {before_length if before_length not in (None, 0) else '8/default'}",
    ]
    after_lines = [
        f"{delta['after_total']} findings",
        f"{delta['after_severity'].get('high', 0)} High",
        f"{delta['after_severity'].get('medium', 0)} Medium",
        f"{delta['after_severity'].get('low', 0)} Low",
    ]
    if pwd_cleared:
        after_lines.append("IAM password policy: Configured")
        if "CLOUD-IAM-001" in pwd_cleared:
            after_lines.append("Minimum password length: 14")
        if "CLOUD-IAM-002" in pwd_cleared or "CLOUD-IAM-003" in pwd_cleared:
            after_lines.append("Complexity: uppercase, lowercase, number, symbol required")
        if "CLOUD-IAM-004" in pwd_cleared:
            after_lines.append("Password expiration: 90 days")
        if "CLOUD-IAM-005" in pwd_cleared:
            after_lines.append("Password reuse prevention: 24")
        after_lines.append(f"{len(pwd_cleared)} controls cleared")

    return {
        "applicable": True,
        "controls_cleared": pwd_cleared,
        "before_lines": before_lines,
        "after_lines": after_lines,
        "policy_present_before": policy_present,
        "minimum_length_before": before_length,
    }


def determine_status(
    *,
    delta: dict[str, Any],
    manager_decision: str | None,
    verification_passed: bool,
    intended_control_ids: list[str] | None = None,
) -> str:
    decision = str(manager_decision or "").lower()
    if decision in {"accepted_risk", "accept_risk", "risk_accepted"}:
        return STATUS_ACCEPTED_RISK
    if decision == "rejected" and not (delta.get("cleared_count") or 0):
        return STATUS_ACCEPTED_RISK

    cleared_ids = set(delta.get("cleared_control_ids") or [])
    intended = [c for c in (intended_control_ids or []) if c]
    if intended:
        hit = [c for c in intended if c in cleared_ids]
        if verification_passed and hit and len(hit) == len(intended):
            return STATUS_SUCCESS
        if hit:
            return STATUS_PARTIAL
        return STATUS_FAILED if verification_passed is False or not hit else STATUS_FAILED

    if verification_passed and (delta.get("cleared_count") or 0) > 0:
        return STATUS_SUCCESS
    if (delta.get("cleared_count") or 0) > 0:
        return STATUS_PARTIAL
    return STATUS_FAILED


def _plain_what_found(findings: list[dict], cleared: list[dict]) -> str:
    if cleared:
        titles = [str(c.get("title") or c.get("id")) for c in cleared[:8]]
        return (
            f"The scan identified {len(findings)} findings. "
            f"This case focuses on {len(cleared)} remediated control(s): "
            + "; ".join(titles)
            + "."
        )
    if not findings:
        return "No findings were recorded for this case."
    top = findings[0]
    return (
        f"The scan identified {len(findings)} findings. "
        f"Top issue: {top.get('title') or top.get('id')} "
        f"({top.get('severity')})."
    )


def _plain_why_mattered(cleared: list[dict], role: str) -> str:
    if any(str(c.get("id") or "").startswith("CLOUD-IAM-00") for c in cleared):
        return (
            "Weak or missing IAM password policy controls increase the chance of credential "
            "compromise for IAM users. Hardening length, complexity, age, and reuse reduces "
            "account takeover risk for human identities in the AWS account."
        )
    agent = ROLE_LABELS.get(role, role)
    return (
        f"Open findings from the {agent} increase residual risk until validated and remediated. "
        "This case records the investigation and verified outcome for audit and learning."
    )


def normalize_execution_method(value: str | None) -> str:
    if not value:
        return EXEC_NOT_EXECUTED
    raw = str(value).strip().upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "CONSOLE": EXEC_AWS_CONSOLE,
        "IAM_CONSOLE": EXEC_AWS_CONSOLE,
        "AWS_IAM_CONSOLE": EXEC_AWS_CONSOLE,
        "CLI": EXEC_AWS_CLI,
        "TF": EXEC_TERRAFORM,
        "TERRAFORM_APPLY": EXEC_TERRAFORM,
        "NONE": EXEC_NOT_EXECUTED,
        "NOT_APPLIED": EXEC_NOT_EXECUTED,
    }
    raw = aliases.get(raw, raw)
    allowed = {
        EXEC_TERRAFORM,
        EXEC_AWS_CONSOLE,
        EXEC_AWS_CLI,
        EXEC_SCRIPT,
        EXEC_MANUAL,
        EXEC_EXTERNAL_TOOL,
        EXEC_NOT_EXECUTED,
    }
    return raw if raw in allowed else EXEC_MANUAL


def infer_remediation_artifact_type(
    *,
    role: str,
    kit_path: str | None,
    artifacts: list | None,
    explicit: str | None = None,
) -> str:
    if explicit:
        return str(explicit).strip().upper()
    blob = " ".join(
        [
            str(kit_path or ""),
            json.dumps(artifacts or [], ensure_ascii=True),
        ]
    ).lower()
    if ".tf" in blob or "terraform" in blob:
        return ARTIFACT_TERRAFORM
    if ".yml" in blob or "runbook" in blob:
        return ARTIFACT_RUNBOOK
    if ".conf" in blob or "config" in blob:
        return ARTIFACT_CONFIG
    if role == "cloud":
        # Cloud kits are Terraform-first when representable; default preference marker only.
        return ARTIFACT_TERRAFORM
    return ARTIFACT_OTHER


def scope_control_ids(
    *,
    intended_control_ids: list[str] | None,
    cleared_control_ids: list[str] | None,
) -> list[str]:
    """Case control set = remediation scope only (intended, else verified clears)."""
    if intended_control_ids:
        return [str(c) for c in intended_control_ids if c]
    return [str(c) for c in (cleared_control_ids or []) if c]


def scope_finding_decisions(
    job_decisions: dict | None,
    case_control_ids: list[str],
    *,
    cleared_control_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Keep only manager decisions for controls in this remediation case.
    Unrelated job-level approvals must not leak into the case snapshot.
    """
    allowed = set(case_control_ids)
    src = job_decisions if isinstance(job_decisions, dict) else {}
    out: dict[str, Any] = {}
    for key, val in src.items():
        kid = str(key)
        if kid in allowed:
            out[kid] = val
    # Verified clears in scope count as approved for the case even if job omitted them.
    for cid in cleared_control_ids or []:
        if cid in allowed and cid not in out:
            out[cid] = "approved"
    # Preserve intended order
    ordered = {cid: out[cid] for cid in case_control_ids if cid in out}
    for cid, val in out.items():
        if cid not in ordered:
            ordered[cid] = val
    return ordered


def execution_summary_text(
    *,
    artifact_type: str,
    execution_method: str,
    case_control_ids: list[str] | None = None,
) -> str:
    """Distinguish artifact reviewed vs method actually used."""
    method = normalize_execution_method(execution_method)
    art = str(artifact_type or ARTIFACT_NONE).upper()
    controls = ""
    if case_control_ids and set(case_control_ids) >= set(IAM_PASSWORD_CONTROLS):
        controls = " CLOUD-IAM-001 through CLOUD-IAM-005"
    if art == ARTIFACT_TERRAFORM and method == EXEC_AWS_CONSOLE:
        return (
            "Terraform remediation reviewed and approved; equivalent configuration applied "
            f"through AWS IAM Console; verified by post-remediation live scan"
            f" ({controls.strip()})."
            if controls
            else "Terraform remediation reviewed and approved; equivalent configuration "
            "applied through AWS IAM Console; verified by post-remediation live scan."
        )
    if art == ARTIFACT_TERRAFORM and method == EXEC_TERRAFORM:
        return (
            "Terraform remediation reviewed, approved, and applied via human-triggered "
            "terraform apply (platform did not auto-apply); verified by post-remediation live scan."
        )
    if method == EXEC_NOT_EXECUTED:
        return "Remediation artifact reviewed; no execution recorded yet (platform does not auto-apply)."
    return (
        f"Remediation artifact ({art}) reviewed and approved; execution method: {method}; "
        "verified by post-remediation scan when clears are present."
    )


def _claims_terraform_applied(text: str) -> bool:
    t = text.lower()
    return "terraform applied" in t or "via terraform apply" in t or "terraform apply" in t


def _plain_remediation(cleared: list[dict], artifact_note: str | None) -> str:
    ids = [str(c.get("id")) for c in cleared if c.get("id")]
    if set(ids) >= set(IAM_PASSWORD_CONTROLS):
        return (
            "Approved consolidated AWS IAM account password policy covering "
            "CLOUD-IAM-001 through CLOUD-IAM-005: minimum length 14; require uppercase, "
            "lowercase, number, and symbol; max age 90 days; reuse prevention 24; "
            "allow users to change their own password."
        )
    if ids:
        return (
            "Manager-approved remediation for: "
            + ", ".join(ids)
            + (f". {artifact_note}" if artifact_note else "")
        )
    return artifact_note or "Manager decision recorded; see Advanced for technical artifacts."


def _training_summary(case_title: str, cleared: list[dict], status: str) -> str:
    n = len(cleared)
    return (
        f"Practiced end-to-end security remediation on '{case_title}': "
        f"validate evidence, review Change Assurance, obtain manager approval, "
        f"apply the approved change outside the agent, and verify with a re-scan. "
        f"Outcome status {status} with {n} control(s) cleared by post-change evidence."
    )


def _interview_star(case: dict[str, Any]) -> dict[str, str]:
    cleared = (case.get("scan_delta") or {}).get("cleared") or []
    ids = [str(c.get("id")) for c in cleared if c.get("id")]
    before_n = (case.get("before") or {}).get("findings_total")
    after_n = (case.get("after") or {}).get("findings_total")
    classification = case.get("classification") or CLASSIFICATION_LAB
    ex = case.get("execution") or {}
    method = normalize_execution_method(ex.get("execution_method") or ex.get("method"))
    artifact = str(case.get("remediation_artifact_type") or ARTIFACT_OTHER).upper()
    lab_note = (
        "This was hands-on work in an AWS security lab environment (not customer employment)."
        if classification == CLASSIFICATION_LAB
        else "Work performed in the recorded environment classification."
    )
    situation = (
        f"{lab_note} An AI Cloud Security Engineer scan reported {before_n} findings "
        f"in the account posture."
        if case.get("domain") == "Cloud" or case.get("role") == "cloud"
        else f"{lab_note} A security agent scan reported {before_n} findings."
    )
    problem = case.get("narrative", {}).get("why_mattered") or "Open security findings required remediation."
    investigation = (
        "I reviewed the job findings, supporting evidence (observed vs expected), "
        "and Change Assurance blast-radius guidance before deciding."
    )
    evidence = (
        "Evidence was taken from live scanner output and stored evidence records on the case snapshot, "
        "not from memory alone."
    )
    remediation = case.get("narrative", {}).get("remediation_approved") or "Manager-approved remediation."
    risk = (
        (case.get("change_assurance_summary") or {}).get("recommendation")
        or "Reviewed impact and remediation risk prior to approval."
    )
    result = (
        f"Post-remediation re-scan proved {len(cleared)} finding(s) cleared"
        + (f" ({', '.join(ids)})." if ids else ".")
        + f" Findings went from {before_n} to {after_n}. Status: {case.get('status')}."
    )
    lessons = case.get("narrative", {}).get("training_summary") or ""
    if artifact == ARTIFACT_TERRAFORM and method == EXEC_AWS_CONSOLE:
        paragraph = (
            f"I identified posture gaps in an AWS security lab ({before_n} findings). "
            "I reviewed and validated a Terraform-based IAM hardening remediation, "
            "approved the account-wide change through the human-in-the-loop workflow, "
            "implemented the equivalent configuration in AWS IAM, and verified the result "
            f"with a live re-scan. Result: {len(cleared)} control(s) cleared ({before_n} → {after_n})."
        )
    elif artifact == ARTIFACT_TERRAFORM and method == EXEC_TERRAFORM:
        paragraph = (
            f"I identified posture gaps ({before_n} findings), reviewed a Terraform remediation, "
            "obtained manager approval, applied it with a human-triggered terraform apply "
            f"(not platform auto-apply), and re-scanned. Result: {len(cleared)} control(s) cleared "
            f"({before_n} → {after_n})."
        )
    else:
        paragraph = (
            f"I identified posture gaps in an AWS security lab ({before_n} findings). "
            f"I validated controls with scan evidence, reviewed remediation and blast radius, "
            f"obtained manager approval, applied the approved change, and re-scanned. "
            f"Result: {len(cleared)} control(s) cleared ({before_n} → {after_n})."
        )
    return {
        "situation": situation,
        "security_problem": problem,
        "investigation": investigation,
        "evidence": evidence,
        "remediation": remediation,
        "risk_considered": str(risk),
        "result": result,
        "lessons_learned": lessons,
        "paragraph": paragraph,
    }


def _portfolio_summary(case: dict[str, Any]) -> str:
    cleared = (case.get("scan_delta") or {}).get("cleared") or []
    n = len(cleared)
    title = case.get("title") or "Security remediation"
    classification = case.get("classification") or CLASSIFICATION_LAB
    ex = case.get("execution") or {}
    method = normalize_execution_method(ex.get("execution_method") or ex.get("method"))
    artifact = str(case.get("remediation_artifact_type") or ARTIFACT_OTHER).upper()
    if artifact == ARTIFACT_TERRAFORM and method == EXEC_AWS_CONSOLE:
        body = (
            "Reviewed and validated a Terraform-based IAM hardening remediation, approved the "
            "account-wide change through the human-in-the-loop workflow, implemented the "
            "equivalent configuration in AWS IAM, and verified the result with a live re-scan."
        )
    elif artifact == ARTIFACT_TERRAFORM and method == EXEC_TERRAFORM:
        body = (
            "Reviewed and validated a Terraform-based remediation, approved it through the "
            "human-in-the-loop workflow, applied it with a human-triggered terraform apply "
            "(platform did not auto-apply), and verified with a live re-scan."
        )
    else:
        body = (
            "Reviewed remediation and Change Assurance impact, approved through a human-in-the-loop "
            "workflow, applied the approved controls, and re-scanned to verify."
        )
    lines = [
        f"{title}",
        f"Classification: {classification}",
        "",
        f"Identified and validated findings using an AI {case.get('agent') or 'Security'} agent.",
        body,
        "",
        "Result:",
        f"{n} security finding(s) successfully cleared."
        if case.get("status") == STATUS_SUCCESS
        else f"Status {case.get('status')}: {n} finding(s) cleared.",
        "",
        "Skills practiced:",
        "Cloud Security" if case.get("role") == "cloud" else DOMAIN_LABELS.get(str(case.get("role")), "Security"),
        "Evidence validation",
        "Change Assurance",
        "Security remediation",
        "Change management",
        "Post-remediation verification",
        "Human-in-the-loop AI security",
    ]
    if any(str(c.get("id") or "").startswith("CLOUD-IAM") for c in cleared) or artifact == ARTIFACT_TERRAFORM:
        # Insert after Skills practiced header (index 10)
        insert_at = lines.index("Skills practiced:") + 1
        extra = ["AWS IAM", "Terraform review"] if case.get("role") == "cloud" else ["Terraform review"]
        for skill in reversed(extra):
            if skill not in lines:
                lines.insert(insert_at, skill)
    text = "\n".join(lines)
    if method != EXEC_TERRAFORM:
        # Safety: never claim Terraform execution in portfolio when method is not TERRAFORM.
        text = text.replace("Terraform applied", "Terraform reviewed")
        text = text.replace("terraform apply", "Terraform review")
        # Restore intentional "human-triggered terraform apply" only when method is TERRAFORM — already gated.
    return text


def _linkedin_draft(case: dict[str, Any]) -> str:
    delta = case.get("scan_delta") or {}
    cleared = delta.get("cleared") or []
    n = len(cleared)
    before_n = (case.get("before") or {}).get("findings_total")
    after_n = (case.get("after") or {}).get("findings_total")
    classification = case.get("classification") or CLASSIFICATION_LAB
    ex = case.get("execution") or {}
    method = normalize_execution_method(ex.get("execution_method") or ex.get("method"))
    artifact = str(case.get("remediation_artifact_type") or ARTIFACT_OTHER).upper()
    focus = "IAM password-policy hardening" if any(
        str(c.get("id") or "") in IAM_PASSWORD_CONTROLS for c in cleared
    ) else str(case.get("title") or "security remediation")
    opener = (
        "Completed another hands-on cloud security remediation in my AWS security lab."
        if classification == CLASSIFICATION_LAB and case.get("role") == "cloud"
        else f"Completed a hands-on security remediation ({classification})."
    )
    if artifact == ARTIFACT_TERRAFORM and method == EXEC_AWS_CONSOLE:
        middle = (
            "I reviewed and validated a Terraform-based remediation, approved the change "
            "through a human-in-the-loop workflow, implemented the equivalent configuration "
            "in AWS IAM, and re-scanned the environment."
        )
    elif artifact == ARTIFACT_TERRAFORM and method == EXEC_TERRAFORM:
        middle = (
            "I reviewed a Terraform remediation, obtained manager approval, applied it with a "
            "human-triggered terraform apply (not platform auto-apply), and re-scanned."
        )
    else:
        middle = (
            "I identified and validated findings, reviewed remediation and blast radius, "
            "applied the approved security controls, and re-scanned the environment."
        )
    return "\n".join(
        [
            opener,
            f"This scenario focused on {focus}.",
            middle,
            f"Before: {before_n} findings",
            f"After: {after_n} findings",
            f"Result: {n} control(s) cleared.",
            "",
            "Key areas practiced:",
            "AWS IAM · Cloud Security · Security Engineering · Terraform review · "
            "Human-in-the-loop AI security · Verification"
            if case.get("role") == "cloud"
            else "Security Engineering · Evidence validation · Change management · Verification",
            "",
            "(Draft only — not published automatically.)",
        ]
    )


def _load_sidecar(workspace: Path, job_id: str, folder: str) -> dict[str, Any] | None:
    path = Path(workspace) / folder / f"{job_id}.json"
    if path.is_file():
        try:
            return _read_json(path)
        except Exception:
            return None
    return None


def build_case_document(
    *,
    workspace: Path | str,
    case_id: str,
    job: dict[str, Any],
    before_findings: list[dict],
    after_findings: list[dict],
    after_scan_path: str | None = None,
    classification: str = CLASSIFICATION_LAB,
    title: str | None = None,
    intended_control_ids: list[str] | None = None,
    execution_method: str | None = None,
    remediation_artifact_type: str | None = None,
    remediation_description: str | None = None,
    changes_performed: str | None = None,
    verification_result: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace)
    role = str(job.get("role") or "unknown")
    job_id = str(job.get("job_id") or "")
    delta = compute_scan_delta(before_findings, after_findings)
    cleared = delta["cleared"]
    intended = intended_control_ids or [str(c.get("id")) for c in cleared if c.get("id")]
    case_control_ids = scope_control_ids(
        intended_control_ids=intended_control_ids,
        cleared_control_ids=list(delta.get("cleared_control_ids") or []),
    )
    # Narrow cleared list shown on the case to the remediation scope when intended is set.
    if intended_control_ids:
        allowed = set(case_control_ids)
        cleared = [c for c in cleared if str(c.get("id")) in allowed]
        delta = dict(delta)
        delta["cleared"] = cleared
        delta["cleared_count"] = len(cleared)
        delta["cleared_control_ids"] = [str(c.get("id")) for c in cleared if c.get("id")]

    assurance = _load_sidecar(workspace, job_id, "assurance") or {}
    impact = _load_sidecar(workspace, job_id, "impact") or {}
    approval = _load_sidecar(workspace, job_id, "approvals") or {}

    # Verification: only SUCCESS when post-scan proves clears.
    verified = (delta.get("cleared_count") or 0) > 0
    if intended:
        cleared_set = set(delta.get("cleared_control_ids") or [])
        verified = all(c in cleared_set for c in intended) and bool(intended)

    if verification_result:
        v_result = verification_result
    elif verified:
        v_result = "PASSED"
    elif (delta.get("cleared_count") or 0) > 0:
        v_result = "PARTIAL"
    else:
        v_result = "FAILED"

    status = determine_status(
        delta=delta,
        manager_decision=job.get("manager_decision") or job.get("status"),
        verification_passed=v_result == "PASSED",
        intended_control_ids=intended if intended_control_ids else None,
    )
    # If intended not provided but clears exist and v_result PASSED → SUCCESS already.
    if intended_control_ids is None and v_result == "PASSED" and cleared:
        status = STATUS_SUCCESS

    pwd_narrative = _password_policy_narrative(delta, before_findings)
    before_block = {
        "findings_total": delta["before_total"],
        "severity": delta["before_severity"],
        "findings": [_snapshot_finding(f) for f in before_findings],
        "scan_report_path_at_capture": job.get("scan_report_path"),
    }
    after_block = {
        "findings_total": delta["after_total"],
        "severity": delta["after_severity"],
        "findings": [_snapshot_finding(f) for f in after_findings],
        "scan_report_path_at_capture": after_scan_path,
    }

    ca_summary = {
        "recommendation": assurance.get("recommendation") or (impact.get("change_assurance") or {}).get("recommendation"),
        "validation_status": assurance.get("validation_status"),
        "blast_radius": assurance.get("blast_radius"),
        "remediation_risk": assurance.get("remediation_risk"),
        "deployment_ready": assurance.get("deployment_ready"),
        "finding_status": assurance.get("finding_status"),
        "primary_finding_id": assurance.get("primary_finding_id"),
    }

    artifact_note = None
    arts = assurance.get("artifacts") or []
    if arts and isinstance(arts[0], dict):
        artifact_note = arts[0].get("path") or arts[0].get("name")

    artifact_type = infer_remediation_artifact_type(
        role=role,
        kit_path=str(job.get("kit_path") or ""),
        artifacts=arts if isinstance(arts, list) else None,
        explicit=remediation_artifact_type,
    )
    exec_method = normalize_execution_method(execution_method)
    if execution_method is None:
        # Unknown historical apply method → do not invent TERRAFORM execution.
        exec_method = EXEC_NOT_EXECUTED
    exec_summary = execution_summary_text(
        artifact_type=artifact_type,
        execution_method=exec_method,
        case_control_ids=case_control_ids,
    )
    scoped_decisions = scope_finding_decisions(
        job.get("finding_decisions") or {},
        case_control_ids,
        cleared_control_ids=list(delta.get("cleared_control_ids") or []),
    )

    case_title = title or (
        "AWS IAM Password Policy Hardening"
        if set(IAM_PASSWORD_CONTROLS) <= set(case_control_ids)
        else str(job.get("title") or f"{ROLE_LABELS.get(role, role)} remediation")
    )

    default_changed = (
        exec_summary
        if exec_method != EXEC_NOT_EXECUTED
        else (
            "Approved remediation recorded; execution method not set "
            "(platform does not auto-apply)."
        )
    )

    narrative = {
        "what_found": _plain_what_found(before_findings, cleared),
        "why_mattered": _plain_why_mattered(cleared, role),
        "remediation_approved": remediation_description
        or _plain_remediation(cleared, artifact_note),
        "what_could_be_affected": (
            f"Change Assurance recommendation: {ca_summary.get('recommendation') or 'n/a'}. "
            "Review blast radius and remediation risk in the Advanced section."
        ),
        "what_changed": changes_performed or default_changed,
        "how_verified": (
            f"Post-remediation read-only re-scan compared against the original finding set. "
            f"Verification: {v_result}. Cleared control IDs in this case: "
            + ", ".join(delta.get("cleared_control_ids") or case_control_ids)
            + "."
        ),
        "result": (
            f"{delta['cleared_count']} finding(s) cleared in this remediation scope; "
            f"{delta['remaining_count']} remaining in the account scan. Status: {status}."
        ),
        "training_summary": "",
    }
    narrative["training_summary"] = _training_summary(case_title, cleared, status)

    remediated_ids = list(delta.get("cleared_control_ids") or case_control_ids)

    case: dict[str, Any] = {
        "version": VERSION,
        "type": "security_case",
        "case_id": case_id,
        "immutable": True,
        "created_at": _now(),
        "classification": classification,
        "title": case_title,
        "job_id": job_id,
        "role": role,
        "agent": ROLE_LABELS.get(role, role),
        "domain": DOMAIN_LABELS.get(role, role),
        "date": (job.get("decided_at") or job.get("updated_at") or job.get("created_at") or _now())[:10],
        "status": status,
        "verification_result": v_result,
        "verified": bool(verified and v_result == "PASSED"),
        "manager_decision": job.get("manager_decision") or job.get("status"),
        "manager_note": job.get("manager_note"),
        "finding_decisions": scoped_decisions,
        "findings_reviewed": len(scoped_decisions) or len(case_control_ids),
        "findings_remediated": len(remediated_ids),
        "controls": case_control_ids,
        "remediation_artifact_type": artifact_type,
        "execution_method": exec_method,
        "execution_performed_by_platform": False,
        "execution": {
            "authorized": bool(job.get("execution_authorized")),
            "performed": False,  # platform never auto-executes
            "execution_performed_by_platform": False,
            "execution_method": exec_method,
            "remediation_artifact_type": artifact_type,
            "remediation_artifact_reviewed": artifact_type != ARTIFACT_NONE,
            "method": exec_summary,
            "apply_status": job.get("apply_status") or "not_executed_by_platform",
            "changes_performed": changes_performed or narrative["what_changed"],
            "terraform_first_preference": role == "cloud",
        },
        "cloud_workflow_preference": CLOUD_TERRAFORM_FIRST_POLICY if role == "cloud" else None,
        "before": before_block,
        "after": after_block,
        "scan_delta": delta,
        "before_after_summary": pwd_narrative,
        "evidence_snapshot": {
            "findings": [
                _snapshot_finding(f)
                for f in before_findings
                if str(f.get("id") or "") in set(case_control_ids)
            ],
            "note": (
                "Historical copy of findings for controls in this remediation only. "
                "Account-wide before/after totals remain on before/after blocks."
            ),
        },
        "change_assurance_summary": ca_summary,
        "change_assurance_snapshot": deepcopy(assurance) if assurance else None,
        "impact_snapshot": deepcopy(impact) if impact else None,
        "approval_snapshot": deepcopy(approval) if approval else None,
        "approval_integrity": deepcopy(
            assurance.get("approval_binding")
            or job.get("approval_binding")
            or approval.get("approval_binding")
            or {}
        ),
        "ai_recommendation": ca_summary.get("recommendation"),
        "approved_artifact": {
            "kit_path": job.get("kit_path"),
            "type": artifact_type,
            "note": "Path recorded for audit; public exports redact filesystem paths.",
            "artifacts": deepcopy(arts[:20]) if arts else [],
        },
        "remediation_description": narrative["remediation_approved"],
        "narrative": narrative,
        "timestamps": {
            "job_created_at": job.get("created_at"),
            "job_decided_at": job.get("decided_at"),
            "case_created_at": _now(),
            "before_scan": job.get("scan_report_path"),
            "after_scan": after_scan_path,
        },
        "license_note": (
            "Local casebook record. Approve ≠ apply. No auto-publish. "
            "Cloud preference is Terraform-first when safe; platform never auto-applies."
        ),
    }
    case["interview"] = _interview_star(case)
    case["portfolio_summary"] = _portfolio_summary(case)
    case["linkedin_draft"] = _linkedin_draft(case)
    if extra:
        case["extra"] = deepcopy(extra)
    return case


def render_readme(case: dict[str, Any]) -> str:
    delta = case.get("scan_delta") or {}
    ba = case.get("before_after_summary") or {}
    lines = [
        f"# {case.get('title')}",
        "",
        f"- **Case ID:** `{case.get('case_id')}`",
        f"- **Job ID:** `{case.get('job_id')}`",
        f"- **Classification:** {case.get('classification')}",
        f"- **Agent:** {case.get('agent')}",
        f"- **Domain:** {case.get('domain')}",
        f"- **Date:** {case.get('date')}",
        f"- **Status:** {case.get('status')}",
        f"- **Verification:** {case.get('verification_result')}",
        f"- **Remediation artifact:** {case.get('remediation_artifact_type')}",
        f"- **Execution method:** {case.get('execution_method')}",
        f"- **Executed by platform:** {'Yes' if case.get('execution_performed_by_platform') else 'No'}",
        "",
        "## Summary",
        "",
        str((case.get("narrative") or {}).get("result") or ""),
        "",
        "## What was found?",
        "",
        str((case.get("narrative") or {}).get("what_found") or ""),
        "",
        "## Why it mattered",
        "",
        str((case.get("narrative") or {}).get("why_mattered") or ""),
        "",
        "## Remediation approved",
        "",
        str((case.get("narrative") or {}).get("remediation_approved") or ""),
        "",
        "## What changed",
        "",
        str((case.get("narrative") or {}).get("what_changed") or ""),
        "",
        "## Verification",
        "",
        str((case.get("narrative") or {}).get("how_verified") or ""),
        "",
        "## Before / After",
        "",
        "### BEFORE",
        "",
    ]
    for line in ba.get("before_lines") or [
        f"{(case.get('before') or {}).get('findings_total')} findings",
    ]:
        lines.append(f"- {line}")
    lines.extend(["", "### AFTER", ""])
    for line in ba.get("after_lines") or [
        f"{(case.get('after') or {}).get('findings_total')} findings",
    ]:
        lines.append(f"- {line}")
    lines.extend(
        [
            "",
            "## Controls cleared",
            "",
        ]
    )
    for c in delta.get("cleared") or []:
        lines.append(f"- `{c.get('id')}` — {c.get('title')} ({c.get('severity')})")
    if not delta.get("cleared"):
        lines.append("- (none — do not claim success without verification)")
    lines.extend(
        [
            "",
            "## Training notes",
            "",
            str((case.get("narrative") or {}).get("training_summary") or ""),
            "",
            "## Interview (short)",
            "",
            str((case.get("interview") or {}).get("paragraph") or ""),
            "",
            "---",
            f"_Generated by security_casebook {VERSION}. Immutable historical snapshot._",
            "",
        ]
    )
    return "\n".join(lines)


def render_internal_report(case: dict[str, Any]) -> str:
    delta = case.get("scan_delta") or {}
    ca = case.get("change_assurance_summary") or {}
    ba = case.get("before_after_summary") or {}
    narrative = case.get("narrative") or {}
    interview = case.get("interview") or {}
    lines = [
        f"# Internal Security Report — {case.get('case_id')}",
        "",
        "> INTERNAL USE ONLY — may contain account identifiers and paths.",
        "",
        "## Case information",
        "",
        f"- Case ID: `{case.get('case_id')}`",
        f"- Job ID: `{case.get('job_id')}`",
        f"- Title: {case.get('title')}",
        f"- Classification: {case.get('classification')}",
        f"- Agent: {case.get('agent')}",
        f"- Domain: {case.get('domain')}",
        f"- Date: {case.get('date')}",
        f"- Status: **{case.get('status')}**",
        f"- Verification: {case.get('verification_result')}",
        f"- Remediation artifact: {case.get('remediation_artifact_type')}",
        f"- Execution method: {case.get('execution_method')}",
        f"- Executed by platform: {'Yes' if case.get('execution_performed_by_platform') else 'No'}",
        "",
        "## Executive summary",
        "",
        narrative.get("result") or "",
        "",
        narrative.get("what_found") or "",
        "",
        "## Findings",
        "",
        f"Original findings: {(case.get('before') or {}).get('findings_total')}",
        f"Severity: {json.dumps((case.get('before') or {}).get('severity') or {})}",
        "",
    ]
    for f in ((case.get("before") or {}).get("findings") or [])[:40]:
        lines.append(f"- `{f.get('id')}` [{f.get('severity')}] {f.get('title')}")
    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "Observed vs expected values are preserved on each finding snapshot and Change Assurance record.",
            "",
            "## Remediation",
            "",
            narrative.get("remediation_approved") or "",
            "",
            f"Execution method: {(case.get('execution') or {}).get('method')}",
            f"Changes performed: {(case.get('execution') or {}).get('changes_performed')}",
            "",
            "## Impact analysis (Change Assurance)",
            "",
            f"- Recommendation: {ca.get('recommendation')}",
            f"- Validation: {ca.get('validation_status')}",
            f"- Deployment ready: {ca.get('deployment_ready')}",
            "",
            "## Manager decision",
            "",
            f"- Decision: {case.get('manager_decision')}",
            f"- Finding decisions: {json.dumps(case.get('finding_decisions') or {})}",
            f"- Note: {case.get('manager_note') or 'n/a'}",
            "",
            "## Before / After",
            "",
            "BEFORE:",
        ]
    )
    for line in ba.get("before_lines") or []:
        lines.append(f"- {line}")
    lines.append("AFTER:")
    for line in ba.get("after_lines") or []:
        lines.append(f"- {line}")
    lines.extend(
        [
            "",
            "## Verification",
            "",
            narrative.get("how_verified") or "",
            "",
            "### Cleared",
            "",
        ]
    )
    for c in delta.get("cleared") or []:
        lines.append(f"- `{c.get('id')}` — {c.get('title')}")
    lines.extend(
        [
            "",
            "### Remaining",
            "",
        ]
    )
    for r in (delta.get("remaining") or [])[:30]:
        lines.append(f"- `{r.get('id')}` — {r.get('title')} ({r.get('severity')})")
    lines.extend(
        [
            "",
            "## Lessons learned",
            "",
            narrative.get("training_summary") or "",
            "",
            "## Interview coaching",
            "",
            f"- Situation: {interview.get('situation')}",
            f"- Problem: {interview.get('security_problem')}",
            f"- Investigation: {interview.get('investigation')}",
            f"- Evidence: {interview.get('evidence')}",
            f"- Remediation: {interview.get('remediation')}",
            f"- Risk: {interview.get('risk_considered')}",
            f"- Result: {interview.get('result')}",
            "",
            "## Technical appendix",
            "",
            f"- Kit path: {(case.get('approved_artifact') or {}).get('kit_path')}",
            f"- Approval integrity keys: {list((case.get('approval_integrity') or {}).keys())}",
            f"- Case version: {case.get('version')}",
            "",
        ]
    )
    return "\n".join(str(x) for x in lines)


def render_public_report(case: dict[str, Any]) -> str:
    public_case = redact_obj(deepcopy(case))
    # Drop heavy internal snapshots from public markdown body
    for key in ("change_assurance_snapshot", "impact_snapshot", "approval_snapshot", "evidence_snapshot"):
        public_case.pop(key, None)
    if isinstance(public_case.get("before"), dict):
        public_case["before"] = {
            "findings_total": public_case["before"].get("findings_total"),
            "severity": public_case["before"].get("severity"),
            "findings": [
                {"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity")}
                for f in (public_case["before"].get("findings") or [])
            ],
        }
    if isinstance(public_case.get("after"), dict):
        public_case["after"] = {
            "findings_total": public_case["after"].get("findings_total"),
            "severity": public_case["after"].get("severity"),
        }
    narrative = public_case.get("narrative") or {}
    delta = public_case.get("scan_delta") or {}
    ba = public_case.get("before_after_summary") or {}
    lines = [
        f"# Public / Portfolio Report — {public_case.get('case_id')}",
        "",
        "> PUBLIC / PORTFOLIO VERSION — sensitive identifiers redacted. "
        f"Classification: **{public_case.get('classification')}**.",
        "",
        "Do not present lab work as customer employment.",
        "",
        "## Case information",
        "",
        f"- Case ID: `{public_case.get('case_id')}`",
        f"- Title: {public_case.get('title')}",
        f"- Agent: {public_case.get('agent')}",
        f"- Domain: {public_case.get('domain')}",
        f"- Date: {public_case.get('date')}",
        f"- Status: {public_case.get('status')}",
        f"- Remediation artifact: {public_case.get('remediation_artifact_type')}",
        f"- Execution method: {public_case.get('execution_method')}",
        f"- Executed by platform: No",
        "",
        "## Portfolio summary",
        "",
        public_case.get("portfolio_summary") or "",
        "",
        "## Executive summary",
        "",
        narrative.get("result") or "",
        "",
        "## What was found?",
        "",
        narrative.get("what_found") or "",
        "",
        "## Why it mattered",
        "",
        narrative.get("why_mattered") or "",
        "",
        "## Remediation",
        "",
        narrative.get("remediation_approved") or "",
        "",
        "## Before / After",
        "",
    ]
    for line in ba.get("before_lines") or []:
        lines.append(f"- BEFORE: {line}")
    for line in ba.get("after_lines") or []:
        lines.append(f"- AFTER: {line}")
    lines.extend(
        [
            "",
            "## Verification",
            "",
            narrative.get("how_verified") or "",
            "",
            "## Controls cleared",
            "",
        ]
    )
    for c in delta.get("cleared") or []:
        lines.append(f"- `{c.get('id')}` — {c.get('title')}")
    lines.extend(
        [
            "",
            "## Lessons learned",
            "",
            narrative.get("training_summary") or "",
            "",
            "## Interview explanation",
            "",
            (public_case.get("interview") or {}).get("paragraph") or "",
            "",
            "---",
            "_Public export generated with automatic redaction. Draft only — not published._",
            "",
        ]
    )
    return redact_text("\n".join(str(x) for x in lines))


def render_md_to_pdf_bytes(markdown: str, header_title: str) -> bytes:
    """Render markdown-ish text to PDF bytes using fpdf2."""
    from fpdf import FPDF

    class _PDF(FPDF):
        def __init__(self, header: str) -> None:
            super().__init__()
            self._header = header

        def header(self) -> None:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, self._ascii(self._header), align="C")
            self.ln(10)

        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

        @staticmethod
        def _ascii(text: str) -> str:
            repl = {
                "\u2014": "-",
                "\u2013": "-",
                "\u2192": "->",
                "\u2022": "*",
                "\u201c": '"',
                "\u201d": '"',
                "\u2018": "'",
                "\u2019": "'",
                "✅": "[OK]",
            }
            for s, d in repl.items():
                text = text.replace(s, d)
            return text.encode("ascii", "replace").decode("ascii")

        def _safe_multi(self, text: str, size: int = 10, style: str = "") -> None:
            self.set_x(self.l_margin)
            self.set_font("Helvetica", style, size)
            # Break very long tokens (paths, ARNs) so Helvetica layout never fails.
            parts: list[str] = []
            for word in text.split(" "):
                while len(word) > 90:
                    parts.append(word[:90])
                    word = word[90:]
                parts.append(word)
            self.multi_cell(0, 5, " ".join(parts))

    pdf = _PDF(header_title)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_margins(18, 18, 18)

    for raw in markdown.splitlines():
        line = raw.rstrip()
        safe = pdf._ascii(line)
        if not safe.strip():
            pdf.ln(3)
            continue
        if safe.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf._safe_multi(safe[2:], size=16, style="B")
            pdf.ln(2)
        elif safe.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            pdf._safe_multi(safe[3:], size=13, style="B")
            pdf.ln(1)
        elif safe.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf._safe_multi(safe[4:], size=11, style="B")
            pdf.ln(1)
        elif safe.lstrip().startswith("> "):
            pdf.set_text_color(80, 80, 80)
            pdf._safe_multi(safe.lstrip()[2:], size=9, style="I")
            pdf.set_text_color(30, 30, 30)
        elif safe.lstrip().startswith("- "):
            pdf._safe_multi("* " + safe.lstrip()[2:], size=10)
        else:
            pdf.set_text_color(30, 30, 30)
            plain = re.sub(r"\*\*(.+?)\*\*", r"\1", safe)
            plain = re.sub(r"`([^`]+)`", r"\1", plain)
            pdf._safe_multi(plain, size=10)
    return bytes(pdf.output())


def write_case_exports(case: dict[str, Any], directory: Path) -> dict[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    reports = directory / "reports"
    reports.mkdir(exist_ok=True)
    readme = render_readme(case)
    internal_md = render_internal_report(case)
    public_md = render_public_report(case)
    linkedin = case.get("linkedin_draft") or _linkedin_draft(case)
    interview = case.get("interview") or {}
    interview_md = "\n".join(
        [
            f"# Interview prep — {case.get('case_id')}",
            "",
            "## STAR / technical explanation",
            "",
            f"**Situation:** {interview.get('situation')}",
            "",
            f"**Security problem:** {interview.get('security_problem')}",
            "",
            f"**Investigation:** {interview.get('investigation')}",
            "",
            f"**Evidence:** {interview.get('evidence')}",
            "",
            f"**Remediation:** {interview.get('remediation')}",
            "",
            f"**Risk considered:** {interview.get('risk_considered')}",
            "",
            f"**Result:** {interview.get('result')}",
            "",
            f"**Lessons learned:** {interview.get('lessons_learned')}",
            "",
            "## Concise answer",
            "",
            interview.get("paragraph") or "",
            "",
        ]
    )
    (directory / "README.md").write_text(readme, encoding="utf-8")
    (reports / "internal.md").write_text(internal_md, encoding="utf-8")
    (reports / "public.md").write_text(public_md, encoding="utf-8")
    (reports / "linkedin.txt").write_text(linkedin, encoding="utf-8")
    (reports / "interview.md").write_text(interview_md, encoding="utf-8")
    (reports / "portfolio_summary.txt").write_text(
        case.get("portfolio_summary") or _portfolio_summary(case), encoding="utf-8"
    )
    try:
        (reports / "internal.pdf").write_bytes(
            render_md_to_pdf_bytes(
                internal_md, f"INTERNAL — {case.get('case_id')} — Sentinel Stacks"
            )
        )
        (reports / "public.pdf").write_bytes(
            render_md_to_pdf_bytes(
                public_md, f"PUBLIC/PORTFOLIO — {case.get('case_id')} — Sentinel Stacks"
            )
        )
    except Exception:
        # PDF optional if fpdf missing; markdown always present.
        pass
    return {
        "readme": str(directory / "README.md"),
        "internal_md": str(reports / "internal.md"),
        "public_md": str(reports / "public.md"),
        "linkedin": str(reports / "linkedin.txt"),
        "interview": str(reports / "interview.md"),
    }


def create_case(
    workspace: Path | str,
    case_doc: dict[str, Any],
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Persist an immutable case. Refuses overwrite unless force (amend)."""
    workspace = Path(workspace)
    case_id = str(case_doc.get("case_id") or "")
    directory = case_dir(workspace, case_id)
    case_path = directory / "case.json"
    if case_path.is_file() and not force:
        existing = _read_json(case_path)
        if existing.get("immutable"):
            raise FileExistsError(f"case {case_id} already exists and is immutable")
    case_doc = dict(case_doc)
    case_doc["immutable"] = True
    if force and case_path.is_file():
        case_doc["amended_at"] = _now()
        case_doc["amendment_note"] = "Explicit amend of historical case"
    _write_json(case_path, case_doc)
    exports = write_case_exports(case_doc, directory)
    case_doc["exports"] = exports

    index = load_index(workspace)
    ids = list(index.get("case_ids") or [])
    if case_id not in ids:
        ids.append(case_id)
        # bump next_seq based on numeric suffix
        m = re.fullmatch(r"CASE-(\d{4})-(\d{4})", case_id)
        if m:
            seq = int(m.group(2)) + 1
            index["next_seq"] = max(int(index.get("next_seq") or 1), seq)
    index["case_ids"] = ids
    by_job = dict(index.get("by_job_id") or {})
    if case_doc.get("job_id"):
        by_job[str(case_doc["job_id"])] = case_id
    index["by_job_id"] = by_job
    save_index(workspace, index)

    # Re-write case.json with export paths
    _write_json(case_path, case_doc)
    return case_doc


def create_case_from_job(
    workspace: Path | str,
    job_id: str,
    *,
    after_scan_path: str | Path | None = None,
    after_findings: list[dict] | None = None,
    classification: str = CLASSIFICATION_LAB,
    title: str | None = None,
    intended_control_ids: list[str] | None = None,
    execution_method: str | None = None,
    remediation_artifact_type: str | None = None,
    remediation_description: str | None = None,
    changes_performed: str | None = None,
    case_id: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    workspace = Path(workspace)
    job_path = workspace / "jobs" / f"{Path(job_id).name}.json"
    if not job_path.is_file():
        raise FileNotFoundError(f"job not found: {job_id}")
    job = _read_json(job_path)

    # Idempotent: one case per job unless force
    index = load_index(workspace)
    existing_id = (index.get("by_job_id") or {}).get(str(job.get("job_id")))
    if existing_id and not force:
        existing = load_case(workspace, existing_id)
        if existing:
            return existing

    before_findings = _load_findings_from_scan(job.get("scan_report_path"))
    after_path = str(after_scan_path) if after_scan_path else None
    if after_findings is None:
        if not after_path:
            raise ValueError("after_scan_path or after_findings required for verification")
        after_findings = _load_findings_from_scan(after_path)
    else:
        after_findings = list(after_findings)

    cid = case_id or next_case_id(workspace)
    doc = build_case_document(
        workspace=workspace,
        case_id=cid,
        job=job,
        before_findings=before_findings,
        after_findings=after_findings,
        after_scan_path=after_path,
        classification=classification,
        title=title,
        intended_control_ids=intended_control_ids,
        execution_method=execution_method,
        remediation_artifact_type=remediation_artifact_type,
        remediation_description=remediation_description,
        changes_performed=changes_performed,
    )
    return create_case(workspace, doc, force=force)


def maybe_create_case_on_clear(
    workspace: Path | str,
    *,
    before_job: dict[str, Any],
    after_findings: list[dict],
    after_scan_path: str | None = None,
    classification: str = CLASSIFICATION_LAB,
) -> dict[str, Any] | None:
    """
    Auto-archive when a re-scan clears findings relative to a prior approved job.
    Does not execute remediation; only records verified clears.
    """
    workspace = Path(workspace)
    decision = str(before_job.get("manager_decision") or before_job.get("status") or "").lower()
    if decision not in {"approved", "partially_approved"} and before_job.get("status") not in {
        "approved",
        "partially_approved",
    }:
        # Still allow if finding_decisions contain approvals
        fds = before_job.get("finding_decisions") or {}
        if not any(str(v).lower() == "approved" for v in fds.values()):
            return None

    before_findings = _load_findings_from_scan(before_job.get("scan_report_path"))
    delta = compute_scan_delta(before_findings, after_findings)
    if not delta.get("cleared_count"):
        return None

    try:
        return create_case_from_job(
            workspace,
            str(before_job.get("job_id")),
            after_scan_path=after_scan_path,
            after_findings=after_findings,
            classification=classification,
        )
    except FileExistsError:
        index = load_index(workspace)
        cid = (index.get("by_job_id") or {}).get(str(before_job.get("job_id")))
        return load_case(workspace, cid) if cid else None


def filter_cases(
    cases: list[dict[str, Any]],
    *,
    agent: str | None = None,
    domain: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    control_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    out = []
    for c in cases:
        if agent and agent.lower() not in str(c.get("agent") or "").lower() and agent.lower() not in str(c.get("role") or "").lower():
            continue
        if domain and domain.lower() not in str(c.get("domain") or "").lower():
            continue
        if status and status.upper() not in str(c.get("status") or "").upper():
            continue
        if control_id:
            controls = [str(x) for x in (c.get("controls") or [])]
            ids = " ".join(controls).upper()
            if control_id.upper() not in ids:
                continue
        if severity:
            sev = severity.lower()
            before_sev = ((c.get("before") or {}).get("severity") or {})
            cleared = (c.get("scan_delta") or {}).get("cleared") or []
            if not (
                int(before_sev.get(sev) or 0) > 0
                or any(str(x.get("severity") or "").lower() == sev for x in cleared)
            ):
                continue
        d = str(c.get("date") or "")
        if date_from and d < date_from:
            continue
        if date_to and d > date_to:
            continue
        if q:
            blob = json.dumps(
                {
                    "case_id": c.get("case_id"),
                    "title": c.get("title"),
                    "job_id": c.get("job_id"),
                    "controls": c.get("controls"),
                    "agent": c.get("agent"),
                },
                ensure_ascii=True,
            ).lower()
            if q.lower() not in blob:
                continue
        out.append(c)
    return out


def _iam_case_needs_repair(case: dict[str, Any] | None) -> bool:
    if not case:
        return True
    controls = [str(c) for c in (case.get("controls") or [])]
    decisions = set((case.get("finding_decisions") or {}).keys())
    expected = set(IAM_PASSWORD_CONTROLS)
    if set(controls) != expected:
        return True
    if decisions - expected:
        return True
    if case.get("execution_method") != EXEC_AWS_CONSOLE:
        return True
    if case.get("remediation_artifact_type") != ARTIFACT_TERRAFORM:
        return True
    if case.get("execution_performed_by_platform") is not False:
        return True
    method = str(((case.get("execution") or {}).get("method") or "")).lower()
    if "terraform applied" in method and "console" not in method:
        return True
    return False


def ensure_iam_password_policy_case(workspace: Path | str) -> dict[str, Any] | None:
    """
    Seed/repair CASE-2026-0001 from the completed IAM password-policy remediation.
    Classification: LAB. Artifact: Terraform reviewed. Execution: AWS Console.
    """
    workspace = Path(workspace)
    existing = load_case(workspace, "CASE-2026-0001")
    force = _iam_case_needs_repair(existing)

    before_job_id = "job_20260815T015357Z_0e17ac50"
    after_job_id = "job_20260815T151934Z_699d3972"
    job_path = workspace / "jobs" / f"{before_job_id}.json"
    after_job_path = workspace / "jobs" / f"{after_job_id}.json"
    if not job_path.is_file():
        return existing

    after_scan = None
    if after_job_path.is_file():
        after_job = _read_json(after_job_path)
        after_scan = after_job.get("scan_report_path")
    if not after_scan:
        candidate = workspace / "scans" / "cycle_20260815T151911Z_be9ff393_cloud.json"
        if candidate.is_file():
            after_scan = str(candidate)
    if not after_scan:
        return existing

    if existing and not force:
        return existing

    return create_case_from_job(
        workspace,
        before_job_id,
        after_scan_path=after_scan,
        classification=CLASSIFICATION_LAB,
        title="AWS IAM Password Policy Hardening",
        intended_control_ids=list(IAM_PASSWORD_CONTROLS),
        case_id="CASE-2026-0001",
        force=True,
        remediation_artifact_type=ARTIFACT_TERRAFORM,
        execution_method=EXEC_AWS_CONSOLE,
        remediation_description=(
            "Terraform-generated consolidated AWS IAM account password policy was reviewed "
            "and approved for CLOUD-IAM-001 through CLOUD-IAM-005: minimum length 14; require "
            "uppercase, lowercase, number, and symbol; max age 90 days; reuse prevention 24; "
            "allow users to change their own password."
        ),
        changes_performed=(
            "Terraform remediation reviewed and approved; equivalent configuration applied "
            "through AWS IAM Console by the human manager/operator; platform execution false; "
            "verified by subsequent Cloud Security Agent live re-scan "
            "(CLOUD-IAM-001 through CLOUD-IAM-005 cleared)."
        ),
    )
