# worker_gate.py
# Sentinel Stacks — CI/PR gate adapter
# Runs a role Hands pack; exits non-zero when findings meet fail-on severities.
# Does NOT apply fixes. Use in GitHub Actions / local pre-merge checks.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VERSION = "0.1.0-w1"

ROLE_PACKS = {
    "devsecops": ("ai_devsecops_pack", "DEVSEC"),
    "security-engineer": ("ai_security_engineer_pack", "PERIM"),
    "cloud": ("ai_cloud_pack", "CLOUD"),
    "ai-security": ("ai_ai_security_pack", "AISEC"),
}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _import_pack(module_name: str):
    return __import__(module_name)


def run_gate(
    *,
    role: str,
    target: str = ".",
    mock: bool = False,
    fail_on: list[str] | None = None,
    report_path: str | None = None,
) -> dict[str, Any]:
    """Execute pack and decide pass/fail for CI."""
    role = (role or "devsecops").strip().lower()
    if role not in ROLE_PACKS:
        return {
            "ok": False,
            "passed": False,
            "error": f"unknown role: {role}",
            "version": VERSION,
        }

    fail_on = [s.lower() for s in (fail_on or ["critical"])]
    fail_ranks = {SEV_RANK.get(s, 0) for s in fail_on}
    min_fail = min(fail_ranks) if fail_ranks else SEV_RANK["critical"]

    mod_name, id_prefix = ROLE_PACKS[role]
    mod = _import_pack(mod_name)
    params: dict[str, Any] = {"target": target}
    if mock:
        params["mock"] = True
        if role == "devsecops":
            params["target"] = "mock-devsecops"
        elif role == "security-engineer":
            params["target"] = "mock-security-engineer"
        elif role == "cloud":
            params["target"] = "mock-cloud"
        elif role == "ai-security":
            params["target"] = "mock-ai-security"

    result = mod.run(params)
    findings = result.get("findings") or []
    if not isinstance(findings, list):
        findings = []

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    blockers: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        if SEV_RANK.get(sev, 0) >= min_fail:
            blockers.append(
                {
                    "id": f.get("id"),
                    "severity": sev,
                    "title": f.get("title"),
                }
            )

    execution = result.get("execution") or {}
    hard_fail = execution.get("status") == "failed"
    gate_fail = bool(blockers) or hard_fail
    report = {
        "ok": not hard_fail,
        "passed": not gate_fail,
        "version": VERSION,
        "role": role,
        "id_prefix": id_prefix,
        "target": target,
        "mock": mock,
        "fail_on": fail_on,
        "severity_counts": counts,
        "blocker_count": len(blockers),
        "blockers": blockers[:40],
        "pack_version": getattr(mod, "VERSION", None),
        "tool_id": result.get("tool_id"),
        "execution_status": execution.get("status"),
        "message": (
            f"GATE FAIL: {len(blockers)} finding(s) at/above {fail_on} for role={role}"
            if gate_fail and blockers
            else (
                f"GATE FAIL: pack execution failed ({execution.get('error')})"
                if hard_fail
                else f"GATE PASS: no findings at/above {fail_on} for role={role}"
            )
        ),
        "auto_apply": False,
    }

    if report_path:
        Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sentinel Stacks CI gate")
    p.add_argument(
        "--role",
        default="devsecops",
        choices=sorted(ROLE_PACKS.keys()),
        help="Which AI agent pack to run",
    )
    p.add_argument("--target", default=".", help="Repo/path/label to scan")
    p.add_argument("--mock", action="store_true", help="Use embedded vulnerable fixture")
    p.add_argument(
        "--fail-on",
        default="critical",
        help="Comma severities that fail the gate (default: critical)",
    )
    p.add_argument("--report-out", default=None, help="Write JSON report path")
    args = p.parse_args(argv)

    fail_on = [s.strip() for s in args.fail_on.split(",") if s.strip()]
    report = run_gate(
        role=args.role,
        target=args.target,
        mock=bool(args.mock),
        fail_on=fail_on,
        report_path=args.report_out,
    )
    print(json.dumps(report, indent=2))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
