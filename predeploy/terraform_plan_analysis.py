# predeploy/terraform_plan_analysis.py
# Static Terraform kit analysis + optional terraform CLI (never apply).

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

PLACEHOLDER_RE = re.compile(r"REPLACE_[A-Z0-9_]+|TODO_|CHANGEME|YOUR_", re.I)
RESOURCE_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"',
    re.M,
)
DESTROY_HINTS = re.compile(
    r"\b(force_destroy\s*=\s*true|prevent_destroy\s*=\s*false)\b",
    re.I,
)
IAM_TYPES = {"aws_iam_role", "aws_iam_policy", "aws_iam_user", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_policy_attachment"}
NET_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_network_acl",
    "aws_route",
    "aws_route_table",
    "aws_vpc",
    "aws_subnet",
}


def _read_tf_sources(kit_path: Path | None, focus_ids: list[str] | None = None) -> dict[str, str]:
    """Map relative path -> tf content from kit zip/dir."""
    out: dict[str, str] = {}
    if not kit_path:
        return out
    kit_path = Path(kit_path)
    if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(kit_path, "r") as zf:
                for name in zf.namelist():
                    if not name.lower().endswith(".tf"):
                        continue
                    if focus_ids and not any(fid in name for fid in focus_ids):
                        # still include all if none match later
                        pass
                    out[name.replace("\\", "/")] = zf.read(name).decode("utf-8", errors="replace")
        except Exception:
            return out
    elif kit_path.is_dir():
        for p in kit_path.rglob("*.tf"):
            rel = str(p.relative_to(kit_path)).replace("\\", "/")
            out[rel] = p.read_text(encoding="utf-8", errors="replace")
    # Prefer focus files if present
    if focus_ids:
        focused = {k: v for k, v in out.items() if any(fid in k for fid in focus_ids)}
        if focused:
            return focused
    return out


def analyze_terraform_sources(sources: dict[str, str]) -> dict[str, Any]:
    placeholders: list[dict[str, str]] = []
    resources: list[dict[str, str]] = []
    flags = {
        "iam_change": False,
        "networking_change": False,
        "destructive_tf": False,
        "placeholder_unresolved": False,
        "data_access_change": False,
    }
    for path, text in sources.items():
        for m in PLACEHOLDER_RE.finditer(text):
            placeholders.append({"file": path, "token": m.group(0)})
            flags["placeholder_unresolved"] = True
        for m in RESOURCE_RE.finditer(text):
            rtype, rname = m.group(1), m.group(2)
            resources.append({"type": rtype, "name": rname, "file": path})
            if rtype in IAM_TYPES:
                flags["iam_change"] = True
            if rtype in NET_TYPES:
                flags["networking_change"] = True
            if rtype in {
                "aws_s3_bucket_public_access_block",
                "aws_s3_bucket_policy",
                "aws_s3_bucket_acl",
            }:
                flags["data_access_change"] = True
            # Account-level BPA is additive hardening — not treated as data-access risk by itself.
            if rtype in {"aws_cloudtrail", "aws_guardduty_detector", "aws_config_configuration_recorder"}:
                pass
        if DESTROY_HINTS.search(text):
            flags["destructive_tf"] = True

    # Heuristic plan summary without terraform binary
    create = len(resources)
    destroy = 1 if flags["destructive_tf"] else 0
    summary = {
        "create": create,
        "modify": 0,
        "replace": 0,
        "destroy": destroy,
        "mode": "static_heuristic",
    }

    validate = {
        "status": "FAIL" if flags["placeholder_unresolved"] or not sources else "PASS",
        "errors": (
            [f"Unresolved placeholder: {p['token']} in {p['file']}" for p in placeholders[:10]]
            if flags["placeholder_unresolved"]
            else ([] if sources else ["No Terraform sources found in kit"])
        ),
        "mode": "static",
    }

    return {
        "version": VERSION,
        "files": sorted(sources.keys()),
        "resources": resources,
        "placeholders": placeholders,
        "flags": flags,
        "validate": validate,
        "plan": {
            "status": "FAIL" if flags["placeholder_unresolved"] else ("PASS" if sources else "SKIP"),
            "summary": summary,
            "destructive_actions": "PRESENT" if destroy or flags["destructive_tf"] else "NONE",
            "mode": "static_heuristic",
            "raw_preview": None,
        },
        "fmt_check": {"status": "SKIP", "reason": "optional CLI not required for static gate"},
    }


def maybe_run_terraform_cli(sources: dict[str, str], timeout: int = 45) -> dict[str, Any] | None:
    """
    If `terraform` is on PATH and sources have no placeholders, run fmt/validate/plan
    in a temp dir. Never apply. Returns None if terraform unavailable or skipped.
    """
    if not sources:
        return None
    joined = "\n".join(sources.values())
    if PLACEHOLDER_RE.search(joined):
        return {
            "skipped": True,
            "reason": "placeholders present — CLI plan deferred until REPLACE_* resolved",
        }
    tf_bin = shutil.which("terraform")
    if not tf_bin:
        return {"skipped": True, "reason": "terraform CLI not installed"}

    result: dict[str, Any] = {"cli": True, "commands": []}
    with tempfile.TemporaryDirectory(prefix="sentinel_tf_") as tmp:
        tmp_path = Path(tmp)
        for name, text in sources.items():
            dest = tmp_path / Path(name).name
            dest.write_text(text, encoding="utf-8")
        # Minimal provider stub so validate can run offline-ish
        (tmp_path / "versions.tf").write_text(
            'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'
            'provider "aws" {\n  region = "us-east-1"\n  skip_credentials_validation = true\n'
            "  skip_metadata_api_check = true\n  skip_requesting_account_id = true\n}\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["TF_INPUT"] = "0"
        env["TF_IN_AUTOMATION"] = "1"

        def run(args: list[str]) -> dict[str, Any]:
            try:
                p = subprocess.run(
                    [tf_bin, *args],
                    cwd=tmp_path,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    check=False,
                )
                return {
                    "cmd": " ".join(args),
                    "exit_code": p.returncode,
                    "stdout": (p.stdout or "")[-4000:],
                    "stderr": (p.stderr or "")[-4000:],
                }
            except Exception as e:
                return {"cmd": " ".join(args), "exit_code": -1, "error": str(e)}

        result["commands"].append(run(["init", "-backend=false", "-input=false"]))
        result["commands"].append(run(["fmt", "-check", "-recursive"]))
        val = run(["validate", "-json"])
        result["commands"].append(val)
        plan = run(["plan", "-input=false", "-lock=false", "-detailed-exitcode"])
        result["commands"].append(plan)
        # Never apply
        result["apply_forbidden"] = True
    return result


def analyze_kit_terraform(
    kit_path: str | Path | None,
    focus_finding_ids: list[str] | None = None,
    *,
    try_cli: bool = True,
) -> dict[str, Any]:
    sources = _read_tf_sources(Path(kit_path) if kit_path else None, focus_finding_ids)
    analysis = analyze_terraform_sources(sources)
    if try_cli:
        cli = maybe_run_terraform_cli(sources)
        analysis["cli"] = cli
        if cli and not cli.get("skipped"):
            # Merge validate from CLI if present
            for c in cli.get("commands") or []:
                if str(c.get("cmd", "")).startswith("validate"):
                    if c.get("exit_code") == 0:
                        analysis["validate"]["status"] = "PASS"
                        analysis["validate"]["mode"] = "terraform_cli"
                    elif c.get("exit_code") not in (None, 0):
                        analysis["validate"]["status"] = "FAIL"
                        analysis["validate"]["mode"] = "terraform_cli"
                        analysis["validate"]["errors"].append(c.get("stderr") or c.get("error") or "validate failed")
                if str(c.get("cmd", "")).startswith("plan"):
                    # exit 0=no change, 2=changes, 1=error
                    code = c.get("exit_code")
                    if code in (0, 2):
                        analysis["plan"]["status"] = "PASS"
                        analysis["plan"]["mode"] = "terraform_cli"
                        analysis["plan"]["raw_preview"] = c.get("stdout")
                        # crude parse
                        out = c.get("stdout") or ""
                        if "will be destroyed" in out or "must be replaced" in out:
                            analysis["plan"]["destructive_actions"] = "PRESENT"
                            analysis["flags"]["destructive_tf"] = True
                            analysis["plan"]["summary"]["destroy"] = max(
                                int(analysis["plan"]["summary"].get("destroy") or 0), 1
                            )
                    elif code == 1:
                        analysis["plan"]["status"] = "FAIL"
                        analysis["plan"]["mode"] = "terraform_cli"
    return analysis
