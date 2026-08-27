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

VERSION = "0.1.1"

# Any of these in an active execution artifact block execution-ready status.
PLACEHOLDER_RE = re.compile(
    r"REPLACE_[A-Z0-9_]+|TODO_[A-Z0-9_]*|\bTODO\b|CHANGEME|YOUR_[A-Z0-9_]+",
    re.I,
)
RESOURCE_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"',
    re.M,
)
DESTROY_HINTS = re.compile(
    r"\b(force_destroy\s*=\s*true|prevent_destroy\s*=\s*false)\b",
    re.I,
)
IAM_TYPES = {
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_policy_attachment",
    "aws_iam_service_linked_role",
}
NET_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_network_acl",
    "aws_route",
    "aws_route_table",
    "aws_vpc",
    "aws_subnet",
}

# Shared remediation artifacts intentionally covering multiple finding IDs.
# Keep in sync with ai_remediation_engine.PASSWORD_POLICY_* when possible.
SHARED_ARTIFACT_GROUPS: dict[str, frozenset[str]] = {
    "terraform/aws_iam_account_password_policy.tf": frozenset(
        {
            "CLOUD-IAM-001",
            "CLOUD-IAM-002",
            "CLOUD-IAM-003",
            "CLOUD-IAM-004",
            "CLOUD-IAM-005",
        }
    ),
}


def _norm_rel(path: str) -> str:
    return str(path or "").replace("\\", "/").lstrip("./")


def _load_kit_manifest(kit_path: Path | None) -> dict[str, Any] | None:
    if not kit_path:
        return None
    kit_path = Path(kit_path)
    try:
        if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(kit_path, "r") as zf:
                for name in zf.namelist():
                    if name.replace("\\", "/").endswith("manifest.json"):
                        return json.loads(zf.read(name).decode("utf-8", errors="replace"))
        elif kit_path.is_dir():
            man = kit_path / "manifest.json"
            if man.is_file():
                return json.loads(man.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return None


def shared_artifact_paths_for_finding(finding_id: str | None) -> list[str]:
    fid = str(finding_id or "").strip().upper()
    if not fid:
        return []
    out: list[str] = []
    for path, ids in SHARED_ARTIFACT_GROUPS.items():
        if fid in {x.upper() for x in ids}:
            out.append(path)
    return out


def resolve_finding_kit_artifacts(
    kit_path: str | Path | None,
    finding_id: str | None,
    *,
    focus_finding_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Resolve remediation artifacts that belong to a finding (direct + shared).
    Never treats the whole kit as the finding's artifact set.
    """
    fid = str(finding_id or "").strip()
    focus = [str(x) for x in (focus_finding_ids or []) if x]
    if fid and fid not in focus:
        focus = [fid] + focus

    kit_path = Path(kit_path) if kit_path else None
    all_names = _list_kit_member_names(kit_path)
    manifest = _load_kit_manifest(kit_path)
    linked: list[str] = []
    mapping = "uncertain"

    # 1) Manifest items for this finding / focus IDs
    if manifest and isinstance(manifest.get("items"), list):
        for item in manifest["items"]:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("check_id") or "").strip()
            if cid and (cid == fid or cid in focus):
                for f in item.get("files") or []:
                    linked.append(_norm_rel(str(f)))
                if linked:
                    mapping = "manifest"

    # 2) Shared groups (password policy, etc.)
    for focus_id in focus or ([fid] if fid else []):
        for shared in shared_artifact_paths_for_finding(focus_id):
            # Prefer actual kit path casing/location
            match = next((n for n in all_names if n.endswith(shared) or n == shared), shared)
            linked.append(_norm_rel(match))
            if mapping == "uncertain":
                mapping = "shared"

    # 3) Filename contains finding id (runbook/config/tf named after control)
    if fid:
        for n in all_names:
            base = n.split("/")[-1]
            if fid in base or fid in n:
                # Skip generic README/manifest
                if base.lower() in {"readme.md", "manifest.json"}:
                    continue
                linked.append(_norm_rel(n))
                if mapping == "uncertain":
                    mapping = "filename"

    # Dedupe preserve order
    seen: set[str] = set()
    paths: list[str] = []
    for p in linked:
        if p and p not in seen:
            seen.add(p)
            paths.append(p)

    # Keep only paths that exist in kit when we know kit members
    if all_names:
        name_set = set(all_names)
        existing = []
        for p in paths:
            if p in name_set:
                existing.append(p)
                continue
            # allow suffix match (zip may nest)
            hit = next((n for n in all_names if n.endswith("/" + p) or n.endswith(p)), None)
            if hit:
                existing.append(hit)
        paths = list(dict.fromkeys(existing))

    # Prefer terraform/*.tf over configs/*.conf for the same control id
    def _artifact_rank(path: str) -> tuple:
        p = path.lower()
        if p.endswith(".tf") or "/terraform/" in p:
            return (0, path)
        if p.endswith((".yml", ".yaml")) or "/runbooks/" in p:
            return (1, path)
        if p.endswith(".conf") or "/configs/" in p:
            return (3, path)
        return (2, path)

    paths = sorted(paths, key=_artifact_rank)

    uncertain = mapping == "uncertain" or (bool(fid) and not paths and bool(all_names))
    if uncertain and not paths:
        mapping = "uncertain"

    # Drop legacy .conf when a .tf for the same finding exists (execution artifact rebind)
    tf_for_fid = [p for p in paths if p.lower().endswith(".tf") and fid and fid in p]
    if tf_for_fid:
        def _is_legacy_conf(path: str) -> bool:
            norm = path.replace("\\", "/").lower()
            return bool(
                fid
                and fid.lower() in norm
                and norm.endswith(".conf")
                and (norm.startswith("configs/") or "/configs/" in norm)
            )

        paths = [p for p in paths if not _is_legacy_conf(p)]

    return {
        "finding_id": fid or None,
        "paths": paths,
        "tf_paths": [p for p in paths if p.lower().endswith(".tf")],
        "mapping": mapping if paths else "uncertain",
        "uncertain": bool(uncertain and not paths),
        "reason": "ARTIFACT_MAPPING_UNCERTAIN" if (uncertain and not paths) else None,
    }


def _list_kit_member_names(kit_path: Path | None) -> list[str]:
    if not kit_path or not kit_path.exists():
        return []
    names: list[str] = []
    try:
        if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(kit_path, "r") as zf:
                names = [_norm_rel(n) for n in zf.namelist() if not n.endswith("/")]
        elif kit_path.is_dir():
            names = [_norm_rel(str(p.relative_to(kit_path))) for p in kit_path.rglob("*") if p.is_file()]
    except Exception:
        return []
    return names


def _read_all_tf_sources(kit_path: Path | None) -> dict[str, str]:
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
                    out[_norm_rel(name)] = zf.read(name).decode("utf-8", errors="replace")
        except Exception:
            return out
    elif kit_path.is_dir():
        for p in kit_path.rglob("*.tf"):
            rel = _norm_rel(str(p.relative_to(kit_path)))
            out[rel] = p.read_text(encoding="utf-8", errors="replace")
    return out


def _read_tf_sources(
    kit_path: Path | None,
    focus_ids: list[str] | None = None,
    *,
    allowed_rel_paths: list[str] | None = None,
) -> dict[str, str]:
    """
    Map relative path -> tf content from kit zip/dir.
    When focusing a finding, ONLY return that finding's linked/shared .tf files.
    Never fall back to scanning the entire kit for an unrelated REPLACE_*.
    """
    all_tf = _read_all_tf_sources(kit_path)
    if not all_tf:
        return {}

    if allowed_rel_paths is not None:
        allowed = {_norm_rel(p) for p in allowed_rel_paths}
        if not allowed:
            return {}
        selected: dict[str, str] = {}
        for path, text in all_tf.items():
            if path in allowed or any(path.endswith("/" + a) or path.endswith(a) for a in allowed):
                selected[path] = text
        return selected

    if focus_ids:
        # Resolve via shared groups + filename; do NOT return whole kit on miss
        primary = focus_ids[0] if focus_ids else None
        scope = resolve_finding_kit_artifacts(kit_path, primary, focus_finding_ids=focus_ids)
        tf_paths = scope.get("tf_paths") or []
        if tf_paths:
            return _read_tf_sources(kit_path, None, allowed_rel_paths=tf_paths)
        # Filename contains any focus id
        focused = {k: v for k, v in all_tf.items() if any(fid in k for fid in focus_ids)}
        return focused  # may be empty — caller treats as scoped miss / uncertain

    return all_tf


def scan_kit_placeholders(
    kit_path: str | Path | None,
    *,
    only_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
) -> list[dict[str, str]]:
    """Detect unresolved placeholders in kit members (tf/conf/yml text)."""
    kit_path = Path(kit_path) if kit_path else None
    if not kit_path:
        return []
    only = {_norm_rel(p) for p in (only_paths or [])} or None
    excl = {_norm_rel(p) for p in (exclude_paths or [])}
    hits: list[dict[str, str]] = []
    names = _list_kit_member_names(kit_path)
    for name in names:
        if not name.lower().endswith((".tf", ".conf", ".yml", ".yaml", ".txt", ".hcl")):
            continue
        if only is not None and not (
            name in only or any(name.endswith("/" + a) or name.endswith(a) for a in only)
        ):
            continue
        if name in excl or any(name.endswith("/" + e) or name.endswith(e) for e in excl):
            continue
        text = _read_kit_member_text(kit_path, name)
        if text is None:
            continue
        for m in PLACEHOLDER_RE.finditer(text):
            hits.append({"file": name, "token": m.group(0)})
    return hits


def _read_kit_member_text(kit_path: Path, rel: str) -> str | None:
    try:
        if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(kit_path, "r") as zf:
                # exact or endswith
                names = zf.namelist()
                match = next((n for n in names if _norm_rel(n) == rel or _norm_rel(n).endswith(rel)), None)
                if not match:
                    return None
                return zf.read(match).decode("utf-8", errors="replace")
        p = kit_path / rel
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
        # try endswith search
        for cand in kit_path.rglob("*"):
            if cand.is_file() and _norm_rel(str(cand.relative_to(kit_path))).endswith(rel):
                return cand.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    return None


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
                "aws_s3_bucket",
                "aws_s3_bucket_server_side_encryption_configuration",
                "aws_s3_bucket_ownership_controls",
            }:
                flags["data_access_change"] = True
            if rtype == "aws_config_configuration_recorder":
                flags["config_recorder_enable"] = True
            if rtype == "aws_guardduty_detector":
                flags["guardduty_enable"] = True
            if rtype == "aws_accessanalyzer_analyzer":
                flags["access_analyzer_enable"] = True
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
    allowed_rel_paths: list[str] | None = None,
) -> dict[str, Any]:
    kit = Path(kit_path) if kit_path else None
    primary = (focus_finding_ids or [None])[0]
    scope = (
        resolve_finding_kit_artifacts(kit, primary, focus_finding_ids=focus_finding_ids)
        if focus_finding_ids
        else {"paths": [], "tf_paths": [], "mapping": "kit", "uncertain": False, "reason": None}
    )
    allow = allowed_rel_paths
    if allow is None and focus_finding_ids:
        allow = list(scope.get("tf_paths") or [])
        # If mapping resolved non-tf only, do not scan whole kit
        if scope.get("paths") and not allow:
            allow = []

    sources = _read_tf_sources(kit, focus_finding_ids if allow is None else None, allowed_rel_paths=allow)

    if focus_finding_ids and scope.get("uncertain") and not sources and not scope.get("paths"):
        analysis = analyze_terraform_sources({})
        analysis["validate"] = {
            "status": "VALIDATION_UNAVAILABLE",
            "errors": ["ARTIFACT_MAPPING_UNCERTAIN — cannot confidently bind kit artifacts to this finding"],
            "mode": "scoped",
        }
        analysis["plan"]["status"] = "SKIP"
        analysis["flags"]["placeholder_unresolved"] = False
        analysis["placeholders"] = []
        analysis["artifact_scope"] = scope
        analysis["cli"] = {"skipped": True, "reason": "ARTIFACT_MAPPING_UNCERTAIN"}
        return analysis

    if focus_finding_ids and not sources and scope.get("paths"):
        # Linked runbook/config only — do not invent whole-kit terraform scope
        analysis = analyze_terraform_sources({})
        analysis["validate"] = {"status": "PASS", "errors": [], "mode": "scoped_non_tf"}
        analysis["plan"]["status"] = "SKIP"
        analysis["flags"]["placeholder_unresolved"] = False
        analysis["placeholders"] = []
    else:
        analysis = analyze_terraform_sources(sources)

    analysis["artifact_scope"] = scope if focus_finding_ids else {"mapping": "kit", "paths": list(sources.keys())}

    # Check linked non-tf configs for placeholders (scoped only; do not weaken detection)
    if focus_finding_ids:
        linked = list(scope.get("paths") or [])
        scoped_hits = scan_kit_placeholders(kit, only_paths=linked)
        for hit in scoped_hits:
            if not any(
                h.get("file") == hit.get("file") and h.get("token") == hit.get("token")
                for h in analysis["placeholders"]
            ):
                analysis["placeholders"].append(hit)
            analysis["flags"]["placeholder_unresolved"] = True
        if analysis["flags"]["placeholder_unresolved"]:
            analysis["validate"]["status"] = "FAIL"
            analysis["validate"]["errors"] = [
                f"Unresolved placeholder: {p['token']} in {p['file']}" for p in analysis["placeholders"][:10]
            ]
            if analysis["plan"].get("status") != "SKIP":
                analysis["plan"]["status"] = "FAIL"

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
