# change_assurance/artifacts/code_patch.py
# source_code_patch + dependency remediation intelligence.

from __future__ import annotations

import re
from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash
from change_assurance.secret_redaction import redact_text

SENSITIVE_PATH_HINTS = (
    "auth",
    "login",
    "oauth",
    "jwt",
    "crypto",
    "secret",
    "password",
    "credential",
    "rbac",
    "permission",
    "network",
    "firewall",
    "tls",
    "ssl",
    "schema",
    "migration",
    "logging",
    "prod",
    "production",
    "security",
)

DEP_MANIFESTS = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "Cargo.toml",
}


def _is_sensitive_path(path: str) -> tuple[bool, str | None]:
    low = path.lower()
    for hint in SENSITIVE_PATH_HINTS:
        if hint in low:
            return True, f"Path suggests {hint} related change"
    return False, None


def parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in (diff_text or "").splitlines():
        if line.startswith("diff --git ") or line.startswith("--- ") or line.startswith("+++ "):
            if line.startswith("+++ "):
                path = line[4:].strip()
                if path.startswith("b/"):
                    path = path[2:]
                if current is None:
                    current = {
                        "file": path,
                        "action": "UPDATE",
                        "added_lines": 0,
                        "removed_lines": 0,
                        "security_sensitive": False,
                        "reason": None,
                    }
                    files.append(current)
                else:
                    current["file"] = path
                sens, reason = _is_sensitive_path(path)
                current["security_sensitive"] = sens
                current["reason"] = reason
            elif line.startswith("--- ") and "/dev/null" in line:
                if current:
                    current["action"] = "ADD"
            continue
        if line.startswith("new file mode"):
            if current:
                current["action"] = "ADD"
            continue
        if line.startswith("deleted file mode"):
            if current:
                current["action"] = "DELETE"
            continue
        if line.startswith("rename from"):
            if current:
                current["action"] = "RENAME"
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current["added_lines"] += 1
        elif line.startswith("-") and not line.startswith("---"):
            current["removed_lines"] += 1
    return files


def analyze_dependency_text(path: str, text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    name = path.split("/")[-1]
    if name not in DEP_MANIFESTS and not any(name.endswith(x) for x in DEP_MANIFESTS):
        return deps
    # requirements.txt style (skip unified-diff +/- lines — handled below)
    if name == "requirements.txt" or path.endswith("requirements.txt"):
        for line in text.splitlines():
            raw = line.rstrip("\n")
            if raw.startswith("+") or raw.startswith("-"):
                continue
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.]+)\s*([=!<>~]+)\s*([^\s;#]+)", line)
            if m:
                deps.append(
                    {
                        "package": m.group(1),
                        "old_version": None,
                        "new_version": m.group(3),
                        "direct_or_transitive": "direct",
                        "manifest": path,
                        "lockfile": None,
                        "change_kind": "unknown",
                        "production_dependency": True,
                    }
                )
            else:
                m2 = re.match(r"^([A-Za-z0-9_.]+)==([^\s;#]+)", line)
                if m2:
                    deps.append(
                        {
                            "package": m2.group(1),
                            "old_version": None,
                            "new_version": m2.group(2),
                            "direct_or_transitive": "direct",
                            "manifest": path,
                            "lockfile": None,
                            "change_kind": "unknown",
                            "production_dependency": True,
                        }
                    )
    # package.json dependencies block (naive)
    if name == "package.json":
        for kind, prod in (("dependencies", True), ("devDependencies", False)):
            block = re.search(rf'"{kind}"\s*:\s*\{{([^}}]+)\}}', text, re.S)
            if not block:
                continue
            for pm in re.finditer(r'"([^"]+)"\s*:\s*"([^"]+)"', block.group(1)):
                deps.append(
                    {
                        "package": pm.group(1),
                        "old_version": None,
                        "new_version": pm.group(2).lstrip("^~"),
                        "direct_or_transitive": "direct",
                        "manifest": path,
                        "lockfile": None,
                        "change_kind": "unknown",
                        "production_dependency": prod,
                    }
                )
    # Diff-style old→new (+pkg==ver / -pkg==ver) — two-pass so order does not matter
    removed: dict[str, str] = {}
    added: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^([+-])([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line.strip())
        if not m:
            continue
        sign, pkg, ver = m.group(1), m.group(2), m.group(3)
        if sign == "-":
            removed[pkg] = ver
        else:
            added[pkg] = ver
    for pkg, new_ver in added.items():
        old_ver = removed.get(pkg)
        deps.append(
            {
                "package": pkg,
                "old_version": old_ver,
                "new_version": new_ver,
                "direct_or_transitive": "direct",
                "manifest": path,
                "lockfile": None,
                "change_kind": classify_version_change(old_ver, new_ver),
                "production_dependency": True,
            }
        )
    for d in deps:
        if not d.get("change_kind") or d.get("change_kind") == "unknown":
            d["change_kind"] = classify_version_change(d.get("old_version"), d.get("new_version"))
    return deps


def classify_version_change(old: str | None, new: str | None) -> str:
    if not old or not new:
        return "unknown"
    def parts(v: str) -> list[int]:
        nums = re.findall(r"\d+", v)
        return [int(x) for x in nums[:3]] + [0] * (3 - min(3, len(nums)))

    try:
        o, n = parts(old), parts(new)
    except Exception:
        return "unknown"
    if o == n:
        return "none"
    if o[0] != n[0]:
        return "major"
    if o[1] != n[1]:
        return "minor"
    if o[2] != n[2]:
        return "patch"
    return "unknown"


class SourceCodePatchHandler(ArtifactHandler):
    artifact_type = "source_code_patch"

    def detect(self, artifact: dict) -> bool:
        return str(artifact.get("artifact_type") or "").lower() in {
            "source_code_patch",
            "dependency_update",
        }

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        mode = str(context.get("validation_mode") or "STATIC_ONLY")
        text = str(artifact.get("content_preview") or "")
        redacted, secrets = redact_text(text)
        errors: list[str] = []
        status = "PASS"
        looks_like_diff = text.lstrip().startswith(("diff ", "--- ", "+++ ")) or (
            "\n+" in text and "\n-" in text
        )
        # Python syntax check only for full-module content (never execute)
        if not looks_like_diff and (
            any(str(f).endswith(".py") for f in (artifact.get("source_files") or []))
            or text.lstrip().startswith(("def ", "import ", "from ", "class "))
        ):
            try:
                compile(text, "<patch>", "exec")
            except SyntaxError as exc:
                status = "FAIL"
                errors.append(f"Python syntax error: {exc}")
        if secrets:
            status = "FAIL"
            errors.append("SECRET_REDACTED: potential secret in patch content")
        if mode not in {"STATIC_ONLY", "SAFE_LOCAL_VALIDATION"}:
            return {
                "status": "VALIDATION_UNAVAILABLE",
                "errors": ["Requested validation mode not enabled"],
                "mode": mode,
                "capability": "CAPABILITY_UNAVAILABLE",
            }
        if not text.strip():
            status = "VALIDATION_UNAVAILABLE"
            errors.append("No patch content available for static validation")
        return {
            "status": status,
            "errors": errors,
            "mode": mode,
            "secrets_redacted": [
                {"status": "SECRET_REDACTED", "secret_type": h.get("secret_type")} for h in secrets
            ],
            "analysis": {
                "diff_files": parse_unified_diff(text),
                "dependencies": self._deps(artifact, text),
            },
        }

    def _deps(self, artifact: dict, text: str) -> list[dict[str, Any]]:
        deps: list[dict[str, Any]] = []
        for path in artifact.get("source_files") or []:
            if any(path.endswith(m) or path.split("/")[-1] == m for m in DEP_MANIFESTS):
                deps.extend(analyze_dependency_text(path, text))
        if not deps:
            deps.extend(analyze_dependency_text("requirements.txt", text))
        # dedupe
        seen = set()
        out = []
        for d in deps:
            key = (d.get("package"), d.get("new_version"), d.get("manifest"))
            if key in seen:
                continue
            seen.add(key)
            out.append(d)
        return out

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        text = str(artifact.get("content_preview") or "")
        files = parse_unified_diff(text)
        if not files and artifact.get("source_files"):
            for f in artifact["source_files"]:
                sens, reason = _is_sensitive_path(f)
                files.append(
                    {
                        "file": f,
                        "action": "UPDATE",
                        "added_lines": 0,
                        "removed_lines": 0,
                        "security_sensitive": sens,
                        "reason": reason,
                    }
                )
        deps = (artifact.get("validation") or {}).get("analysis", {}).get("dependencies") or self._deps(
            artifact, text
        )
        flags = {
            "security_sensitive_code": any(f.get("security_sensitive") for f in files),
            "dependency_change": bool(deps),
            "major_dependency": any(d.get("change_kind") == "major" for d in deps),
            "auth_change": any("auth" in str(f.get("file") or "").lower() for f in files),
            "files_deleted": any(f.get("action") == "DELETE" for f in files),
            "large_diff": sum(f.get("added_lines", 0) + f.get("removed_lines", 0) for f in files) > 200,
        }
        git_diff_hash = stable_hash(files) if files else stable_hash(text)
        artifact.setdefault("meta", {})["git_diff_hash"] = git_diff_hash
        actions = [{"action": f.get("action") or "UPDATE", "file": f.get("file")} for f in files] or [
            {"action": "UPDATE"}
        ]
        return {
            "actions": actions,
            "plan": {"status": "static", "summary": {"files": len(files), "dependencies": len(deps)}},
            "flags": flags,
            "diff_files": files,
            "dependencies": deps,
            "git_diff_hash": git_diff_hash,
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        changes = artifact.get("proposed_changes") or []
        deleted = [c for c in changes if str(c.get("action") or "").upper() == "DELETE"]
        return {"destructive": bool(deleted), "details": deleted or "NONE"}

    def calculate_hash(self, artifact: dict) -> str:
        return stable_hash(
            {
                "type": artifact.get("artifact_type"),
                "files": artifact.get("source_files"),
                "preview": artifact.get("content_preview"),
                "git_diff_hash": (artifact.get("meta") or {}).get("git_diff_hash"),
            }
        )

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": True,
            "procedure": "Revert the approved git commit/patch; re-run DevSecOps scan; do not force-push shared branches.",
            "confidence": "MEDIUM",
        }
