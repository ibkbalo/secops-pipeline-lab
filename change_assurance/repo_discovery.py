# change_assurance/repo_discovery.py
# Read-only repository fingerprinting for DevSecOps Change Assurance.

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from change_assurance.models import stable_hash

CONFIG_GLOBS = (
    ".github/workflows/*.{yml,yaml}",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "Dockerfile",
    "**/Dockerfile",
    "docker-compose*.yml",
    "**/*.{yaml,yml}",
    "**/Chart.yaml",
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
    "**/*.tf",
)


def _run_git(repo: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return (proc.stdout or "").strip() or None
    except Exception:
        return None


def discover_repository(path: str | Path | None) -> dict[str, Any]:
    """
    Read-only inspection. Never modifies the repository.
    """
    if not path:
        return {
            "status": "UNAVAILABLE",
            "repository": None,
            "branch": None,
            "commit_sha": None,
            "fingerprint": None,
            "relevant_files": [],
            "note": "No repository path provided",
        }
    root = Path(path).expanduser().resolve()
    if not root.exists():
        return {
            "status": "UNAVAILABLE",
            "repository": str(path),
            "branch": None,
            "commit_sha": None,
            "fingerprint": None,
            "relevant_files": [],
            "note": "Path does not exist",
        }
    # If path is a file (kit zip), treat as artifact root not a git repo
    if root.is_file():
        return {
            "status": "ARTIFACT_ONLY",
            "repository": str(root),
            "branch": None,
            "commit_sha": None,
            "fingerprint": stable_hash({"path": str(root), "size": root.stat().st_size}),
            "relevant_files": [root.name],
            "note": "File/kit path — no live git fingerprint",
        }

    branch = _run_git(root, "rev-parse", "--abbrev-ref", "HEAD")
    commit = _run_git(root, "rev-parse", "HEAD")
    remotes = _run_git(root, "remote", "get-url", "origin")

    relevant: list[str] = []
    patterns = [
        ".github/workflows",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "Dockerfile",
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "Cargo.toml",
        "Chart.yaml",
    ]
    try:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(root)).replace("\\", "/")
            if any(x in rel for x in (".git/", "node_modules/", "__pycache__/", ".venv/", "dist/")):
                continue
            name = p.name
            if (
                name in patterns
                or rel.startswith(".github/workflows/")
                or name.endswith((".tf", ".yaml", ".yml"))
                and any(k in rel.lower() for k in ("deploy", "k8s", "kube", "helm", "chart", "ci"))
            ):
                relevant.append(rel)
            if len(relevant) >= 80:
                break
    except Exception:
        pass

    fp_body = {
        "repository": str(root),
        "branch": branch,
        "commit_sha": commit,
        "origin": remotes,
    }
    return {
        "status": "OK" if commit else "PARTIAL",
        "repository": str(root),
        "branch": branch,
        "commit_sha": commit,
        "origin": remotes,
        "fingerprint": stable_hash(fp_body),
        "repo_fingerprint": fp_body,
        "relevant_files": relevant,
        "note": "Read-only discovery",
    }


def extract_kit_texts(kit_path: str | Path | None) -> dict[str, str]:
    """Map relative path → text content from ZIP or directory (read-only)."""
    out: dict[str, str] = {}
    if not kit_path:
        return out
    p = Path(kit_path)
    try:
        if p.is_file() and p.suffix.lower() == ".zip":
            import zipfile

            with zipfile.ZipFile(p, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    if name.endswith(
                        (
                            ".py",
                            ".js",
                            ".ts",
                            ".yml",
                            ".yaml",
                            ".json",
                            ".tf",
                            ".toml",
                            ".txt",
                            ".md",
                            ".xml",
                            ".gradle",
                            "Dockerfile",
                            "Jenkinsfile",
                            ".mod",
                        )
                    ) or name.split("/")[-1] in {
                        "Dockerfile",
                        "Jenkinsfile",
                        "requirements.txt",
                        "package.json",
                        "go.mod",
                        "Cargo.toml",
                        "pom.xml",
                        "pyproject.toml",
                    }:
                        try:
                            out[name.replace("\\", "/")] = zf.read(name).decode("utf-8", errors="replace")[:20000]
                        except Exception:
                            continue
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.stat().st_size < 500_000:
                    rel = str(f.relative_to(p)).replace("\\", "/")
                    try:
                        out[rel] = f.read_text(encoding="utf-8", errors="replace")[:20000]
                    except Exception:
                        continue
    except Exception:
        return out
    return out
