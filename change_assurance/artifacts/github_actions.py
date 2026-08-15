# change_assurance/artifacts/github_actions.py
# Static analysis of GitHub Actions / GitLab CI / Jenkinsfile changes.

from __future__ import annotations

import re
from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash
from change_assurance.secret_redaction import redact_text


HIGH_RISK_PATTERNS = [
    ("write_all", re.compile(r"permissions\s*:\s*write-all", re.I)),
    ("broad_write", re.compile(r"permissions\s*:\s*\n(?:\s+\w+:\s*write\s*\n){3,}", re.I)),
    ("pull_request_target", re.compile(r"pull_request_target", re.I)),
    ("workflow_run", re.compile(r"workflow_run\s*:", re.I)),
    ("id_token_write", re.compile(r"id-token\s*:\s*write", re.I)),
    ("contents_write", re.compile(r"contents\s*:\s*write", re.I)),
    ("unpinned_action", re.compile(r"uses:\s*[^\s@]+@(main|master|latest)\b", re.I)),
    ("secrets_in_pr", re.compile(r"pull_request[\s\S]{0,200}secrets\.", re.I)),
]


class GitHubActionsHandler(ArtifactHandler):
    artifact_type = "github_actions"

    def detect(self, artifact: dict) -> bool:
        t = str(artifact.get("artifact_type") or "").lower()
        if t in {"github_actions", "gitlab_ci", "jenkinsfile", "cicd_config"}:
            return True
        files = " ".join(artifact.get("source_files") or [])
        return ".github/workflows" in files or "Jenkinsfile" in files or ".gitlab-ci" in files

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        text, secrets = redact_text(str(artifact.get("content_preview") or ""))
        errors: list[str] = []
        flags: dict[str, Any] = {}
        risks: list[str] = []
        # YAML structural: require key markers for GHA
        if text.strip() and ("on:" not in text and "on :" not in text) and "pipeline {" not in text:
            # may be gitlab
            if "stages:" not in text and "job:" not in text:
                errors.append("Workflow YAML missing expected 'on:' / stages markers (structural check)")
        for name, pat in HIGH_RISK_PATTERNS:
            if pat.search(text):
                flags[name] = True
                risks.append(name)
        status = "PASS"
        if secrets:
            status = "FAIL"
            errors.append("SECRET_REDACTED: credential-like content in CI config")
        if flags.get("write_all") or flags.get("pull_request_target") and flags.get("secrets_in_pr"):
            # still PASS parse, risk handled upstream — but write-all is high risk evidence
            pass
        if not text.strip():
            status = "VALIDATION_UNAVAILABLE"
            errors.append("No CI/CD content to validate")
        return {
            "status": status,
            "errors": errors,
            "mode": "STATIC_ONLY",
            "analysis": {"flags": flags, "risks": risks, "redacted_preview": text[:2000]},
            "secrets_redacted": [{"status": "SECRET_REDACTED", "secret_type": s.get("secret_type")} for s in secrets],
        }

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        val = artifact.get("validation") or self.validate(artifact, context)
        flags = (val.get("analysis") or {}).get("flags") or {}
        actions = [{"action": "UPDATE", "target": "ci_cd_workflow"}]
        if flags.get("write_all"):
            actions.append({"action": "PERMISSION_ESCALATION", "detail": "permissions: write-all"})
        return {
            "actions": actions,
            "plan": {"status": "static", "summary": {"risks": (val.get("analysis") or {}).get("risks") or []}},
            "flags": {
                **flags,
                "pipeline_permission_change": bool(flags),
                "production_deploy_risk": bool(
                    flags.get("write_all")
                    or flags.get("id_token_write")
                    or flags.get("contents_write")
                    or flags.get("pull_request_target")
                ),
                "secret_access": "secrets." in str(artifact.get("content_preview") or "").lower(),
            },
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        text = str(artifact.get("content_preview") or "").lower()
        destructive = "delete" in text and ("environment" in text or "branch" in text)
        return {"destructive": destructive, "details": "CI destructive markers" if destructive else "NONE"}

    def calculate_hash(self, artifact: dict) -> str:
        return stable_hash(
            {
                "type": self.artifact_type,
                "files": artifact.get("source_files"),
                "preview": artifact.get("content_preview"),
            }
        )

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": True,
            "procedure": "Revert workflow YAML to previous commit; disable workflow if needed; rotate any exposed tokens.",
            "confidence": "MEDIUM",
        }
