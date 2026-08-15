# change_assurance/artifacts/dockerfile.py

from __future__ import annotations

import re
from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash
from change_assurance.secret_redaction import redact_text


class DockerfileHandler(ArtifactHandler):
    artifact_type = "dockerfile"

    def detect(self, artifact: dict) -> bool:
        if str(artifact.get("artifact_type") or "").lower() == "dockerfile":
            return True
        return any("dockerfile" in str(f).lower() for f in (artifact.get("source_files") or []))

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        text, secrets = redact_text(str(artifact.get("content_preview") or ""))
        flags: dict[str, Any] = {}
        risks: list[str] = []
        errors: list[str] = []
        if not text.strip():
            return {
                "status": "VALIDATION_UNAVAILABLE",
                "errors": ["No Dockerfile content"],
                "mode": "STATIC_ONLY",
            }
        user_m = re.findall(r"(?im)^\s*USER\s+(\S+)", text)
        if not user_m or any(u in {"root", "0"} for u in user_m):
            flags["runs_as_root"] = True
            risks.append("container_runs_as_root")
        if re.search(r"(?im)^\s*(COPY|ADD)\s+.*(\.env|id_rsa|credentials|secret)", text):
            flags["secret_copied"] = True
            risks.append("secrets_copied_into_image")
            errors.append("SECRET_REDACTED pattern: secret-like file copied into image")
        if re.search(r"(?im)^\s*RUN\s+.*(curl|wget).*\|\s*(sh|bash)", text):
            flags["untrusted_download_exec"] = True
            risks.append("untrusted_download_execution")
        if re.search(r"(?im)^\s*EXPOSE\s+", text):
            flags["ports_exposed"] = re.findall(r"(?im)^\s*EXPOSE\s+(.+)$", text)
        if secrets:
            flags["secret_in_dockerfile"] = True
            errors.append("SECRET_REDACTED: credential-like content in Dockerfile")
        status = "FAIL" if errors else "PASS"
        return {
            "status": status,
            "errors": errors,
            "mode": "STATIC_ONLY",
            "analysis": {"flags": flags, "risks": risks, "instructions": self._instructions(text)},
            "secrets_redacted": [{"status": "SECRET_REDACTED", "secret_type": s.get("secret_type")} for s in secrets],
        }

    def _instructions(self, text: str) -> list[str]:
        out = []
        for line in text.splitlines():
            m = re.match(r"(?i)^\s*(FROM|USER|RUN|COPY|ADD|ENTRYPOINT|CMD|EXPOSE|ENV|ARG)\b", line)
            if m:
                out.append(m.group(1).upper())
        return out

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        val = artifact.get("validation") or self.validate(artifact, context)
        flags = (val.get("analysis") or {}).get("flags") or {}
        return {
            "actions": [{"action": "UPDATE", "target": "dockerfile"}],
            "plan": {"status": "static", "summary": {"risks": (val.get("analysis") or {}).get("risks") or []}},
            "flags": {
                **flags,
                "container_privilege": bool(flags.get("runs_as_root")),
                "secret_access": bool(flags.get("secret_copied") or flags.get("secret_in_dockerfile")),
            },
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {"destructive": False, "details": "NONE"}

    def calculate_hash(self, artifact: dict) -> str:
        return stable_hash(
            {"type": "dockerfile", "files": artifact.get("source_files"), "preview": artifact.get("content_preview")}
        )

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": True,
            "procedure": "Revert Dockerfile; rebuild image in authorized phase; re-scan image; do not push automatically.",
            "confidence": "MEDIUM",
        }
