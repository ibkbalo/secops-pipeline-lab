# change_assurance/artifacts/generic.py
# Safe fallback handlers — never fake PASS when validator unavailable.

from __future__ import annotations

from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash


class GenericArtifactHandler(ArtifactHandler):
    """Fallback for unsupported artifact types."""

    artifact_type = "configuration_change"

    def __init__(self, artifact_type: str = "configuration_change"):
        self.artifact_type = artifact_type

    def detect(self, artifact: dict) -> bool:
        return True

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        text = str(artifact.get("content_preview") or "")
        placeholders = []
        for token in ("REPLACE_", "TODO_", "CHANGEME", "YOUR_"):
            if token in text:
                placeholders.append(token)
        if placeholders:
            return {
                "status": "FAIL",
                "errors": [f"Unresolved placeholder marker: {t}" for t in placeholders],
                "mode": "static_generic",
            }
        # No specialized validator available for this artifact type.
        return {
            "status": "VALIDATION_UNAVAILABLE",
            "errors": [f"No specialized validator for artifact_type={self.artifact_type}"],
            "mode": "stub",
            "capability": "CAPABILITY_UNAVAILABLE",
        }

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "actions": artifact.get("proposed_changes") or [{"action": "UNKNOWN"}],
            "plan": {"status": "VALIDATION_UNAVAILABLE", "summary": {}},
            "flags": {},
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        actions = [str(a.get("action") or "").upper() for a in (artifact.get("proposed_changes") or [])]
        destructive = any(a in {"DELETE", "REPLACE", "REVOKE", "DISABLE"} for a in actions)
        return {"destructive": destructive, "details": actions}

    def calculate_hash(self, artifact: dict) -> str:
        return artifact.get("artifact_hash") or stable_hash(artifact)

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": "UNKNOWN",
            "procedure": "MANAGER CONTEXT REQUIRED — define rollback for this artifact type",
            "confidence": "LOW",
        }


def handler_for_type(artifact_type: str) -> ArtifactHandler:
    t = (artifact_type or "").lower()
    if t == "terraform":
        from change_assurance.artifacts.terraform import TerraformArtifactHandler

        return TerraformArtifactHandler()
    if t in {"source_code_patch", "dependency_update"}:
        from change_assurance.artifacts.code_patch import SourceCodePatchHandler

        return SourceCodePatchHandler()
    if t in {"github_actions", "gitlab_ci", "jenkinsfile", "cicd_config"}:
        from change_assurance.artifacts.github_actions import GitHubActionsHandler

        return GitHubActionsHandler()
    if t == "dockerfile":
        from change_assurance.artifacts.dockerfile import DockerfileHandler

        return DockerfileHandler()
    if t in {"kubernetes", "helm", "k8s"}:
        from change_assurance.artifacts.kubernetes import KubernetesHandler

        return KubernetesHandler()
    return GenericArtifactHandler(artifact_type=t or "configuration_change")
