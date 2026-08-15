# change_assurance/artifacts/terraform.py
# Terraform artifact handler — reuses predeploy terraform analysis.

from __future__ import annotations

from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash
from predeploy import terraform_plan_analysis as tfplan


class TerraformArtifactHandler(ArtifactHandler):
    artifact_type = "terraform"

    def detect(self, artifact: dict) -> bool:
        return str(artifact.get("artifact_type") or "").lower() == "terraform"

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        kit = context.get("kit_path") or artifact.get("meta", {}).get("kit_path")
        focus = [artifact.get("finding_id")] if artifact.get("finding_id") else None
        analysis = tfplan.analyze_kit_terraform(kit, focus, try_cli=bool(context.get("try_terraform_cli")))
        status = (analysis.get("validate") or {}).get("status") or "VALIDATION_UNAVAILABLE"
        if status == "PASS" and analysis.get("flags", {}).get("placeholder_unresolved"):
            status = "FAIL"
        return {
            "status": status,
            "errors": (analysis.get("validate") or {}).get("errors") or [],
            "analysis": analysis,
            "mode": (analysis.get("validate") or {}).get("mode") or "static",
        }

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        validation = artifact.get("validation") or self.validate(artifact, context)
        analysis = validation.get("analysis") or {}
        plan = analysis.get("plan") or {}
        summary = plan.get("summary") or {}
        actions = []
        for _ in range(int(summary.get("create") or 0)):
            actions.append({"action": "CREATE"})
        for _ in range(int(summary.get("modify") or 0)):
            actions.append({"action": "UPDATE"})
        for _ in range(int(summary.get("replace") or 0)):
            actions.append({"action": "REPLACE"})
        for _ in range(int(summary.get("destroy") or 0)):
            actions.append({"action": "DELETE"})
        return {
            "actions": actions or [{"action": "UNKNOWN"}],
            "plan": plan,
            "resources": analysis.get("resources") or [],
            "placeholders": analysis.get("placeholders") or [],
            "flags": analysis.get("flags") or {},
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        changes = artifact.get("proposed_changes") or self.analyze_changes(artifact, context)
        flags = (changes.get("flags") if isinstance(changes, dict) else {}) or {}
        plan = (changes.get("plan") if isinstance(changes, dict) else {}) or {}
        destructive = plan.get("destructive_actions") == "PRESENT" or flags.get("destructive_tf")
        return {
            "destructive": bool(destructive),
            "details": plan.get("destructive_actions") or "NONE",
        }

    def calculate_hash(self, artifact: dict) -> str:
        return artifact.get("artifact_hash") or stable_hash(
            {
                "type": artifact.get("artifact_type"),
                "files": artifact.get("source_files"),
                "preview": artifact.get("content_preview"),
            }
        )

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": True,
            "procedure": (
                "Revert Terraform state/console change using prior export; "
                "re-apply previous configuration; re-scan control."
            ),
            "confidence": "MEDIUM",
        }
