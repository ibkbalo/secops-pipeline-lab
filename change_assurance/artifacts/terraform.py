# change_assurance/artifacts/terraform.py
# Terraform artifact handler — static kit analysis + optional reviewed-plan ingest.

from __future__ import annotations

from pathlib import Path
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
        if context.get("finding_id") and (
            not focus or str(context.get("finding_id")) not in {str(x) for x in (focus or [])}
        ):
            focus = [context.get("finding_id")] + (focus or [])
        analysis = tfplan.analyze_kit_terraform(kit, focus, try_cli=bool(context.get("try_terraform_cli")))
        # Overlay reviewed saved plan when bound on the job (source of truth for CA)
        reviewed = self._ingest_reviewed_plan(artifact, context, analysis)
        if reviewed:
            analysis = dict(analysis)
            analysis["plan"] = {
                **(analysis.get("plan") or {}),
                "status": "REVIEWED_PLAN",
                "mode": "saved_plan",
                "summary": reviewed.get("summary") or {},
                "destructive_actions": reviewed.get("destructive_actions") or "NONE",
                "resources_to_create": reviewed.get("resources_to_create") or [],
                "resources_modified": reviewed.get("resources_modified") or [],
                "resources_destroyed": reviewed.get("resources_destroyed") or [],
                "resource_addresses": reviewed.get("resource_addresses") or [],
                "reviewed_plan": reviewed,
            }
            analysis["reviewed_plan"] = reviewed
            analysis["resources"] = [
                {
                    "type": r.get("type"),
                    "name": r.get("name"),
                    "address": r.get("address"),
                    "action": "create",
                }
                for r in (reviewed.get("resources_to_create") or [])
            ] or analysis.get("resources") or []
            # CURRENT reviewed plan is authoritative for action flags — clear stale
            # source-.tf flags (e.g. IAM SLR) that are not in this plan's actions.
            from change_assurance.plan_manager_context import flags_from_reviewed_plan

            analysis["flags"] = flags_from_reviewed_plan(
                reviewed,
                base_flags=dict(analysis.get("flags") or {}),
            )

        status = (analysis.get("validate") or {}).get("status") or "VALIDATION_UNAVAILABLE"
        if status == "PASS" and analysis.get("flags", {}).get("placeholder_unresolved"):
            status = "FAIL"
        # Validate alone is not plan approval
        if reviewed:
            status_note = "ARTIFACT_VALIDATED_PLAN_REVIEWED"
        else:
            status_note = "ARTIFACT_VALIDATED_PLAN_NOT_REVIEWED"
        scope = analysis.get("artifact_scope") or {}
        return {
            "status": status,
            "errors": (analysis.get("validate") or {}).get("errors") or [],
            "analysis": analysis,
            "mode": (analysis.get("validate") or {}).get("mode") or "static",
            "artifact_scope": scope,
            "relevant_artifacts": scope.get("paths") or analysis.get("files") or [],
            "placeholders": analysis.get("placeholders") or [],
            "plan_review_status": status_note,
            "reviewed_plan_bound": bool(reviewed),
        }

    def _ingest_reviewed_plan(
        self, artifact: dict, context: dict, analysis: dict[str, Any]
    ) -> dict[str, Any] | None:
        job = context.get("job") or {}
        finding_id = str(context.get("finding_id") or artifact.get("finding_id") or "")
        try:
            from change_assurance.plan_ingestion import (
                ingest_reviewed_plan_for_finding,
                sha256_file,
                validate_plan_artifact_binding,
            )
        except Exception:
            return None

        # Resolve source .tf path + sha from kit
        src_path = None
        src_sha = None
        kit = context.get("kit_path") or (artifact.get("meta") or {}).get("kit_path")
        scope = analysis.get("artifact_scope") or {}
        tf_paths = scope.get("tf_paths") or [
            p for p in (scope.get("paths") or []) if str(p).lower().endswith(".tf")
        ]
        if kit and tf_paths:
            kit_p = Path(str(kit))
            rel = tf_paths[0]
            candidates = []
            if kit_p.is_dir():
                candidates.append(kit_p / rel)
            elif kit_p.suffix.lower() == ".zip":
                candidates.append(kit_p.with_suffix("") / rel)
            for c in candidates:
                if c.is_file():
                    src_path = c
                    src_sha = sha256_file(c)
                    break
        # Prefer prerequisite resolution sha when present
        resolutions = (job.get("prerequisite_resolutions") or {}).get(finding_id) or {}
        if resolutions.get("artifact_sha256"):
            src_sha = str(resolutions["artifact_sha256"]).lower()
        if resolutions.get("artifact_path") and Path(str(resolutions["artifact_path"])).is_file():
            src_path = Path(str(resolutions["artifact_path"]))
            if not src_sha:
                src_sha = sha256_file(src_path)

        region = (
            context.get("region")
            or ((context.get("discovery") or {}).get("region"))
            or job.get("region")
        )
        account = (
            context.get("account_id")
            or ((context.get("discovery") or {}).get("account_id"))
            or job.get("aws_account_id")
        )
        try:
            reviewed = ingest_reviewed_plan_for_finding(
                job,
                finding_id,
                source_artifact_path=src_path,
                source_artifact_sha256=src_sha,
                account_id=str(account) if account else None,
                region=str(region) if region else None,
                plan_json=context.get("reviewed_plan_json"),
            )
        except Exception as exc:
            artifact.setdefault("meta", {})["reviewed_plan_error"] = str(exc)
            return None
        if not reviewed:
            return None

        bind = validate_plan_artifact_binding(
            reviewed,
            current_artifact_sha256=src_sha,
            expected_account=str(account) if account else None,
            expected_region=str(region) if region else None,
        )
        reviewed["binding_check"] = bind
        if not bind.get("valid"):
            reviewed["invalidated"] = True
            reviewed["invalidation_reasons"] = bind.get("reasons") or []
        # Stash on artifact meta for approval binding
        meta = artifact.setdefault("meta", {})
        meta["plan_hash"] = reviewed.get("plan_content_hash")
        meta["saved_plan_sha256"] = reviewed.get("saved_plan_sha256")
        meta["source_artifact_sha256"] = reviewed.get("source_artifact_sha256") or src_sha
        meta["plan_account_id"] = reviewed.get("account_id")
        meta["plan_region"] = reviewed.get("region")
        meta["execution_role"] = reviewed.get("execution_role")
        meta["execution_identity"] = reviewed.get("execution_identity")
        meta["execution_profile"] = reviewed.get("execution_profile")
        meta["saved_plan_path"] = reviewed.get("saved_plan_path")
        meta["plan_generated_at"] = reviewed.get("plan_generated_at")
        meta["plan_review_status"] = (
            "PLAN_INVALIDATED" if reviewed.get("invalidated") else "PLAN_REVIEWED"
        )
        return reviewed

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        validation = artifact.get("validation") or self.validate(artifact, context)
        analysis = validation.get("analysis") or {}
        plan = analysis.get("plan") or {}
        reviewed = analysis.get("reviewed_plan") or plan.get("reviewed_plan")
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
        out: dict[str, Any] = {
            "actions": actions or [{"action": "UNKNOWN"}],
            "plan": plan,
            "resources": analysis.get("resources") or [],
            "placeholders": analysis.get("placeholders") or [],
            "flags": analysis.get("flags") or {},
        }
        if reviewed:
            out["reviewed_plan"] = reviewed
            out["dependencies"] = reviewed.get("dependencies") or []
        return out

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
        meta = artifact.get("meta") or {}
        # Prefer real source-file SHA when available (plan-aware binding)
        if meta.get("source_artifact_sha256"):
            return str(meta["source_artifact_sha256"]).lower()
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
