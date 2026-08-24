# change_assurance/domains/cloud/adapter.py
# Cloud Security adapter — reuses mature predeploy discovery/analysis.
# Finding status is governed by evidence quality (DIRECT proof required to CONFIRM).

from __future__ import annotations

from typing import Any

from change_assurance.domains.base import DomainAdapter
from change_assurance.domains.cloud.evidence_registry import cloud_specs
from change_assurance.evidence_quality import assess_finding_evidence
from change_assurance.models import new_evidence
from predeploy import aws_dependency_discovery as aws_disc
from predeploy import blast_radius as pre_blast
from predeploy import post_deployment_verification as postverify


class CloudSecurityAdapter(DomainAdapter):
    domain = "cloud_security"

    def capability_status(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": "AVAILABLE",
            "detail": "AWS read-only discovery + Terraform artifact analysis + evidence quality checks",
        }

    def verify_finding(self, finding: dict, context: dict) -> dict[str, Any]:
        disc = self._discover(finding, context)
        assessment = disc.get("evidence_assessment")
        if not assessment:
            assessment = assess_finding_evidence(
                finding_id=finding.get("id"),
                title=finding.get("title"),
                evidence=disc.get("evidence") or [],
                specs=cloud_specs(),
                collection_error=disc.get("error") if disc.get("status") == "FAIL" else None,
                capability_unavailable=disc.get("status") in {"SKIP", "UNAVAILABLE"},
            )
            disc["evidence_assessment"] = assessment
            disc["evidence"] = assessment.get("labeled_evidence") or disc.get("evidence") or []
            summary = dict(disc.get("summary") or {})
            summary["finding_status"] = assessment.get("finding_status") or summary.get("finding_status")
            disc["summary"] = summary

        status = (
            (assessment or {}).get("finding_status")
            or (disc.get("summary") or {}).get("finding_status")
            or "UNVERIFIED"
        )
        context["discovery"] = disc
        context["evidence_assessment"] = assessment
        return {
            "finding_status": status,
            "discovery": disc,
            "still_present": status == "CONFIRMED",
            "evidence_assessment": assessment,
            "evidence_quality": (assessment or {}).get("evidence_quality"),
        }

    def gather_evidence(self, finding: dict, context: dict) -> list[dict[str, Any]]:
        disc = context.get("discovery") or self._discover(finding, context)
        assessment = context.get("evidence_assessment") or disc.get("evidence_assessment") or {}
        out = []
        for ev in assessment.get("labeled_evidence") or disc.get("evidence") or []:
            row = new_evidence(
                finding_id=finding.get("id"),
                domain=self.domain,
                source_type="aws_api",
                source=str(ev.get("api_call") or "aws"),
                target=str(ev.get("resource_id") or ""),
                observed_value=ev.get("observed_value"),
                expected_value=ev.get("expected_value"),
                confidence=str(ev.get("confidence") or "HIGH"),
            )
            row["quality"] = ev.get("quality") or "INDIRECT"
            row["purpose"] = ev.get("purpose") or "context"
            row["api_call"] = ev.get("api_call") or row["source"]
            out.append(row)
        # DIRECT proof first — Face Advanced / Manager Mode must not lead with account summary
        out.sort(key=lambda r: 0 if str(r.get("quality") or "").upper() == "DIRECT" else 1)
        return out

    def discover_dependencies(self, change: dict, context: dict) -> list[dict[str, Any]]:
        # Prefer dependencies derived from the reviewed Terraform plan
        reviewed = change.get("reviewed_plan") or (change.get("plan") or {}).get("reviewed_plan")
        if isinstance(reviewed, dict) and reviewed.get("dependencies"):
            return list(reviewed["dependencies"])
        disc = context.get("discovery") or {}
        deps = []
        for name in disc.get("public_bucket_names") or []:
            deps.append({"type": "s3_bucket", "id": name, "relation": "public_exposure"})
        for name in disc.get("website_bucket_names") or []:
            deps.append({"type": "s3_website", "id": name, "relation": "website_hosting"})
        # Config / recorder controls: never emit opaque none_detected when we know the control class
        if (change.get("flags") or {}).get("config_recorder_enable") or str(
            context.get("finding_id") or ""
        ).upper() in {"CLOUD-LOG-002", "AWS-016"}:
            deps.append(
                {
                    "type": "config_control",
                    "id": "Config recorder/delivery enablement (plan not yet bound)",
                    "relation": "control",
                    "confidence": "MEDIUM",
                }
            )
            return deps
        if (change.get("flags") or {}).get("access_analyzer_enable"):
            deps.append(
                {
                    "type": "access_analyzer",
                    "id": "Regional Access Analyzer create (no IAM permission mutation)",
                    "relation": "additive",
                    "confidence": "HIGH",
                }
            )
            return deps
        if not deps:
            deps.append(
                {
                    "type": "workload_dependency",
                    "id": "No public/website workload dependencies identified from discovery",
                    "relation": "none",
                    "confidence": "LOW",
                }
            )
        return deps

    def classify_scope(self, change: dict, context: dict) -> str:
        reviewed = change.get("reviewed_plan") or (change.get("plan") or {}).get("reviewed_plan")
        if isinstance(reviewed, dict) and reviewed.get("region"):
            return "REGIONAL"
        disc = context.get("discovery") or {}
        return str(disc.get("scope") or "RESOURCE").upper().replace("-", "_")

    def analyze_impact(self, change: dict, context: dict) -> dict[str, Any]:
        disc = context.get("discovery") or {}
        flags = dict((change.get("flags") or {}))
        for k, v in (disc.get("flags_hint") or {}).items():
            if v:
                flags[k] = True
        if int((disc.get("summary") or {}).get("public_buckets") or 0) > 0:
            flags["public_workload_dependency"] = True
        plan_summary = (change.get("plan") or {}).get("summary") or {}
        reviewed = change.get("reviewed_plan") or (change.get("plan") or {}).get("reviewed_plan")
        # Reviewed plan actions override stale discovery/source flags for IAM/Config/etc.
        if isinstance(reviewed, dict) and (
            reviewed.get("resource_addresses")
            or reviewed.get("resources_to_create")
            or reviewed.get("summary")
        ):
            from change_assurance.plan_manager_context import flags_from_reviewed_plan

            flags = flags_from_reviewed_plan(reviewed, base_flags=flags)
        blast = pre_blast.classify_blast_radius(
            finding_ids=[context.get("finding_id")] if context.get("finding_id") else None,
            scope=str(
                "regional"
                if isinstance(reviewed, dict) and reviewed.get("region")
                else (disc.get("scope") or "resource")
            ),
            terraform_summary=plan_summary,
            discovery={
                "public_buckets": (disc.get("summary") or {}).get("public_buckets"),
                "website_buckets": (disc.get("summary") or {}).get("website_buckets"),
            },
            flags=flags,
        )
        workloads = disc.get("potentially_affected_workloads")
        if isinstance(reviewed, dict) and reviewed.get("manager_affect"):
            workloads = reviewed["manager_affect"].get("potentially_affected") or workloads
        elif flags.get("config_recorder_enable"):
            workloads = (
                "Creates AWS Config recording infrastructure in-region. "
                "Does not modify existing CloudTrail buckets or application workloads."
            )
        return {
            "blast_radius": blast,
            "workloads": workloads or "UNKNOWN",
            "flags": flags,
            "reviewed_plan": reviewed,
        }

    def calculate_risk(self, change: dict, context: dict) -> dict[str, Any]:
        impact = context.get("impact") or self.analyze_impact(change, context)
        reviewed = (
            change.get("reviewed_plan")
            or (change.get("plan") or {}).get("reviewed_plan")
            or (impact or {}).get("reviewed_plan")
        )
        if isinstance(reviewed, dict) and reviewed.get("risk"):
            risk = dict(reviewed["risk"])
            # Keep blast level aligned when plan is create-only Config
            return risk
        level = (impact.get("blast_radius") or {}).get("level") or "UNKNOWN"
        reasons = list((impact.get("blast_radius") or {}).get("reasons") or [])
        return {"level": level, "reasons": reasons, "rationale": reasons[0] if reasons else None}

    def generate_manager_questions(self, finding: dict, change: dict, context: dict) -> list[str]:
        from change_assurance.plan_manager_context import (
            all_plan_addresses,
            flags_from_reviewed_plan,
            manager_questions_for_plan,
        )

        disc = context.get("discovery") or {}
        assessment = context.get("evidence_assessment") or disc.get("evidence_assessment") or {}
        reviewed = change.get("reviewed_plan") or {}
        flags = dict(change.get("flags") or {})
        plan_addrs: list[str] = []
        if isinstance(reviewed, dict) and (
            reviewed.get("resource_addresses")
            or reviewed.get("resources_to_create")
            or reviewed.get("summary")
        ):
            plan_addrs = all_plan_addresses(reviewed)
            flags = flags_from_reviewed_plan(reviewed, base_flags=flags)
        return manager_questions_for_plan(
            finding,
            flags=flags,
            plan_addresses=plan_addrs,
            discovery=disc,
            evidence_assessment=assessment,
        )

    def build_verification_plan(self, finding: dict, change: dict, context: dict) -> dict[str, Any]:
        return postverify.verification_plan_for_finding(
            str(finding.get("id") or ""),
            finding.get("title"),
        )

    def _discover(self, finding: dict, context: dict) -> dict[str, Any]:
        if context.get("discovery"):
            return context["discovery"]
        fid = str(finding.get("id") or "")
        return aws_disc.discover_for_findings(
            [fid] if fid else [],
            [finding],
            profile=context.get("profile"),
            region=context.get("region"),
        )
