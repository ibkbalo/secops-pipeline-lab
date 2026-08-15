# change_assurance/domains/cloud/adapter.py
# Cloud Security adapter — reuses mature predeploy discovery/analysis.

from __future__ import annotations

from typing import Any

from change_assurance.domains.base import DomainAdapter
from change_assurance.models import new_evidence
from predeploy import aws_dependency_discovery as aws_disc
from predeploy import blast_radius as pre_blast
from predeploy import post_deployment_verification as postverify


class CloudSecurityAdapter(DomainAdapter):
    domain = "cloud_security"

    def capability_status(self) -> dict[str, Any]:
        return {"domain": self.domain, "status": "AVAILABLE", "detail": "AWS read-only discovery + Terraform artifact analysis"}

    def verify_finding(self, finding: dict, context: dict) -> dict[str, Any]:
        disc = self._discover(finding, context)
        status = (disc.get("summary") or {}).get("finding_status") or "UNKNOWN"
        return {
            "finding_status": status,
            "discovery": disc,
            "still_present": status == "CONFIRMED",
        }

    def gather_evidence(self, finding: dict, context: dict) -> list[dict[str, Any]]:
        disc = context.get("discovery") or self._discover(finding, context)
        out = []
        for ev in disc.get("evidence") or []:
            out.append(
                new_evidence(
                    finding_id=finding.get("id"),
                    domain=self.domain,
                    source_type="aws_api",
                    source=str(ev.get("api_call") or "aws"),
                    target=str(ev.get("resource_id") or ""),
                    observed_value=ev.get("observed_value"),
                    expected_value=ev.get("expected_value"),
                    confidence=str(ev.get("confidence") or "HIGH"),
                )
            )
        return out

    def discover_dependencies(self, change: dict, context: dict) -> list[dict[str, Any]]:
        disc = context.get("discovery") or {}
        deps = []
        for name in disc.get("public_bucket_names") or []:
            deps.append({"type": "s3_bucket", "id": name, "relation": "public_exposure"})
        for name in disc.get("website_bucket_names") or []:
            deps.append({"type": "s3_website", "id": name, "relation": "website_hosting"})
        if not deps:
            deps.append({"type": "none_detected", "id": None, "relation": "none"})
        return deps

    def classify_scope(self, change: dict, context: dict) -> str:
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
        blast = pre_blast.classify_blast_radius(
            finding_ids=[context.get("finding_id")] if context.get("finding_id") else None,
            scope=str(disc.get("scope") or "resource"),
            terraform_summary=plan_summary,
            discovery={
                "public_buckets": (disc.get("summary") or {}).get("public_buckets"),
                "website_buckets": (disc.get("summary") or {}).get("website_buckets"),
            },
            flags=flags,
        )
        return {
            "blast_radius": blast,
            "workloads": disc.get("potentially_affected_workloads") or "UNKNOWN",
            "flags": flags,
        }

    def calculate_risk(self, change: dict, context: dict) -> dict[str, Any]:
        impact = context.get("impact") or self.analyze_impact(change, context)
        level = (impact.get("blast_radius") or {}).get("level") or "UNKNOWN"
        # Remediation risk tracks operational blast, not finding severity.
        return {"level": level, "reasons": (impact.get("blast_radius") or {}).get("reasons") or []}

    def generate_manager_questions(self, finding: dict, change: dict, context: dict) -> list[str]:
        disc = context.get("discovery") or {}
        qs = []
        if int((disc.get("summary") or {}).get("public_buckets") or 0) > 0:
            qs.append("MANAGER CONTEXT REQUIRED: Are any S3 buckets intentionally public?")
        if int((disc.get("summary") or {}).get("website_buckets") or 0) > 0:
            qs.append("MANAGER CONTEXT REQUIRED: Are static website buckets required for a business workflow?")
        if (change.get("flags") or {}).get("iam_change"):
            qs.append("MANAGER CONTEXT REQUIRED: Will IAM changes affect break-glass or production roles?")
        if (change.get("flags") or {}).get("networking_change"):
            qs.append("MANAGER CONTEXT REQUIRED: Will networking changes interrupt legitimate traffic?")
        return qs

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
