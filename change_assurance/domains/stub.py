# change_assurance/domains/stub.py
# Safe stub adapters for domains without full connectors yet.

from __future__ import annotations

from typing import Any

from change_assurance.domains.base import DomainAdapter
from change_assurance.models import new_evidence


class StubDomainAdapter(DomainAdapter):
    """
    Returns CAPABILITY_UNAVAILABLE rather than fabricated PASS results.
    """

    def __init__(self, domain: str, label: str, example_questions: list[str] | None = None):
        self.domain = domain
        self.label = label
        self.example_questions = example_questions or [
            "MANAGER CONTEXT REQUIRED: Provide business intent for this change."
        ]

    def capability_status(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": "CAPABILITY_UNAVAILABLE",
            "detail": f"{self.label} connector not fully integrated — manager review required",
        }

    def verify_finding(self, finding: dict, context: dict) -> dict[str, Any]:
        return {
            "finding_status": "UNKNOWN",
            "still_present": None,
            "capability": "CAPABILITY_UNAVAILABLE",
            "note": "Live verification connector unavailable for this domain",
        }

    def gather_evidence(self, finding: dict, context: dict) -> list[dict[str, Any]]:
        return [
            new_evidence(
                finding_id=finding.get("id"),
                domain=self.domain,
                source_type="static_analysis",
                source="stub_adapter",
                observed_value={"capability": "CAPABILITY_UNAVAILABLE"},
                confidence="LOW",
            )
        ]

    def discover_dependencies(self, change: dict, context: dict) -> list[dict[str, Any]]:
        return [{"type": "UNKNOWN", "id": None, "relation": "UNKNOWN", "capability": "CAPABILITY_UNAVAILABLE"}]

    def classify_scope(self, change: dict, context: dict) -> str:
        return "UNKNOWN"

    def analyze_impact(self, change: dict, context: dict) -> dict[str, Any]:
        return {
            "blast_radius": {
                "level": "UNKNOWN",
                "reasons": ["Domain connector unavailable — cannot compute blast radius"],
                "scope": "UNKNOWN",
            },
            "workloads": "UNKNOWN",
            "flags": {},
            "capability": "CAPABILITY_UNAVAILABLE",
        }

    def calculate_risk(self, change: dict, context: dict) -> dict[str, Any]:
        return {
            "level": "UNKNOWN",
            "reasons": ["Domain connector unavailable"],
            "capability": "CAPABILITY_UNAVAILABLE",
        }

    def generate_manager_questions(self, finding: dict, change: dict, context: dict) -> list[str]:
        return list(self.example_questions)

    def build_verification_plan(self, finding: dict, change: dict, context: dict) -> dict[str, Any]:
        return {
            "finding_id": finding.get("id"),
            "method": "manual_or_future_connector",
            "steps": [
                "Apply only after manager approval",
                "Re-run the originating agent scan",
                f"Confirm {finding.get('id')} is cleared",
            ],
            "pass_criteria": "Finding cleared on re-scan + domain-specific checks when connector exists",
            "capability": "CAPABILITY_UNAVAILABLE",
        }


def security_engineering_adapter() -> StubDomainAdapter:
    return StubDomainAdapter(
        "security_engineering",
        "Security Engineering",
        [
            "MANAGER CONTEXT REQUIRED: Could this lock out users or service accounts?",
            "MANAGER CONTEXT REQUIRED: Is this control still required by production?",
        ],
    )


def ai_security_adapter() -> StubDomainAdapter:
    return StubDomainAdapter(
        "ai_security",
        "AI Security",
        [
            "MANAGER CONTEXT REQUIRED: Is this AI tool required for an approved business workflow?",
            "MANAGER CONTEXT REQUIRED: Could removing this tool reduce legitimate agent usefulness?",
        ],
    )
