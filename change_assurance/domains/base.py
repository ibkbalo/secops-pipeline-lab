# change_assurance/domains/base.py

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class DomainAdapter(ABC):
    domain: str = "unknown"

    @abstractmethod
    def verify_finding(self, finding: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def gather_evidence(self, finding: dict, context: dict) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def discover_dependencies(self, change: dict, context: dict) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def classify_scope(self, change: dict, context: dict) -> str:
        ...

    @abstractmethod
    def analyze_impact(self, change: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def calculate_risk(self, change: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def generate_manager_questions(self, finding: dict, change: dict, context: dict) -> list[str]:
        ...

    @abstractmethod
    def build_verification_plan(self, finding: dict, change: dict, context: dict) -> dict[str, Any]:
        ...

    def capability_status(self) -> dict[str, Any]:
        return {"domain": self.domain, "status": "AVAILABLE"}
