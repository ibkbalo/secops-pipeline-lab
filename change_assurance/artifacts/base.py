# change_assurance/artifacts/base.py

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ArtifactHandler(ABC):
    artifact_type: str = "unknown"

    @abstractmethod
    def detect(self, artifact: dict) -> bool:
        ...

    @abstractmethod
    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        ...

    @abstractmethod
    def calculate_hash(self, artifact: dict) -> str:
        ...

    @abstractmethod
    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        ...
