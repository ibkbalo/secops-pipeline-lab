# change_assurance/capabilities/__init__.py
"""Remediation execution capability registry, preflight, and bootstrap provisioning."""

from change_assurance.capabilities.assess import (
    apply_capability_to_report,
    assess_execution_capability,
)
from change_assurance.capabilities.registry import (
    all_specs,
    ensure_default_capabilities,
    match_capability,
    register_capability,
)
from change_assurance.capabilities.freshness import capability_needs_reprobe
from change_assurance.capabilities.types import (
    BOOTSTRAP_PENDING_ADMIN,
    BOOTSTRAP_SATISFIED,
    BOOTSTRAP_VERIFIED,
    EXECUTION_BLOCKED_PENDING_CAPABILITY,
    EXECUTION_READY,
    MISSING_PERMISSIONS,
    NOT_SUPPORTED,
    READY,
    UNVERIFIABLE,
)

__all__ = [
    "READY",
    "MISSING_PERMISSIONS",
    "UNVERIFIABLE",
    "NOT_SUPPORTED",
    "BOOTSTRAP_PENDING_ADMIN",
    "BOOTSTRAP_SATISFIED",
    "BOOTSTRAP_VERIFIED",
    "EXECUTION_BLOCKED_PENDING_CAPABILITY",
    "EXECUTION_READY",
    "register_capability",
    "match_capability",
    "all_specs",
    "ensure_default_capabilities",
    "assess_execution_capability",
    "apply_capability_to_report",
    "capability_needs_reprobe",
]
