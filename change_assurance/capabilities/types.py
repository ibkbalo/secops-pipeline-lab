# change_assurance/capabilities/types.py
# Remediation capability / bootstrap types — separate from finding evidence.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VERSION = "0.1.0-capability"

# Capability preflight states
READY = "READY"
MISSING_PERMISSIONS = "MISSING_PERMISSIONS"
UNVERIFIABLE = "UNVERIFIABLE"
NOT_SUPPORTED = "NOT_SUPPORTED"

# Identity roles (security separation)
IDENTITY_SCANNER_PLANNER = "scanner_planner"
IDENTITY_REMEDIATION_EXECUTOR = "remediation_executor"
IDENTITY_BOOTSTRAP_PROVISIONER = "bootstrap_provisioner"

# Bootstrap authorization (never equals remediation manager decision)
BOOTSTRAP_PENDING_ADMIN = "READY_FOR_ADMIN_AUTHORIZATION"
BOOTSTRAP_AUTHORIZED = "ADMIN_AUTHORIZED"  # never set by this task
BOOTSTRAP_NOT_REQUIRED = "NOT_REQUIRED"
# After independent permission proof (admin installed policy externally)
BOOTSTRAP_SATISFIED = "SATISFIED"
BOOTSTRAP_VERIFIED = "VERIFIED"  # alias surfaced alongside SATISFIED

# Execution gating when capability missing
EXECUTION_BLOCKED_PENDING_CAPABILITY = "BLOCKED_PENDING_CAPABILITY"
# Capability READY; manager has not yet authorized ordinary remediation
EXECUTION_READY = "READY_PENDING_MANAGER_AUTHORIZATION"
EXECUTION_NOT_PERFORMED = "NOT_PERFORMED"


@dataclass(frozen=True)
class PermissionRequirement:
    action: str
    why: str
    resource: str | None = None
    condition: dict[str, Any] | None = None


@dataclass
class CapabilitySpec:
    """Declared execution capability for a supported remediation control."""

    capability_id: str
    control_ids: tuple[str, ...]
    title_tokens: tuple[str, ...]
    service: str
    permissions: tuple[PermissionRequirement, ...]
    inline_policy_name: str
    description: str = ""
    verification_permissions: tuple[str, ...] = ()

    def action_names(self) -> list[str]:
        return [p.action for p in self.permissions]


def empty_assessment(*, capability_id: str | None = None, state: str = NOT_SUPPORTED) -> dict[str, Any]:
    return {
        "version": VERSION,
        "capability_id": capability_id,
        "state": state,
        "permission_ready": state if state in {READY, MISSING_PERMISSIONS, UNVERIFIABLE} else UNVERIFIABLE,
        "required_permissions": [],
        "available_permissions": [],
        "missing_permissions": [],
        "unknown_permissions": [],
        "execution_identity": None,
        "planning_identity": None,
        "bootstrap_identity_path": None,
        "verified_via": None,
        "verified_at": None,
        "probe_profile": None,
        "bootstrap": None,
        "self_bootstrap_forbidden": True,
        "scanner_bootstrap_forbidden": True,
        "aws_modified": False,
        "auto_attached": False,
    }
