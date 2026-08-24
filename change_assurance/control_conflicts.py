# change_assurance/control_conflicts.py
# Pre-deployment cross-control conflict analysis.
# Proposed Terraform resources are evaluated against known Sentinel controls
# BEFORE manager approval / apply — never mutates AWS, never applies.

from __future__ import annotations

from typing import Any, Callable, Protocol

VERSION = "0.1.0-xcontrol"

# Applicability classes for predicted / scanned controls
REQUIRED = "REQUIRED"
RECOMMENDED = "RECOMMENDED"
CONDITIONAL = "CONDITIONAL"
MANUAL_ONLY = "MANUAL_ONLY"
NOT_APPLICABLE = "NOT_APPLICABLE"


class ConflictAdapter(Protocol):
    def analyze(
        self,
        *,
        resource_changes: list[dict[str, Any]],
        source_terraform: str | None,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ...


_ADAPTERS: list[ConflictAdapter] = []


def register_adapter(adapter: ConflictAdapter) -> None:
    if adapter not in _ADAPTERS:
        _ADAPTERS.append(adapter)


def ensure_default_adapters() -> None:
    if _ADAPTERS:
        return
    from change_assurance.domains.cloud.s3_control_conflicts import S3ControlConflictAdapter

    register_adapter(S3ControlConflictAdapter())


def predicted_finding(
    *,
    control_family: str,
    control_id_hint: str,
    title: str,
    severity: str,
    applicability: str,
    reason: str,
    resource_address: str | None = None,
    resource_type: str | None = None,
    would_fail_after_apply: bool = True,
    auto_remediable: bool = False,
    manager_message: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": VERSION,
        "control_family": control_family,
        "control_id_hint": control_id_hint,
        "title": title,
        "severity": severity,
        "applicability": applicability,
        "reason": reason,
        "resource_address": resource_address,
        "resource_type": resource_type,
        "would_fail_after_apply": bool(would_fail_after_apply),
        "auto_remediable": bool(auto_remediable),
        "manager_message": manager_message,
        "evidence": evidence or {},
        "predicted": True,
        "aws_modified": False,
        "terraform_apply": False,
    }


def analyze_proposed_change(
    *,
    reviewed_plan: dict[str, Any] | None = None,
    source_terraform: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate a proposed Terraform plan/source against registered control adapters.
    Returns predicted secondary findings + summary for Manager Mode.
    """
    ensure_default_adapters()
    ctx = dict(context or {})
    changes: list[dict[str, Any]] = []
    if isinstance(reviewed_plan, dict):
        changes = list(reviewed_plan.get("resource_changes") or [])
        if not changes and reviewed_plan.get("raw_resource_changes"):
            changes = list(reviewed_plan.get("raw_resource_changes") or [])
        # Normalized plans may only expose addresses — synthesize minimal change rows
        if not changes:
            for addr in reviewed_plan.get("resource_addresses") or []:
                changes.append(
                    {
                        "address": addr,
                        "type": str(addr).split(".", 1)[0] if "." in str(addr) else str(addr),
                        "change": {"actions": ["create"]},
                    }
                )
            for addr in reviewed_plan.get("resources_to_create") or []:
                if isinstance(addr, str):
                    changes.append(
                        {
                            "address": addr,
                            "type": addr.split(".", 1)[0] if "." in addr else addr,
                            "change": {"actions": ["create"]},
                        }
                    )
            # Also include succeeded resources already in state (partial execution)
            for addr in ctx.get("existing_resources") or []:
                changes.append(
                    {
                        "address": addr,
                        "type": str(addr).split(".", 1)[0] if "." in str(addr) else str(addr),
                        "change": {"actions": ["no-op"]},
                        "already_exists": True,
                    }
                )

    predicted: list[dict[str, Any]] = []
    for adapter in _ADAPTERS:
        try:
            predicted.extend(
                adapter.analyze(
                    resource_changes=changes,
                    source_terraform=source_terraform,
                    context=ctx,
                )
            )
        except Exception as exc:
            predicted.append(
                predicted_finding(
                    control_family="analyzer",
                    control_id_hint="CONFLICT_ANALYZER_ERROR",
                    title="Cross-control analysis error",
                    severity="info",
                    applicability=RECOMMENDED,
                    reason=str(exc)[:300],
                    would_fail_after_apply=False,
                    auto_remediable=False,
                    manager_message="Cross-control analysis hit an error; review Terraform manually.",
                    evidence={"error": str(exc)[:300]},
                )
            )

    blocking = [
        p
        for p in predicted
        if p.get("would_fail_after_apply") and p.get("applicability") == REQUIRED
    ]
    advisory = [p for p in predicted if p not in blocking]

    fully_hardened = len(blocking) == 0 and not any(
        p.get("applicability") == REQUIRED for p in predicted
    )

    return {
        "version": VERSION,
        "predicted_secondary_findings": predicted,
        "blocking_conflicts": blocking,
        "advisory_conflicts": advisory,
        "has_blocking_conflicts": bool(blocking),
        "remediation_fully_hardened": bool(fully_hardened) and not blocking,
        "summary_line": (
            f"{len(blocking)} blocking cross-control conflict(s), "
            f"{len(advisory)} advisory note(s)."
            if predicted
            else "No predicted cross-control conflicts from registered adapters."
        ),
        "auto_apply_forbidden": True,
    }
