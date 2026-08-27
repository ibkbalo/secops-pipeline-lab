# change_assurance/capabilities/assess.py
# Preflight: can the remediation identity execute this supported control?

from __future__ import annotations

from typing import Any

from change_assurance.capabilities.bootstrap import build_bootstrap_package
from change_assurance.capabilities.identities import (
    DEFAULT_SCANNER_PROFILE,
    resolve_identities,
)
from change_assurance.capabilities.probe import (
    assert_no_wildcards,
    classify_simulation,
    resource_map_for_spec,
    simulate_actions,
)
from change_assurance.capabilities.registry import match_capability
from change_assurance.capabilities.types import (
    BOOTSTRAP_NOT_REQUIRED,
    BOOTSTRAP_PENDING_ADMIN,
    BOOTSTRAP_SATISFIED,
    BOOTSTRAP_VERIFIED,
    EXECUTION_BLOCKED_PENDING_CAPABILITY,
    EXECUTION_NOT_PERFORMED,
    EXECUTION_READY,
    IDENTITY_BOOTSTRAP_PROVISIONER,
    IDENTITY_REMEDIATION_EXECUTOR,
    IDENTITY_SCANNER_PLANNER,
    MISSING_PERMISSIONS,
    NOT_SUPPORTED,
    READY,
    UNVERIFIABLE,
    VERSION,
    empty_assessment,
)


def _satisfied_bootstrap(
    spec: Any,
    *,
    account_id: str,
    region: str,
    role_name: str,
    finding_id: str | None,
    verified_at: str | None,
    verified_via: str | None,
) -> dict[str, Any]:
    """Installation state after independent permission proof — not ordinary remediation."""
    return {
        "version": VERSION,
        "kind": "BOOTSTRAP_CAPABILITY_PROVISIONING",
        "label": "BOOTSTRAP / CAPABILITY PROVISIONING",
        "capability_id": spec.capability_id,
        "finding_id_hint": finding_id,
        "service": spec.service,
        "inline_policy_name": spec.inline_policy_name,
        "role_name": role_name,
        "authorization_status": BOOTSTRAP_SATISFIED,
        "install_state": BOOTSTRAP_SATISFIED,
        "verification_state": BOOTSTRAP_VERIFIED,
        "satisfied": True,
        "verified_at": verified_at,
        "verified_via": verified_via,
        "executable_by_remediation_role": False,
        "executable_by_scanner": False,
        "requires_admin_bootstrap": False,
        "self_escalation_forbidden": True,
        "aws_modified": False,
        "auto_applied": False,
        "ordinary_remediation_note": (
            "Capability verified. Ordinary remediation is the control artifact only "
            f"(e.g. terraform/{finding_id or 'CONTROL'}.tf) — bootstrap IAM is installation state."
        ),
    }


def assess_execution_capability(
    *,
    finding_id: str | None,
    title: str | None = None,
    job: dict[str, Any] | None = None,
    account_id: str | None = None,
    region: str | None = None,
    simulated: dict[str, str] | None = None,
    probe_error: str | None = None,
    probe_profile: str | None = None,
    run_live_probe: bool = True,
) -> dict[str, Any]:
    """
    Answer: can the configured remediation identity execute this supported remediation?
    Does not alter finding evidence. Never writes AWS.
    """
    job = job or {}
    acct = str(account_id or job.get("aws_account_id") or "").strip()
    reg = str(region or job.get("region") or "us-east-1")
    idents = resolve_identities(job, account_id=acct or None)
    executor = idents[IDENTITY_REMEDIATION_EXECUTOR]
    planner = idents[IDENTITY_SCANNER_PLANNER]

    spec = match_capability(finding_id=finding_id, title=title)
    if not spec:
        out = empty_assessment(state=NOT_SUPPORTED)
        out["detail"] = "No execution capability registered for this finding"
        out["identities"] = idents
        out["execution_gate"] = EXECUTION_NOT_PERFORMED
        return out

    assert_no_wildcards(spec.action_names())

    sim = dict(simulated or {})
    err = probe_error
    prof = probe_profile
    if run_live_probe and not sim and not err:
        source_arn = str(executor.get("identity") or "")
        if source_arn.startswith("arn:aws:iam::"):
            service_hint = None
            if spec.service == "guardduty":
                service_hint = "guardduty.amazonaws.com"
            elif spec.service == "config":
                service_hint = "config.amazonaws.com"
            elif spec.service == "accessanalyzer":
                service_hint = "access-analyzer.amazonaws.com"
            sim, prof, err = simulate_actions(
                source_arn=source_arn,
                actions=spec.action_names(),
                region=reg,
                probe_profiles=[
                    str(planner.get("profile") or DEFAULT_SCANNER_PROFILE),
                    DEFAULT_SCANNER_PROFILE,
                ],
                service_name_hint=service_hint,
                resource_by_action=resource_map_for_spec(
                    spec, account_id=acct or "000000000000", region=reg
                ),
            )
        else:
            err = "missing remediation execution identity ARN"

    classified = classify_simulation(spec, sim, probe_error=err)
    state = classified["state"]

    required_rows = [
        {
            "action": p.action,
            "why": p.why,
            "resource": p.resource,
            "condition": p.condition,
        }
        for p in spec.permissions
    ]

    bootstrap = None
    auth_status = BOOTSTRAP_NOT_REQUIRED
    role_name = str(executor.get("role_name") or "SentinelStacksRemediationRole")
    if state == MISSING_PERMISSIONS:
        bootstrap = build_bootstrap_package(
            spec,
            account_id=acct or "unknown",
            region=reg,
            role_name=role_name,
            finding_id=finding_id,
            missing_permissions=list(classified.get("missing") or []),
            identities=idents,
        )
        auth_status = BOOTSTRAP_PENDING_ADMIN
    elif state == READY:
        bootstrap = _satisfied_bootstrap(
            spec,
            account_id=acct or "unknown",
            region=reg,
            role_name=role_name,
            finding_id=finding_id,
            verified_at=classified.get("verified_at"),
            verified_via=classified.get("verified_via"),
        )
        auth_status = BOOTSTRAP_SATISFIED

    if state == READY:
        gate = EXECUTION_READY  # READY_PENDING_MANAGER_AUTHORIZATION
        exec_ready = True
    elif state == MISSING_PERMISSIONS:
        gate = EXECUTION_BLOCKED_PENDING_CAPABILITY
        exec_ready = False
    else:
        gate = EXECUTION_BLOCKED_PENDING_CAPABILITY
        exec_ready = False

    return {
        "version": VERSION,
        "capability_id": spec.capability_id,
        "control_ids": list(spec.control_ids),
        "service": spec.service,
        "state": state,
        "permission_ready": state,  # READY | MISSING_PERMISSIONS | UNVERIFIABLE
        "detail": classified.get("detail"),
        "required_permissions": required_rows,
        "available_permissions": classified.get("available") or [],
        "missing_permissions": classified.get("missing") or [],
        "unknown_permissions": classified.get("unknown") or [],
        "execution_identity": executor.get("identity"),
        "planning_identity": planner.get("identity"),
        "planning_profile": planner.get("profile"),
        "bootstrap_identity_path": idents.get(IDENTITY_BOOTSTRAP_PROVISIONER),
        "bootstrap_executor_available": idents.get("bootstrap_executor_available"),
        "verified_via": classified.get("verified_via"),
        "verified_at": classified.get("verified_at"),
        "probe_profile": prof,
        "bootstrap": bootstrap,
        "bootstrap_authorization_status": auth_status,
        "bootstrap_install_state": (bootstrap or {}).get("install_state")
        or (BOOTSTRAP_SATISFIED if state == READY else None),
        "bootstrap_verification_state": (bootstrap or {}).get("verification_state")
        or (BOOTSTRAP_VERIFIED if state == READY else None),
        "execution_gate": gate,
        "execution_capability_ready": exec_ready,
        "self_bootstrap_forbidden": True,
        "scanner_bootstrap_forbidden": True,
        "remediation_authorization_separate": True,
        "finding_evidence_unaffected": True,
        "aws_modified": False,
        "auto_attached": False,
        "identities": idents,
        # Ordinary remediation stays control-only once capability READY
        "ordinary_remediation_includes_iam": False,
    }


def apply_capability_to_report(
    report: dict[str, Any],
    job: dict[str, Any],
    finding: dict[str, Any] | None,
    *,
    run_live_probe: bool = True,
) -> dict[str, Any]:
    """
    Attach capability preflight to a Change Assurance report.
    Does not mutate finding evidence. Blocks execution when capability missing.
    """
    from change_assurance.capabilities.freshness import capability_needs_reprobe

    finding = finding or {}
    fid = str(finding.get("id") or report.get("primary_finding_id") or "")
    title = str(finding.get("title") or "")

    prior = report.get("execution_capability") or {}
    # Avoid hammering IAM when a recently verified READY result is still fresh.
    if (
        run_live_probe
        and str(prior.get("state") or "") == READY
        and str(prior.get("capability_id") or "")
        and not capability_needs_reprobe(prior)
    ):
        assessment = dict(prior)
        report["execution_capability"] = assessment
        report["permission_ready"] = assessment.get("permission_ready")
        report["execution_permission_assessment"] = assessment
        report["planning_profile"] = assessment.get("planning_profile")
        report["planning_identity"] = assessment.get("planning_identity")
        report["capability_bootstrap"] = assessment.get("bootstrap")
        report["bootstrap_authorization_status"] = assessment.get("bootstrap_authorization_status")
        report["execution_gate"] = assessment.get("execution_gate")
        report["execution_ready"] = bool(report.get("deployment_ready"))
        report["remediation_prerequisites"] = [
            p
            for p in (report.get("remediation_prerequisites") or [])
            if str((p or {}).get("id") or "")
            not in {"guardduty_write_permission", "execution_capability"}
        ]
        report["recommendation_reasons"] = [
            r
            for r in (report.get("recommendation_reasons") or [])
            if "Execution capability:" not in str(r)
        ]
        report.pop("staged_remediation", None)
        report.pop("guardduty_permission_package", None)
        return assessment

    assessment = assess_execution_capability(
        finding_id=fid,
        title=title,
        job=job,
        account_id=str(
            (report.get("reviewed_plan") or {}).get("account_id")
            or job.get("aws_account_id")
            or ""
        )
        or None,
        region=str(
            (report.get("reviewed_plan") or {}).get("region") or job.get("region") or "us-east-1"
        ),
        run_live_probe=run_live_probe,
    )

    report["execution_capability"] = assessment
    report["permission_ready"] = assessment.get("permission_ready")
    report["execution_permission_assessment"] = assessment  # backward-compatible key
    report["planning_profile"] = assessment.get("planning_profile")
    report["planning_identity"] = assessment.get("planning_identity")
    report["capability_bootstrap"] = assessment.get("bootstrap")
    report["bootstrap_authorization_status"] = assessment.get("bootstrap_authorization_status")
    report["execution_gate"] = assessment.get("execution_gate")

    # Clear legacy GuardDuty "staged security remediation" coupling
    report.pop("staged_remediation", None)
    report.pop("guardduty_permission_package", None)

    if assessment.get("state") == READY:
        report["execution_ready"] = bool(report.get("deployment_ready"))
        # Drop capability prereq rows from ordinary remediation prerequisites
        report["remediation_prerequisites"] = [
            p
            for p in (report.get("remediation_prerequisites") or [])
            if str((p or {}).get("id") or "")
            not in {"guardduty_write_permission", "execution_capability"}
        ]
        # Strip stale "capability missing" reason lines once verified READY
        report["recommendation_reasons"] = [
            r
            for r in (report.get("recommendation_reasons") or [])
            if "Execution capability:" not in str(r)
        ]
    else:
        report["execution_ready"] = False
        prereqs = [
            p
            for p in (report.get("remediation_prerequisites") or [])
            if str((p or {}).get("id") or "")
            not in {"guardduty_write_permission", "execution_capability"}
        ]
        if assessment.get("state") != NOT_SUPPORTED:
            prereqs.append(
                {
                    "id": "execution_capability",
                    "kind": "CAPABILITY_BOOTSTRAP",
                    "label": "Remediation execution capability",
                    "detail": assessment.get("detail"),
                    "status": assessment.get("state"),
                    "permission_ready": assessment.get("permission_ready"),
                    "bootstrap_authorization_status": assessment.get(
                        "bootstrap_authorization_status"
                    ),
                    "artifact": (assessment.get("bootstrap") or {}).get("terraform_relpath"),
                }
            )
        report["remediation_prerequisites"] = prereqs
        reasons = [
            r
            for r in (report.get("recommendation_reasons") or [])
            if "Execution capability:" not in str(r)
        ]
        reasons.append(
            f"Execution capability: {assessment.get('state')} — "
            "ordinary remediation is not executable until administrator provisions capability"
        )
        report["recommendation_reasons"] = reasons

    return assessment
