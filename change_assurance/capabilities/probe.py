# change_assurance/capabilities/probe.py
# Read-only IAM simulation for remediation-role capability preflight.
# Never attaches policies. Never uses remediation role to probe itself preferentially.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from change_assurance.capabilities.types import CapabilitySpec


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expand_resource(template: str | None, *, account_id: str, region: str) -> str | None:
    if not template:
        return None
    return template.format(account_id=account_id, region=region)


def normalize_eval_decision(decision: str | None) -> str:
    """Map IAM SimulatePrincipalPolicy EvalDecision to allow|deny|unknown."""
    d = str(decision or "").strip().lower()
    if d in {"allow", "allowed"}:
        return "allow"
    if d in {"deny", "implicitdeny", "explicitdeny"}:
        return "deny" if d == "deny" else d
    return d or "unknown"


def simulate_actions(
    *,
    source_arn: str,
    actions: list[str],
    region: str,
    probe_profiles: list[str],
    service_name_hint: str | None = None,
    resource_by_action: dict[str, str] | None = None,
) -> tuple[dict[str, str], str | None, str | None]:
    """
    Returns (action→raw EvalDecision, probe_profile_used, error_or_None).
    Prefers scanner/read profiles that can call iam:SimulatePrincipalPolicy.

    When resource_by_action maps an action to a concrete ARN, that action is
    simulated against that resource (required for scoped iam:GetRole etc.).
    Actions sharing the same resource are batched; Resource=* is the default.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError as e:
        return {}, None, f"boto3 unavailable: {e}"

    context = []
    if service_name_hint:
        context.extend(
            [
                {
                    "ContextKeyName": "iam:AWSServiceName",
                    "ContextKeyValues": [service_name_hint],
                    "ContextKeyType": "string",
                },
                {
                    "ContextKeyName": "iam:PassedToService",
                    "ContextKeyValues": [service_name_hint],
                    "ContextKeyType": "string",
                },
            ]
        )
    context.append(
        {
            "ContextKeyName": "aws:RequestedRegion",
            "ContextKeyValues": [region],
            "ContextKeyType": "string",
        }
    )

    # Group actions by simulation resource (None → omit ResourceArns → "*")
    groups: dict[str | None, list[str]] = {}
    resource_by_action = resource_by_action or {}
    for action in actions:
        res = resource_by_action.get(action) or None
        groups.setdefault(res, []).append(action)

    last_err: str | None = None
    seen: list[str] = []
    for prof in probe_profiles:
        if not prof or prof in seen:
            continue
        seen.append(prof)
        try:
            session = boto3.Session(profile_name=prof, region_name=region)
            iam = session.client("iam")
            out: dict[str, str] = {}
            for res, acts in groups.items():
                kwargs: dict[str, Any] = {
                    "PolicySourceArn": source_arn,
                    "ActionNames": list(acts),
                }
                if context:
                    kwargs["ContextEntries"] = context
                if res:
                    kwargs["ResourceArns"] = [res]
                resp = iam.simulate_principal_policy(**kwargs)
                for r in resp.get("EvaluationResults") or []:
                    action = str(r.get("EvalActionName") or "")
                    decision = str(r.get("EvalDecision") or "Unknown")
                    if action:
                        out[action] = decision
            if out:
                return out, prof, None
            last_err = f"profile={prof}: empty EvaluationResults"
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code") or type(e).__name__
            last_err = f"profile={prof}: {code}: {e}"
        except Exception as e:
            last_err = f"profile={prof}: {type(e).__name__}: {e}"
    return {}, None, last_err or "no probe profile succeeded"


def resource_map_for_spec(
    spec: CapabilitySpec,
    *,
    account_id: str,
    region: str,
) -> dict[str, str]:
    """action → expanded resource ARN for permissions that declare a resource."""
    out: dict[str, str] = {}
    for p in spec.permissions:
        expanded = expand_resource(p.resource, account_id=account_id, region=region)
        if expanded:
            out[p.action] = expanded
    return out


def classify_simulation(
    spec: CapabilitySpec,
    simulated: dict[str, str],
    *,
    probe_error: str | None = None,
) -> dict[str, Any]:
    """Map SimulatePrincipalPolicy results to READY / MISSING_PERMISSIONS / UNVERIFIABLE."""
    from change_assurance.capabilities.types import (
        MISSING_PERMISSIONS,
        READY,
        UNVERIFIABLE,
    )

    required = spec.action_names()
    if not simulated and probe_error:
        return {
            "state": UNVERIFIABLE,
            "available": [],
            "missing": [],
            "unknown": list(required),
            "detail": f"Capability probe failed: {probe_error}",
        }
    if not simulated:
        return {
            "state": UNVERIFIABLE,
            "available": [],
            "missing": [],
            "unknown": list(required),
            "detail": "No SimulatePrincipalPolicy result available",
        }

    available: list[str] = []
    missing: list[str] = []
    unknown: list[str] = []
    for action in required:
        decision = normalize_eval_decision(simulated.get(action))
        if decision == "allow":
            available.append(action)
        elif decision in {"deny", "implicitdeny", "explicitdeny"}:
            missing.append(action)
        else:
            unknown.append(action)

    if missing:
        state = MISSING_PERMISSIONS
        detail = f"Missing remediation permissions: {', '.join(missing)}"
    elif unknown:
        state = UNVERIFIABLE
        detail = f"Unable to confirm permissions: {', '.join(unknown)}"
    else:
        state = READY
        detail = (
            "Sentinel independently verified that the configured remediation identity "
            "has the permissions required to execute this reviewed remediation"
        )

    return {
        "state": state,
        "available": available,
        "missing": missing,
        "unknown": unknown,
        "detail": detail,
        "verified_at": _now(),
        "verified_via": "iam.SimulatePrincipalPolicy",
    }


def assert_no_wildcards(actions: list[str] | tuple[str, ...]) -> None:
    for a in actions:
        if a.endswith(":*") or a in {"*", "iam:*", "guardduty:*"}:
            raise ValueError(f"Wildcard permission forbidden in capability registry: {a}")
