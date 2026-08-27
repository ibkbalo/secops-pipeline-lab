# change_assurance/plan_manager_context.py
# Derive Manager Mode questions / prepare lists from the CURRENT reviewed plan
# (and partial-execution lifecycle), not stale original-remediation metadata.

from __future__ import annotations

from typing import Any


_ACTION_FLAG_KEYS = (
    "iam_change",
    "config_recorder_enable",
    "networking_change",
    "access_analyzer_enable",
)


def _addr_str(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("address") or item.get("type") or item.get("name") or "")
    return str(item or "")


def plan_action_addresses(reviewed: dict[str, Any] | None) -> dict[str, list[str]]:
    """Addresses grouped by action from a normalized / ingested reviewed plan."""
    reviewed = reviewed or {}
    creates: list[str] = []
    modifies: list[str] = []
    destroys: list[str] = []
    for r in reviewed.get("resources_to_create") or []:
        a = _addr_str(r)
        if a:
            creates.append(a)
    for r in reviewed.get("resources_modified") or []:
        a = _addr_str(r)
        if a:
            modifies.append(a)
    for r in reviewed.get("resources_destroyed") or []:
        a = _addr_str(r)
        if a:
            destroys.append(a)
    # Recovery / summary-only plans often expose flat resource_addresses as creates
    if not creates and not modifies and not destroys:
        for a in reviewed.get("resource_addresses") or []:
            s = _addr_str(a)
            if s:
                creates.append(s)
    return {"create": creates, "modify": modifies, "destroy": destroys}


def all_plan_addresses(reviewed: dict[str, Any] | None) -> list[str]:
    groups = plan_action_addresses(reviewed)
    out: list[str] = []
    seen: set[str] = set()
    for key in ("create", "modify", "destroy"):
        for a in groups[key]:
            if a not in seen:
                seen.add(a)
                out.append(a)
    return out


def flags_from_plan_addresses(
    addresses: list[str] | None,
    *,
    base_flags: dict[str, Any] | None = None,
    clear_action_flags: bool = True,
) -> dict[str, Any]:
    """Recompute action flags from CURRENT plan addresses (not source .tf alone)."""
    flags = dict(base_flags or {})
    action_keys = _ACTION_FLAG_KEYS + ("guardduty_enable",)
    if clear_action_flags:
        for k in action_keys:
            flags[k] = False
    text = " ".join(str(a) for a in (addresses or [])).lower()
    if "aws_iam_" in text:
        flags["iam_change"] = True
    if "aws_config_" in text:
        flags["config_recorder_enable"] = True
    if "aws_accessanalyzer_" in text or "accessanalyzer" in text.replace("_", ""):
        flags["access_analyzer_enable"] = True
    if "aws_guardduty_" in text or "guardduty" in text.replace("_", ""):
        flags["guardduty_enable"] = True
    if any(
        tok in text
        for tok in ("aws_security_group", "aws_network_acl", "aws_vpc", "aws_subnet", "aws_route")
    ):
        flags["networking_change"] = True
    return flags


def flags_from_reviewed_plan(
    reviewed: dict[str, Any] | None,
    *,
    base_flags: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return flags_from_plan_addresses(
        all_plan_addresses(reviewed),
        base_flags=base_flags,
        clear_action_flags=True,
    )


def _has_iam_action(addresses: list[str]) -> bool:
    return any("aws_iam_" in a.lower() for a in addresses)


def _has_config_action(addresses: list[str]) -> bool:
    return any("aws_config_" in a.lower() for a in addresses)


def _has_guardduty_action(addresses: list[str]) -> bool:
    return any("aws_guardduty_" in a.lower() for a in addresses)


def _has_s3_delivery_action(addresses: list[str]) -> bool:
    return any(
        ("aws_s3_" in a.lower() and "config" in a.lower()) or "delivery_channel" in a.lower()
        for a in addresses
    )


def manager_questions_for_plan(
    finding: dict[str, Any] | None,
    *,
    flags: dict[str, Any] | None = None,
    plan_addresses: list[str] | None = None,
    discovery: dict[str, Any] | None = None,
    evidence_assessment: dict[str, Any] | None = None,
) -> list[str]:
    """
    Manager questions derived from CURRENT plan actions + unresolved business context.
    Blocking items use MANAGER CONTEXT REQUIRED.
    Informational items use MANAGER CONSIDERATION (do not force RECOMMEND_REVIEW alone).
    """
    finding = finding or {}
    flags = dict(flags or {})
    addrs = list(plan_addresses or [])
    disc = discovery or {}
    assessment = evidence_assessment or disc.get("evidence_assessment") or {}
    qs: list[str] = []

    if assessment.get("finding_status") == "UNVERIFIED":
        qs.append(
            "MANAGER CONTEXT REQUIRED: Evidence is insufficient to prove this control — "
            "confirm the control state manually or re-run discovery with the correct API."
        )
    if int((disc.get("summary") or {}).get("public_buckets") or 0) > 0:
        qs.append("MANAGER CONTEXT REQUIRED: Are any S3 buckets intentionally public?")
    if int((disc.get("summary") or {}).get("website_buckets") or 0) > 0:
        qs.append(
            "MANAGER CONTEXT REQUIRED: Are static website buckets required for a business workflow?"
        )

    iam_in_plan = _has_iam_action(addrs) if addrs else bool(flags.get("iam_change"))
    if iam_in_plan:
        title_l = str(finding.get("title") or "").lower()
        fid = str(finding.get("id") or "").upper()
        # GuardDuty ordinary remediation is detector-only; IAM bootstrap is a separate
        # capability-provisioning flow — do not force break-glass CONTEXT REQUIRED.
        if "guardduty" in title_l or fid in {"CLOUD-LOG-003", "CLOUD-DFT-001"}:
            pass
        elif "access analyzer" not in title_l and fid != "CLOUD-IAM-013":
            qs.append(
                "MANAGER CONTEXT REQUIRED: Will IAM changes affect break-glass or production roles?"
            )

    if flags.get("access_analyzer_enable") or any(
        "accessanalyzer" in a.lower().replace("_", "") for a in addrs
    ):
        qs.append(
            "MANAGER CONTEXT REQUIRED: Confirm the intended Region for the account-level Access Analyzer."
        )

    config_in_plan = _has_config_action(addrs) if addrs else bool(flags.get("config_recorder_enable"))
    if config_in_plan or flags.get("config_recorder_enable"):
        qs.append("MANAGER CONTEXT REQUIRED: Confirm AWS Config recording scope is acceptable.")
        if _has_s3_delivery_action(addrs) or not addrs:
            qs.append(
                "MANAGER CONTEXT REQUIRED: Confirm dedicated Config S3 delivery location is acceptable."
            )
        qs.append("MANAGER CONTEXT REQUIRED: Confirm expected AWS Config/S3 cost is acceptable.")

    if flags.get("networking_change"):
        qs.append("MANAGER CONTEXT REQUIRED: Will networking changes interrupt legitimate traffic?")

    gd_in_plan = _has_guardduty_action(addrs) if addrs else bool(flags.get("guardduty_enable"))
    title_l = str(finding.get("title") or "").lower()
    fid = str(finding.get("id") or "").upper()
    if gd_in_plan or "guardduty" in title_l or fid in {"CLOUD-LOG-003", "CLOUD-DFT-001"}:
        region = (
            str((disc.get("region") or "")).strip()
            or str(((assessment.get("observed") or {}) if isinstance(assessment.get("observed"), dict) else {}).get("region") or "")
            or "the planned Region"
        )
        qs.append(
            "MANAGER CONSIDERATION: Enabling Amazon GuardDuty incurs AWS service cost that depends on "
            "monitored activity/features — exact future cost is not fabricated here; confirm budget fit."
        )
        qs.append(
            f"MANAGER CONSIDERATION: This remediation enables GuardDuty in {region} only — "
            "multi-region coverage is a separate decision and is not proven by this single-region plan."
        )
        qs.append(
            "MANAGER CONSIDERATION: GuardDuty is a detective control — enabling a detector does not by itself "
            "block attacks or modify application workloads."
        )

    seen: set[str] = set()
    out: list[str] = []
    for q in qs:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out


def filter_stale_manager_questions(
    questions: list[str] | None,
    *,
    plan_addresses: list[str] | None = None,
    flags: dict[str, Any] | None = None,
) -> list[str]:
    """Drop plan-irrelevant questions (e.g. IAM break-glass when no IAM in current plan)."""
    addrs = list(plan_addresses or [])
    flags = flags or {}
    iam_relevant = _has_iam_action(addrs) if addrs else bool(flags.get("iam_change"))
    out: list[str] = []
    for q in questions or []:
        ql = str(q).lower()
        if not iam_relevant and (
            "break-glass" in ql or "will iam changes" in ql or ("iam change" in ql and "break" in ql)
        ):
            continue
        out.append(str(q))
    return out


def split_prepare_resources(
    *,
    resolution_resources: list[Any] | None = None,
    already_created: list[str] | None = None,
    current_creates: list[str] | None = None,
) -> dict[str, list[str]]:
    """
    Distinguish already-created (partial execution) from current-plan creates.
    Prefer explicit current_creates when provided; otherwise subtract already_created
    from resolution_resources (and drop data sources).
    """
    already = [_addr_str(x) for x in (already_created or []) if _addr_str(x)]
    already_set = set(already)
    if current_creates is not None:
        will = [
            _addr_str(x)
            for x in current_creates
            if _addr_str(x) and _addr_str(x) not in already_set
        ]
        will = [a for a in will if not a.startswith("data.")]
        return {"already_created": already, "will_create": will, "prepare": will}

    raw = [_addr_str(x) for x in (resolution_resources or []) if _addr_str(x)]
    will = [a for a in raw if a not in already_set and not a.startswith("data.")]
    return {"already_created": already, "will_create": will, "prepare": will}
