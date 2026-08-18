# change_assurance/evidence_quality.py
# Generic evidence relevance & sufficiency checks (domain-agnostic).
# Never fabricate evidence. Never confirm from unrelated/indirect proof alone.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

VERSION = "0.1.0-eq"

QUALITY_DIRECT = "DIRECT"
QUALITY_INDIRECT = "INDIRECT"
QUALITY_INSUFFICIENT = "INSUFFICIENT"
QUALITY_UNAVAILABLE = "UNAVAILABLE"
QUALITY_ERROR = "ERROR"

STATUS_CONFIRMED = "CONFIRMED"
STATUS_PASS = "PASS"  # alias used in some UIs; CA also uses ALREADY_REMEDIATED
STATUS_REMEDIATED = "ALREADY_REMEDIATED"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_ERROR = "ERROR"
STATUS_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceSpec:
    """Contract: finding → required property → source → evaluation."""

    control_key: str
    title_tokens: tuple[str, ...]  # all tokens must appear in title (lowercase)
    id_prefixes: tuple[str, ...] = ()
    preferred_sources: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    operator: str = "=="  # >=, <=, ==, !=, truthy, falsy, all_true
    expected_value: Any = None
    human_label: str = ""
    human_expected: str = ""
    domain: str = "cloud_security"
    # Optional custom evaluator: (observed_dict) -> (ok: bool|None, detail)
    # ok True = control satisfied; False = violated; None = cannot evaluate
    custom_eval: Callable[[dict[str, Any]], tuple[bool | None, str]] | None = field(
        default=None, compare=False, hash=False, repr=False
    )


def _lower(s: Any) -> str:
    return str(s or "").lower()


def match_spec(
    specs: list[EvidenceSpec],
    *,
    finding_id: str | None = None,
    title: str | None = None,
) -> EvidenceSpec | None:
    fid = str(finding_id or "").upper()
    title_l = _lower(title)
    # Prefer title-token match (stable across renumbered IDs)
    for spec in specs:
        if spec.title_tokens and all(t in title_l for t in spec.title_tokens):
            return spec
    # Fall back to finding-id prefix families
    for spec in specs:
        if spec.id_prefixes and any(fid.startswith(p.upper()) for p in spec.id_prefixes):
            return spec
    return None


def extract_field(observed: Any, field_name: str) -> Any:
    """Pull a named property from nested dict/list evidence payloads."""
    if observed is None:
        return None
    if isinstance(observed, dict):
        if field_name in observed:
            return observed[field_name]
        # case-insensitive key
        for k, v in observed.items():
            if str(k).lower() == field_name.lower():
                return v
        for v in observed.values():
            found = extract_field(v, field_name)
            if found is not None:
                return found
    if isinstance(observed, list):
        for item in observed:
            found = extract_field(item, field_name)
            if found is not None:
                return found
    return None


def _coerce_number(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            return float(int(value))
        return float(value)
    except Exception:
        return None


def evaluate_condition(
    observed_value: Any,
    operator: str,
    expected_value: Any,
) -> tuple[bool | None, str]:
    """
    Returns (ok, detail).
    ok=True → control satisfied (PASS)
    ok=False → control violated (CONFIRMED finding)
    ok=None → cannot evaluate
    """
    op = (operator or "==").strip().lower()
    if op == "truthy":
        if observed_value is None:
            return None, "value missing"
        return (bool(observed_value) and str(observed_value).lower() not in {"0", "false", "no"}, "truthy check")
    if op == "falsy":
        if observed_value is None:
            return None, "value missing"
        ok = not bool(observed_value) or str(observed_value).lower() in {"0", "false", "no", ""}
        return ok, "falsy check"
    if op == "all_true":
        if not isinstance(observed_value, dict):
            return None, "expected dict of booleans"
        if not observed_value:
            return None, "empty dict"
        return all(bool(v) for v in observed_value.values()), "all_true"
    if op in {">=", "<=", ">", "<", "==", "!="}:
        if isinstance(expected_value, (int, float)) or op in {">=", "<=", ">", "<"}:
            obs_n = _coerce_number(observed_value)
            exp_n = _coerce_number(expected_value)
            if obs_n is None or exp_n is None:
                return None, "numeric compare unavailable"
            checks = {
                ">=": obs_n >= exp_n,
                "<=": obs_n <= exp_n,
                ">": obs_n > exp_n,
                "<": obs_n < exp_n,
                "==": obs_n == exp_n,
                "!=": obs_n != exp_n,
            }
            return checks[op], f"{obs_n} {op} {exp_n}"
        # string equality
        if observed_value is None:
            return None, "value missing"
        if op == "==":
            return str(observed_value) == str(expected_value), "equality"
        if op == "!=":
            return str(observed_value) != str(expected_value), "inequality"
    return None, f"unsupported operator {operator}"


def classify_evidence_item(
    item: dict[str, Any],
    spec: EvidenceSpec | None,
) -> str:
    """Classify a single evidence row relative to a control spec."""
    if item.get("quality") in {
        QUALITY_DIRECT,
        QUALITY_INDIRECT,
        QUALITY_INSUFFICIENT,
        QUALITY_UNAVAILABLE,
        QUALITY_ERROR,
    }:
        # Keep explicit label unless claiming DIRECT without required fields
        q = str(item.get("quality"))
        if q != QUALITY_DIRECT or not spec:
            return q
    observed = item.get("observed_value")
    if item.get("error") or str(item.get("status") or "").upper() == "ERROR":
        return QUALITY_ERROR
    if isinstance(observed, dict) and observed.get("error"):
        return QUALITY_ERROR
    if not spec:
        return QUALITY_INDIRECT
    source = str(item.get("api_call") or item.get("source") or "").lower()
    preferred = [s.lower() for s in spec.preferred_sources]
    has_fields = True
    for f in spec.required_fields:
        if extract_field(observed, f) is None and extract_field(item, f) is None:
            has_fields = False
            break
    # NOT_CONFIGURED password policy is still direct failing proof
    if (
        preferred
        and any(p in source for p in preferred)
        and isinstance(observed, dict)
        and str(observed.get("PasswordPolicy") or "").upper() == "NOT_CONFIGURED"
    ):
        return QUALITY_DIRECT
    if preferred and any(p in source for p in preferred) and has_fields:
        return QUALITY_DIRECT
    if has_fields and preferred and not any(p in source for p in preferred):
        # field present but wrong/weak source — still can be direct if field is authoritative
        return QUALITY_DIRECT
    if preferred and any(p in source for p in preferred) and not has_fields:
        return QUALITY_INSUFFICIENT
    if source:
        return QUALITY_INDIRECT
    return QUALITY_UNAVAILABLE


def assess_finding_evidence(
    *,
    finding_id: str | None,
    title: str | None,
    evidence: list[dict[str, Any]] | None,
    specs: list[EvidenceSpec],
    collection_error: str | None = None,
    capability_unavailable: bool = False,
) -> dict[str, Any]:
    """
    Decide finding status from evidence sufficiency.
    Only DIRECT evidence with a failing evaluation → CONFIRMED.
    """
    evidence = list(evidence or [])
    spec = match_spec(specs, finding_id=finding_id, title=title)

    if collection_error:
        return {
            "version": VERSION,
            "finding_status": STATUS_ERROR,
            "evidence_quality": QUALITY_ERROR,
            "control_key": spec.control_key if spec else None,
            "reason": f"Evidence collection error: {collection_error}",
            "observed": None,
            "expected": None,
            "result": "ERROR",
            "evidence_source": None,
            "spec_matched": bool(spec),
            "labeled_evidence": evidence,
            "manager_summary": {
                "headline": "EVIDENCE ERROR",
                "message": "Required evidence lookup failed unexpectedly.",
                "observed": None,
                "expected": None,
                "result": "ERROR",
                "evidence_source": None,
            },
        }

    if capability_unavailable:
        return {
            "version": VERSION,
            "finding_status": STATUS_UNVERIFIED,
            "evidence_quality": QUALITY_UNAVAILABLE,
            "control_key": spec.control_key if spec else None,
            "reason": "Required evidence capability unavailable",
            "observed": None,
            "expected": spec.human_expected if spec else None,
            "result": "UNAVAILABLE",
            "evidence_source": None,
            "spec_matched": bool(spec),
            "labeled_evidence": evidence,
            "manager_summary": {
                "headline": "EVIDENCE UNAVAILABLE",
                "message": "The system cannot collect the evidence needed to prove this finding.",
                "observed": None,
                "expected": spec.human_expected if spec else None,
                "result": "UNAVAILABLE",
                "evidence_source": None,
            },
        }

    if not spec:
        # No contract — cannot independently confirm from generic evidence
        labeled = []
        for ev in evidence:
            row = dict(ev)
            row["quality"] = row.get("quality") or QUALITY_INDIRECT
            row["purpose"] = row.get("purpose") or "context"
            labeled.append(row)
        return {
            "version": VERSION,
            "finding_status": STATUS_UNVERIFIED if evidence else STATUS_UNVERIFIED,
            "evidence_quality": QUALITY_INSUFFICIENT if evidence else QUALITY_UNAVAILABLE,
            "control_key": None,
            "reason": "No evidence contract matched this finding — cannot confirm from available evidence",
            "observed": None,
            "expected": None,
            "result": "UNVERIFIED",
            "evidence_source": None,
            "spec_matched": False,
            "labeled_evidence": labeled,
            "manager_summary": {
                "headline": "EVIDENCE INSUFFICIENT",
                "message": "The current evidence does not directly prove this security finding.",
                "observed": None,
                "expected": None,
                "result": "UNVERIFIED",
                "evidence_source": None,
            },
        }

    labeled: list[dict[str, Any]] = []
    direct_items: list[dict[str, Any]] = []
    error_items: list[dict[str, Any]] = []
    for ev in evidence:
        row = dict(ev)
        q = classify_evidence_item(row, spec)
        row["quality"] = q
        if q == QUALITY_DIRECT:
            row.setdefault("purpose", "proof")
            direct_items.append(row)
        elif q == QUALITY_INDIRECT:
            row.setdefault("purpose", "context")
        elif q == QUALITY_ERROR:
            row.setdefault("purpose", "error")
            error_items.append(row)
        else:
            row.setdefault("purpose", "insufficient")
        labeled.append(row)

    registry_match = {
        "finding_id": finding_id,
        "matched_evidence_spec": spec.control_key,
        "collector": (spec.preferred_sources[0] if spec.preferred_sources else None),
        "required_fields": list(spec.required_fields),
        "preferred_source": list(spec.preferred_sources),
    }

    # Preferred-source API errors must not fall back to CONFIRMED via indirect evidence
    if error_items and not direct_items:
        preferred = [s.lower() for s in spec.preferred_sources]
        preferred_error = None
        for item in error_items:
            src = str(item.get("api_call") or item.get("source") or "").lower()
            if not preferred or any(p in src for p in preferred):
                preferred_error = item
                break
        if preferred_error is None:
            preferred_error = error_items[0]
        err_obs = preferred_error.get("observed_value")
        err_src = preferred_error.get("api_call") or preferred_error.get("source")
        return {
            "version": VERSION,
            "finding_status": STATUS_ERROR,
            "evidence_quality": QUALITY_ERROR,
            "control_key": spec.control_key,
            "reason": f"Direct evidence source failed: {err_src}",
            "observed": err_obs if isinstance(err_obs, dict) else {"error": err_obs},
            "expected": spec.human_expected or spec.expected_value,
            "result": "ERROR",
            "evidence_source": err_src,
            "spec_matched": True,
            "required_fields": list(spec.required_fields),
            "preferred_sources": list(spec.preferred_sources),
            "registry_match": registry_match,
            "labeled_evidence": labeled,
            "manager_summary": {
                "headline": "EVIDENCE ERROR",
                "message": "Required live evidence lookup failed — finding is not confirmed.",
                "observed": err_obs,
                "expected": spec.human_expected or str(spec.expected_value),
                "result": "ERROR",
                "evidence_source": err_src,
                "finding_status": STATUS_ERROR,
            },
        }

    if not direct_items:
        return {
            "version": VERSION,
            "finding_status": STATUS_UNVERIFIED,
            "evidence_quality": QUALITY_INSUFFICIENT if evidence else QUALITY_UNAVAILABLE,
            "control_key": spec.control_key,
            "reason": (
                "No DIRECT evidence for required field(s): "
                + ", ".join(spec.required_fields)
                + f" from preferred source(s): {', '.join(spec.preferred_sources) or 'n/a'}"
            ),
            "observed": None,
            "expected": spec.human_expected or spec.expected_value,
            "result": "UNVERIFIED",
            "evidence_source": None,
            "spec_matched": True,
            "required_fields": list(spec.required_fields),
            "preferred_sources": list(spec.preferred_sources),
            "registry_match": registry_match,
            "labeled_evidence": labeled,
            "manager_summary": {
                "headline": "EVIDENCE INSUFFICIENT",
                "message": "The current evidence does not directly prove this security finding.",
                "observed": None,
                "expected": spec.human_expected or str(spec.expected_value),
                "result": "UNVERIFIED",
                "evidence_source": None,
                "finding_status": STATUS_UNVERIFIED,
            },
        }

    # Evaluate using first direct item that yields a decisive result
    observed_display = None
    source_display = None
    eval_ok: bool | None = None
    eval_detail = ""
    for item in direct_items:
        observed = item.get("observed_value")
        source_display = item.get("api_call") or item.get("source")
        if spec.custom_eval:
            eval_ok, eval_detail = spec.custom_eval(observed if isinstance(observed, dict) else {"value": observed})
            if spec.required_fields:
                observed_display = {
                    f: extract_field(observed, f) for f in spec.required_fields
                }
            else:
                observed_display = observed
        else:
            # single-field or multi-field
            if len(spec.required_fields) == 1 and spec.operator != "all_true":
                field = spec.required_fields[0]
                val = extract_field(observed, field)
                if val is None:
                    val = extract_field(item, field)
                observed_display = {field: val}
                eval_ok, eval_detail = evaluate_condition(val, spec.operator, spec.expected_value)
            elif spec.operator == "all_true":
                # expected subset of booleans on observed dict
                subset = {}
                for f in spec.required_fields or (
                    list(observed.keys()) if isinstance(observed, dict) else []
                ):
                    subset[f] = extract_field(observed, f)
                observed_display = subset
                eval_ok, eval_detail = evaluate_condition(subset, "all_true", True)
            else:
                # multi-field equality bag
                subset = {f: extract_field(observed, f) for f in spec.required_fields}
                observed_display = subset
                if any(v is None for v in subset.values()):
                    eval_ok, eval_detail = None, "required field missing"
                else:
                    eval_ok, eval_detail = evaluate_condition(
                        subset.get(spec.required_fields[0]),
                        spec.operator,
                        spec.expected_value,
                    )
        if eval_ok is not None:
            break

    if eval_ok is None:
        return {
            "version": VERSION,
            "finding_status": STATUS_UNVERIFIED,
            "evidence_quality": QUALITY_INSUFFICIENT,
            "control_key": spec.control_key,
            "reason": f"Direct evidence present but condition could not be evaluated ({eval_detail})",
            "observed": observed_display,
            "expected": spec.human_expected or spec.expected_value,
            "result": "UNVERIFIED",
            "evidence_source": source_display,
            "spec_matched": True,
            "labeled_evidence": labeled,
            "manager_summary": {
                "headline": "EVIDENCE INSUFFICIENT",
                "message": "The current evidence does not directly prove this security finding.",
                "observed": observed_display,
                "expected": spec.human_expected or str(spec.expected_value),
                "result": "UNVERIFIED",
                "evidence_source": source_display,
                "finding_status": STATUS_UNVERIFIED,
            },
        }

    if eval_ok:
        status = STATUS_REMEDIATED
        result = "PASS"
        reason = f"Control satisfied ({eval_detail})"
    else:
        status = STATUS_CONFIRMED
        result = "FAIL"
        reason = f"Control violated ({eval_detail})"

    return {
        "version": VERSION,
        "finding_status": status,
        "evidence_quality": QUALITY_DIRECT,
        "control_key": spec.control_key,
        "reason": reason,
        "observed": observed_display,
        "expected": spec.human_expected or spec.expected_value,
        "result": result,
        "evidence_source": source_display,
        "spec_matched": True,
        "human_label": spec.human_label,
        "required_fields": list(spec.required_fields),
        "preferred_sources": list(spec.preferred_sources),
        "registry_match": {
            "finding_id": finding_id,
            "matched_evidence_spec": spec.control_key,
            "collector": (spec.preferred_sources[0] if spec.preferred_sources else None),
            "required_fields": list(spec.required_fields),
            "preferred_source": list(spec.preferred_sources),
        },
        "labeled_evidence": labeled,
        "manager_summary": {
            "headline": "EVIDENCE DIRECT" if result == "FAIL" else "CONTROL SATISFIED",
            "message": reason,
            "observed": observed_display,
            "expected": spec.human_expected or str(spec.expected_value),
            "result": result,
            "evidence_source": source_display,
            "human_label": spec.human_label,
            "finding_status": status,
        },
    }
