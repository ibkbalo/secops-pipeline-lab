# change_assurance/aws_response_semantics.py
# Map known AWS API responses/exceptions to control-state evidence.
# Generic registry: services register semantic meanings without weakening quality.
# Unknown exceptions remain ERROR / UNAVAILABLE — never invent PASS/FAIL.

from __future__ import annotations

from typing import Any


# (aws_service_lower, error_code) → semantic control-state meaning
# control_state values are service-agnostic labels used by collectors/evaluators.
AWS_SEMANTIC_EXCEPTIONS: dict[tuple[str, str], dict[str, Any]] = {
    (
        "guardduty",
        "SubscriptionRequiredException",
    ): {
        "control_state": "SERVICE_NOT_SUBSCRIBED",
        "pass": False,
        "evidence_quality": "DIRECT",
        "human_template": "Amazon GuardDuty is not subscribed/enabled in {region}",
        "notes": (
            "SubscriptionRequiredException proves GuardDuty coverage is absent in this "
            "account/Region; it does not prove an attack or compromise."
        ),
        "api_hints": ("list_detectors", "get_detector", "create_detector"),
    },
}


def normalize_error_code(exc: Any) -> str:
    """Extract AWS error Code from a ClientError / dict / string."""
    if exc is None:
        return ""
    if isinstance(exc, dict):
        code = exc.get("code") or exc.get("Code") or exc.get("error_code")
        if code:
            return str(code)
        err = exc.get("Error") if isinstance(exc.get("Error"), dict) else {}
        return str(err.get("Code") or "")
    # botocore ClientError
    try:
        resp = getattr(exc, "response", None) or {}
        if isinstance(resp, dict):
            err = resp.get("Error") if isinstance(resp.get("Error"), dict) else {}
            code = err.get("Code")
            if code:
                return str(code)
    except Exception:
        pass
    text = str(exc)
    for token in (
        "SubscriptionRequiredException",
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
        "ExpiredToken",
        "RequestTimeout",
        "Throttling",
        "ServiceUnavailable",
    ):
        if token.lower() in text.lower():
            return token
    return type(exc).__name__ if not isinstance(exc, str) else ""


def interpret_aws_exception(
    *,
    service: str,
    error_code: str | None = None,
    exc: Any = None,
    region: str | None = None,
    api_call: str | None = None,
) -> dict[str, Any] | None:
    """
    Return a semantic interpretation when a known AWS response proves control state.
    Returns None for real permission/network/unknown errors (caller keeps ERROR/UNVERIFIED).
    """
    svc = str(service or "").strip().lower()
    code = str(error_code or normalize_error_code(exc) or "").strip()
    if not svc or not code:
        return None
    row = AWS_SEMANTIC_EXCEPTIONS.get((svc, code))
    if not row:
        # Case-insensitive code match
        for (s, c), payload in AWS_SEMANTIC_EXCEPTIONS.items():
            if s == svc and c.lower() == code.lower():
                row = payload
                break
    if not row:
        return None
    region_s = str(region or "the Region")
    human = str(row.get("human_template") or "").format(region=region_s, code=code)
    return {
        "service": svc,
        "error_code": code,
        "api_call": api_call,
        "region": region,
        "control_state": row.get("control_state"),
        "pass": bool(row.get("pass")),
        "evidence_quality": str(row.get("evidence_quality") or "DIRECT"),
        "human_observed": human,
        "notes": row.get("notes"),
        "semantic": True,
    }


def is_permission_or_transport_error(error_code: str | None, exc: Any = None) -> bool:
    """True for AccessDenied / credential / timeout class failures — not control-state proof."""
    code = str(error_code or normalize_error_code(exc) or "").lower()
    markers = (
        "accessdenied",
        "unauthorized",
        "unrecognizedclient",
        "expiredtoken",
        "invalidclienttoken",
        "authfailure",
        "timeout",
        "requesttimeout",
        "endpointconnection",
        "connectionclosed",
        "throttling",
        "serviceunavailable",
        "internalerror",
    )
    return any(m in code for m in markers)


def register_semantic_exception(
    service: str,
    error_code: str,
    *,
    control_state: str,
    human_template: str,
    evidence_quality: str = "DIRECT",
    passes: bool = False,
    notes: str | None = None,
) -> None:
    """Allow domains to register additional semantic exception mappings at runtime."""
    AWS_SEMANTIC_EXCEPTIONS[(str(service).lower(), str(error_code))] = {
        "control_state": control_state,
        "pass": passes,
        "evidence_quality": evidence_quality,
        "human_template": human_template,
        "notes": notes,
    }
