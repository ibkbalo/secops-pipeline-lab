# change_assurance/capabilities/freshness.py
# Capability state freshness — unresolved states must re-probe after external bootstrap.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from change_assurance.capabilities.types import (
    MISSING_PERMISSIONS,
    READY,
    UNVERIFIABLE,
)

# READY results stay fresh briefly to avoid hammering IAM SimulatePrincipalPolicy.
CAPABILITY_READY_TTL_SECONDS = 900  # 15 minutes
# Unresolved capability must re-check on the next assurance load / Manager Mode view.
CAPABILITY_UNRESOLVED_TTL_SECONDS = 0


def _parse_verified_at(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def capability_age_seconds(assessment: dict[str, Any] | None, *, now: datetime | None = None) -> float | None:
    assessment = assessment or {}
    verified = _parse_verified_at(str(assessment.get("verified_at") or "") or None)
    if not verified:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - verified).total_seconds())


def capability_needs_reprobe(
    assessment: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    force: bool = False,
) -> bool:
    """
    True when Sentinel should re-run read-only capability verification.

    - MISSING_PERMISSIONS / UNVERIFIABLE: always re-check (admin may have installed policy).
    - READY: re-check only after CAPABILITY_READY_TTL_SECONDS (or missing verified_at).
    - NOT_SUPPORTED / empty: no probe.
    """
    if force:
        return True
    assessment = assessment or {}
    state = str(assessment.get("state") or "").upper()
    if not state or state == "NOT_SUPPORTED":
        return False
    if state in {MISSING_PERMISSIONS, UNVERIFIABLE}:
        age = capability_age_seconds(assessment, now=now)
        if age is None:
            return True
        return age >= CAPABILITY_UNRESOLVED_TTL_SECONDS
    if state == READY:
        age = capability_age_seconds(assessment, now=now)
        if age is None:
            return True
        return age >= CAPABILITY_READY_TTL_SECONDS
    return False
