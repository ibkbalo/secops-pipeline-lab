# change_assurance/domains/cloud/s3_control_conflicts.py
# S3 adapter for pre-deploy cross-control conflict analysis.
# Generic — not CLOUD-LOG-002 specific.

from __future__ import annotations

import re
from typing import Any

from change_assurance.control_conflicts import (
    MANUAL_ONLY,
    NOT_APPLICABLE,
    RECOMMENDED,
    REQUIRED,
    predicted_finding,
)

# Bucket purpose classification (shared with scan-time MFA Delete scoping)
SERVICE_DELIVERY_NAME_RE = re.compile(
    r"(?i)(sentinel-aws-config-|aws-cloudtrail-logs-|awsconfig|config-delivery|"
    r"cloudtrail|vpc-flow-logs|elb-access-logs|s3-access-logs)"
)
HIGH_VALUE_NAME_RE = re.compile(
    r"(?i)(backup|customer-data|prod-data|pii|phi|payment|treasury|secrets-archive)"
)


def classify_s3_bucket(name: str | None, *, tags: dict[str, Any] | None = None) -> str:
    """
    Return SERVICE_DELIVERY | HIGH_VALUE | GENERAL.
    Used by scan controls and pre-deploy conflict analysis.
    """
    tags = tags or {}
    purpose = str(tags.get("SentinelPurpose") or tags.get("sentinel_purpose") or "").lower()
    if purpose in {
        "aws-config-delivery",
        "cloudtrail-delivery",
        "log-delivery",
        "service-delivery",
    }:
        return "SERVICE_DELIVERY"
    if str(tags.get("DoNotReuseForTrail") or "").lower() in {"true", "1", "yes"}:
        return "SERVICE_DELIVERY"
    n = str(name or "")
    if SERVICE_DELIVERY_NAME_RE.search(n):
        return "SERVICE_DELIVERY"
    if HIGH_VALUE_NAME_RE.search(n):
        return "HIGH_VALUE"
    if str(tags.get("DataClass") or tags.get("data_class") or "").lower() in {
        "confidential",
        "restricted",
        "high",
    }:
        return "HIGH_VALUE"
    return "GENERAL"


def mfa_delete_applicability(bucket_class: str) -> str:
    """
    MFA Delete requires the AWS account root user + MFA serial/token.
    It cannot be enabled by a least-privilege remediation role via Terraform alone.
    """
    if bucket_class == "SERVICE_DELIVERY":
        return NOT_APPLICABLE
    if bucket_class == "HIGH_VALUE":
        return MANUAL_ONLY
    return RECOMMENDED


class S3ControlConflictAdapter:
    """Predict S3 control failures from proposed Terraform creates / existing buckets."""

    def analyze(
        self,
        *,
        resource_changes: list[dict[str, Any]],
        source_terraform: str | None,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        src = source_terraform or ""
        ctx = context or {}
        out: list[dict[str, Any]] = []

        bucket_addrs: list[str] = []
        versioning_addrs: set[str] = set()
        encryption_addrs: set[str] = set()
        pab_addrs: set[str] = set()
        bucket_names: dict[str, str] = {}

        for rc in resource_changes or []:
            if not isinstance(rc, dict):
                continue
            rtype = str(rc.get("type") or "")
            addr = str(rc.get("address") or "")
            actions = (rc.get("change") or {}).get("actions") or []
            if rtype == "aws_s3_bucket" and (
                "create" in actions or rc.get("already_exists") or "no-op" in actions
            ):
                bucket_addrs.append(addr)
                vals = ((rc.get("change") or {}).get("after") or {}) if isinstance(rc.get("change"), dict) else {}
                if isinstance(vals, dict) and vals.get("bucket"):
                    bucket_names[addr] = str(vals["bucket"])
            elif rtype == "aws_s3_bucket_versioning":
                versioning_addrs.add(addr)
            elif rtype == "aws_s3_bucket_server_side_encryption_configuration":
                encryption_addrs.add(addr)
            elif rtype == "aws_s3_bucket_public_access_block":
                pab_addrs.add(addr)

        # Also detect from source HCL when plan is partial / recovery-only
        src_has_versioning = bool(re.search(r'resource\s+"aws_s3_bucket_versioning"', src))
        src_has_encryption = bool(
            re.search(r'resource\s+"aws_s3_bucket_server_side_encryption_configuration"', src)
        )
        src_has_pab = bool(re.search(r'resource\s+"aws_s3_bucket_public_access_block"', src))
        src_bucket_match = re.search(
            r'resource\s+"aws_s3_bucket"\s+"([^"]+)"',
            src,
        )
        if src_bucket_match and not bucket_addrs:
            bucket_addrs.append(f"aws_s3_bucket.{src_bucket_match.group(1)}")

        # Infer names from context / source
        default_name = str(ctx.get("expected_bucket_name") or "")
        if not default_name and "sentinel-aws-config-" in src:
            default_name = "sentinel-aws-config-<account>-<region>"

        for addr in bucket_addrs:
            name = bucket_names.get(addr) or default_name or addr
            # Resolve companion presence: plan companions OR source companions OR matching name suffix
            has_versioning = src_has_versioning or any(
                "versioning" in a for a in versioning_addrs
            ) or bool(
                re.search(
                    rf'aws_s3_bucket_versioning\.[^\s]+.*{re.escape(addr.split(".", 1)[-1])}',
                    "\n".join(versioning_addrs),
                )
            )
            # If recovery plan only lists remaining creates, existing bucket may lack versioning
            # while companions in THIS plan don't include versioning → conflict
            plan_adds_versioning = any("versioning" in a for a in versioning_addrs)
            if not plan_adds_versioning and not src_has_versioning:
                has_versioning = False
            elif plan_adds_versioning or src_has_versioning:
                has_versioning = True

            has_encryption = src_has_encryption or any("encryption" in a for a in encryption_addrs)
            has_pab = src_has_pab or any("public_access_block" in a for a in pab_addrs)

            bclass = classify_s3_bucket(name, tags=ctx.get("bucket_tags") or {})
            # Prefer explicit purpose from Config dedicated path
            if "aws_s3_bucket.config" in addr or "sentinel-aws-config" in str(name):
                bclass = "SERVICE_DELIVERY"

            if not has_versioning:
                out.append(
                    predicted_finding(
                        control_family="s3_versioning",
                        control_id_hint="CLOUD-STO-VERSIONING",
                        title=f"S3 versioning missing for proposed/existing bucket ({name})",
                        severity="medium",
                        applicability=REQUIRED if bclass in {"SERVICE_DELIVERY", "HIGH_VALUE"} else RECOMMENDED,
                        reason=(
                            "Proposed remediation creates or leaves an S3 bucket without "
                            "aws_s3_bucket_versioning. Sentinel storage controls require "
                            "versioning for audit/security delivery buckets and recommend it broadly."
                        ),
                        resource_address=addr,
                        resource_type="aws_s3_bucket",
                        would_fail_after_apply=True,
                        auto_remediable=True,
                        manager_message=(
                            f"This bucket will be present, but versioning is not enabled — "
                            f"a Sentinel S3 versioning control (e.g. CLOUD-STO-005 class) would fail "
                            f"on the next scan."
                        ),
                        evidence={
                            "bucket_class": bclass,
                            "has_versioning_resource": False,
                        },
                    )
                )
            else:
                # Versioning present — MFA Delete advisory only (never auto-required for TF apply)
                mfa_app = mfa_delete_applicability(bclass)
                if mfa_app == NOT_APPLICABLE:
                    out.append(
                        predicted_finding(
                            control_family="s3_mfa_delete",
                            control_id_hint="CLOUD-STO-MFA-DELETE",
                            title=f"S3 MFA Delete not applicable for service delivery bucket ({name})",
                            severity="info",
                            applicability=NOT_APPLICABLE,
                            reason=(
                                "MFA Delete requires the AWS account root user and an MFA serial/token. "
                                "Service delivery buckets (Config/CloudTrail/logs) are managed by "
                                "least-privilege automation and are marked NOT APPLICABLE."
                            ),
                            resource_address=addr,
                            resource_type="aws_s3_bucket",
                            would_fail_after_apply=False,
                            auto_remediable=False,
                            manager_message=(
                                "MFA Delete is intentionally not part of automated remediation for "
                                "this service delivery bucket."
                            ),
                            evidence={"bucket_class": bclass, "aws_root_required": True},
                        )
                    )
                elif mfa_app in {MANUAL_ONLY, RECOMMENDED}:
                    out.append(
                        predicted_finding(
                            control_family="s3_mfa_delete",
                            control_id_hint="CLOUD-STO-MFA-DELETE",
                            title=f"S3 MFA Delete is {mfa_app} for bucket ({name})",
                            severity="low",
                            applicability=mfa_app,
                            reason=(
                                "MFA Delete cannot be enabled by Terraform through a least-privilege "
                                "remediation role; it requires root + MFA challenge via AWS CLI/API."
                            ),
                            resource_address=addr,
                            resource_type="aws_s3_bucket",
                            would_fail_after_apply=False,
                            auto_remediable=False,
                            manager_message=(
                                "MFA Delete is a manual root/MFA operation. Sentinel will not auto-apply it."
                            ),
                            evidence={"bucket_class": bclass, "aws_root_required": True},
                        )
                    )

            if not has_encryption and ("create" in str(resource_changes)):
                # Only warn when creating without encryption companion in same change set
                creating = any(
                    isinstance(rc, dict)
                    and rc.get("address") == addr
                    and "create" in ((rc.get("change") or {}).get("actions") or [])
                    for rc in resource_changes
                )
                if creating and not has_encryption:
                    out.append(
                        predicted_finding(
                            control_family="s3_encryption",
                            control_id_hint="CLOUD-STO-ENCRYPTION",
                            title=f"S3 default encryption missing for ({name})",
                            severity="high",
                            applicability=REQUIRED,
                            reason="Bucket create without server-side encryption configuration.",
                            resource_address=addr,
                            resource_type="aws_s3_bucket",
                            would_fail_after_apply=True,
                            auto_remediable=True,
                            manager_message="Proposed bucket lacks default encryption — storage encryption control would fail.",
                            evidence={"bucket_class": bclass},
                        )
                    )

            if not has_pab:
                creating = any(
                    isinstance(rc, dict)
                    and str(rc.get("address") or "") == addr
                    and "create" in ((rc.get("change") or {}).get("actions") or [])
                    for rc in (resource_changes or [])
                )
                # For already-existing buckets in recovery, PAB may be pending in plan
                plan_adds_pab = any("public_access_block" in a for a in pab_addrs)
                if not plan_adds_pab and not src_has_pab and creating:
                    out.append(
                        predicted_finding(
                            control_family="s3_public_access_block",
                            control_id_hint="CLOUD-STO-PAB",
                            title=f"S3 public access block missing for ({name})",
                            severity="critical",
                            applicability=REQUIRED,
                            reason="Bucket create without public access block.",
                            resource_address=addr,
                            resource_type="aws_s3_bucket",
                            would_fail_after_apply=True,
                            auto_remediable=True,
                            manager_message="Proposed bucket lacks Block Public Access — critical storage control would fail.",
                            evidence={"bucket_class": bclass},
                        )
                    )

        # Never attach EBS / unrelated controls from S3 analysis
        out = [p for p in out if "ebs" not in str(p.get("control_family") or "").lower()]
        return out
