# predeploy/post_deployment_verification.py
# Re-check specific controls after manager-approved apply (apply itself is external).

from __future__ import annotations

from typing import Any

VERSION = "0.1.0"


def verification_plan_for_finding(finding_id: str, title: str | None = None) -> dict[str, Any]:
    fid = (finding_id or "").upper()
    title_l = (title or "").lower()
    if "access analyzer" in title_l or fid == "CLOUD-IAM-013":
        return {
            "finding_id": finding_id,
            "method": "aws_api",
            "steps": [
                "Call accessanalyzer.list_analyzers in the finding Region (e.g. us-east-1)",
                "Confirm at least one analyzer with type=ACCOUNT and status=ACTIVE",
                "Re-run scan_cloud_pack live and ensure CLOUD-IAM-013 no longer fails",
            ],
            "pass_criteria": "ACTIVE ACCOUNT Access Analyzer present in the intended Region",
            "version": VERSION,
        }
    if "guardduty" in title_l or fid in {"CLOUD-LOG-004", "AWS-016"}:
        return {
            "finding_id": finding_id,
            "method": "aws_api",
            "steps": [
                "guardduty.list_detectors / get_detector — detector exists and Status=ENABLED",
                "Re-run scan_cloud_pack live for GuardDuty clearance",
            ],
            "pass_criteria": "GuardDuty detector enabled",
            "version": VERSION,
        }
    if fid.startswith("CLOUD-STO") or "public access block" in title_l:
        return {
            "finding_id": finding_id,
            "method": "aws_api",
            "steps": [
                "Call s3control.get_public_access_block for the account",
                "Confirm BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets are all true",
                "Re-run scan_cloud_pack live and ensure CLOUD-STO-001 no longer fails",
            ],
            "pass_criteria": "All four account S3 Block Public Access settings are true",
            "version": VERSION,
        }
    if fid.startswith("CLOUD-LOG") or "cloudtrail" in title_l:
        return {
            "finding_id": finding_id,
            "method": "aws_api",
            "steps": [
                "cloudtrail.describe_trails — trail exists and preferably multi-region",
                "get_trail_status — IsLogging true",
                "Re-run scan_cloud_pack live for CLOUD-LOG-* clearance",
            ],
            "pass_criteria": "CloudTrail trail present and logging",
            "version": VERSION,
        }
    return {
        "finding_id": finding_id,
        "method": "rescan",
        "steps": [
            "Re-run the originating Hands pack live",
            f"Confirm {finding_id} no longer appears as failed",
            "Write fix evidence note via worker_report",
        ],
        "pass_criteria": f"{finding_id} cleared on re-scan",
        "version": VERSION,
    }


def verify_s3_account_bpa(discovery: dict[str, Any] | None) -> dict[str, Any]:
    """Evaluate live discovery snapshot for S3 BPA pass/fail."""
    summary = (discovery or {}).get("summary") or {}
    pab = summary.get("account_pab") or {}
    ok = all(
        [
            bool(pab.get("BlockPublicAcls")),
            bool(pab.get("IgnorePublicAcls")),
            bool(pab.get("BlockPublicPolicy")),
            bool(pab.get("RestrictPublicBuckets")),
        ]
    )
    return {
        "version": VERSION,
        "control": "CLOUD-STO-001",
        "passed": ok,
        "observed": pab,
        "finding_remains_open": not ok,
    }
