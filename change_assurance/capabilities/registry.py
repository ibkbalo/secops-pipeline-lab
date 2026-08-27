# change_assurance/capabilities/registry.py
# Supported-control execution capability registry.

from __future__ import annotations

from typing import Any, Callable

from change_assurance.capabilities.types import CapabilitySpec, PermissionRequirement

_SPECS: list[CapabilitySpec] = []
_ENSURED = False


def register_capability(spec: CapabilitySpec) -> None:
    # Replace existing id
    global _SPECS
    _SPECS = [s for s in _SPECS if s.capability_id != spec.capability_id]
    _SPECS.append(spec)


def all_specs() -> list[CapabilitySpec]:
    ensure_default_capabilities()
    return list(_SPECS)


def match_capability(
    *,
    finding_id: str | None,
    title: str | None = None,
) -> CapabilitySpec | None:
    ensure_default_capabilities()
    fid = str(finding_id or "").upper().strip()
    title_l = str(title or "").lower()
    for spec in _SPECS:
        if fid and fid in {c.upper() for c in spec.control_ids}:
            return spec
    for spec in _SPECS:
        if spec.title_tokens and all(tok in title_l for tok in spec.title_tokens):
            return spec
    return None


def ensure_default_capabilities() -> None:
    global _ENSURED
    if _ENSURED:
        return
    _ENSURED = True
    _register_builtins()


def _register_builtins() -> None:
    # —— Amazon GuardDuty detector enablement ——
    register_capability(
        CapabilitySpec(
            capability_id="aws_guardduty_detector_enable",
            control_ids=("CLOUD-LOG-003", "CLOUD-DFT-001"),
            title_tokens=("guardduty",),
            service="guardduty",
            inline_policy_name="SentinelGuardDutyRemediation",
            description="Enable Amazon GuardDuty detector in a Region",
            verification_permissions=("guardduty:ListDetectors", "guardduty:GetDetector"),
            permissions=(
                PermissionRequirement("guardduty:CreateDetector", "Create detector"),
                PermissionRequirement("guardduty:GetDetector", "Read detector after create"),
                PermissionRequirement("guardduty:ListDetectors", "List detectors / refresh"),
                PermissionRequirement("guardduty:UpdateDetector", "Enable/update detector"),
                PermissionRequirement("guardduty:TagResource", "Provider tagging / default_tags"),
                PermissionRequirement("guardduty:ListTagsForResource", "Read tags on refresh"),
                PermissionRequirement(
                    "iam:CreateServiceLinkedRole",
                    "Create AWSServiceRoleForAmazonGuardDuty when absent",
                    condition={"StringEquals": {"iam:AWSServiceName": "guardduty.amazonaws.com"}},
                ),
                PermissionRequirement(
                    "iam:GetRole",
                    "Read GuardDuty service-linked role",
                    resource="arn:aws:iam::{account_id}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                ),
            ),
        )
    )

    # —— IAM Access Analyzer (ACCOUNT analyzer) ——
    register_capability(
        CapabilitySpec(
            capability_id="aws_accessanalyzer_account",
            control_ids=("CLOUD-IAM-013",),
            title_tokens=("access", "analyzer"),
            service="accessanalyzer",
            inline_policy_name="SentinelAccessAnalyzerRemediation",
            description="Create ACTIVE ACCOUNT Access Analyzer",
            verification_permissions=("access-analyzer:ListAnalyzers", "access-analyzer:GetAnalyzer"),
            permissions=(
                PermissionRequirement(
                    "access-analyzer:CreateAnalyzer",
                    "Create account analyzer",
                    resource="arn:aws:access-analyzer:{region}:{account_id}:analyzer/sentinel-account",
                ),
                PermissionRequirement(
                    "access-analyzer:GetAnalyzer",
                    "Read analyzer",
                    resource="arn:aws:access-analyzer:{region}:{account_id}:analyzer/sentinel-account",
                ),
                PermissionRequirement("access-analyzer:ListAnalyzers", "List analyzers"),
                PermissionRequirement(
                    "access-analyzer:ListTagsForResource",
                    "Read analyzer tags",
                    resource="arn:aws:access-analyzer:{region}:{account_id}:analyzer/sentinel-account",
                ),
                PermissionRequirement(
                    "iam:CreateServiceLinkedRole",
                    "Create Access Analyzer SLR when absent",
                    condition={"StringEquals": {"iam:AWSServiceName": "access-analyzer.amazonaws.com"}},
                ),
            ),
        )
    )

    # —— AWS Config recorder enablement (executor IAM — not resource prerequisites) ——
    register_capability(
        CapabilitySpec(
            capability_id="aws_config_recorder_enable",
            control_ids=("CLOUD-LOG-002",),
            title_tokens=("config", "recorder"),
            service="config",
            inline_policy_name="SentinelAWSConfigRemediation",
            description="Enable AWS Config recorder + dedicated delivery resources",
            verification_permissions=(
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
            ),
            permissions=(
                PermissionRequirement(
                    "iam:CreateServiceLinkedRole",
                    "Create AWSServiceRoleForConfig when absent",
                    condition={"StringEquals": {"iam:AWSServiceName": "config.amazonaws.com"}},
                ),
                PermissionRequirement(
                    "iam:GetRole",
                    "Read Config SLR",
                    resource="arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                ),
                PermissionRequirement(
                    "iam:PassRole",
                    "Pass Config SLR",
                    resource="arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                    condition={"StringEqualsIfExists": {"iam:PassedToService": "config.amazonaws.com"}},
                ),
                PermissionRequirement("config:PutConfigurationRecorder", "Create/update recorder"),
                PermissionRequirement("config:PutDeliveryChannel", "Create/update delivery channel"),
                PermissionRequirement("config:StartConfigurationRecorder", "Enable recording"),
                PermissionRequirement("config:DescribeConfigurationRecorders", "Validate recorder"),
                PermissionRequirement("config:DescribeConfigurationRecorderStatus", "Confirm recording"),
                PermissionRequirement("config:DescribeDeliveryChannels", "Validate delivery channel"),
                PermissionRequirement(
                    "s3:CreateBucket",
                    "Create dedicated Config delivery bucket",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
                PermissionRequirement(
                    "s3:PutBucketPolicy",
                    "Config delivery bucket policy",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
                PermissionRequirement(
                    "s3:PutBucketVersioning",
                    "Enable delivery bucket versioning",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
                PermissionRequirement(
                    "s3:PutBucketPublicAccessBlock",
                    "Block public access on Config bucket",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
                PermissionRequirement(
                    "s3:PutEncryptionConfiguration",
                    "Encrypt Config bucket",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
                PermissionRequirement(
                    "s3:PutBucketOwnershipControls",
                    "Ownership controls on Config bucket",
                    resource="arn:aws:s3:::sentinel-aws-config-{account_id}-{region}",
                ),
            ),
        )
    )
