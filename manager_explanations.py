# manager_explanations.py
# Deterministic, control-specific Manager Mode teaching metadata.
# No LLMs. Adapters/Face consume this registry for plain-English explanations.

from __future__ import annotations

import re
from typing import Any, Callable

VERSION = "0.1.0-mx1"

# Families used for cross-control leakage checks
FAMILY_IAM = "iam"
FAMILY_GUARDDUTY = "guardduty"
FAMILY_CONFIG = "config"
FAMILY_NETWORK = "network"
FAMILY_STORAGE = "storage"
FAMILY_IDENTITY = "identity"
FAMILY_GENERIC = "generic"

# Breach/exposure claim patterns that require DIRECT confirmation of exposure.
# Educational negations are scrubbed before matching (see unsupported_risk_claim_reason).
_UNSAFE_BREACH_PATTERNS = [
    re.compile(r"\battackers?\s+can\s+currently\b", re.I),
    re.compile(r"\bcurrently\s+(has|have)\s+access\b", re.I),
    re.compile(r"\bactive\s+breach\b", re.I),
    re.compile(r"\bdata\s+(is|are)\s+(currently\s+)?(leaked|exfiltrated|stolen)\b", re.I),
    re.compile(r"\bcompromised\s+already\b", re.I),
    re.compile(r"\b(this|sentinel)\s+proves?\s+(a\s+)?breach\b", re.I),
]


def _region(finding: dict[str, Any], impact: dict[str, Any] | None = None) -> str:
    return (
        str(((finding.get("resource") or {}).get("region") or "")).strip()
        or str(((impact or {}).get("region") or "")).strip()
        or str((((impact or {}).get("discovery") or {}).get("region") or "")).strip()
        or "us-east-1"
    )


CONTROL_EXPLANATIONS: dict[str, dict[str, Any]] = {
    "CLOUD-IAM-013": {
        "family": FAMILY_IAM,
        "service": "IAM Access Analyzer",
        "technology_tokens": ("access analyzer", "iam access analyzer"),
        "forbidden_family_terms": (
            r"\bs3\b",
            r"block public access",
            r"\bguardduty\b",
            r"\bnginx\b",
            r"\bwaf\b",
            r"flow logs?",
            r"\bebs\b",
            r"unused[\s-]?access",
            r"unused access analysis",
            r"unused-access analyzer",
        ),
        "forbidden_capability_claims": (
            r"unused[\s-]?access",
            r"unused access analysis",
            r"monitor(?:ing)? unused",
            r"unused permissions?",
        ),
        "plain_english_name": "IAM Access Analyzer",
        "what_it_is": (
            "IAM Access Analyzer is an AWS security service that examines supported AWS "
            "resource policies and helps identify access that exists outside the account's "
            "intended trust boundary (for example, access from another AWS account)."
        ),
        "security_concept": "Detective control — external access analysis",
        "why_it_matters": (
            "Without an ACTIVE account-level external-access analyzer in the Region, "
            "unintended public or cross-account access through supported resource policies "
            "is less visible. The absence of the analyzer does not prove external exposure."
        ),
        "analyzer_type": "ACCOUNT",
        "analyzer_capability": "external_access",
        "realistic_risk_example": (
            "An engineer changes a supported resource policy and unintentionally grants "
            "access to another AWS account. Access Analyzer can help surface that "
            "external-access relationship so it can be reviewed."
        ),
        "absence_does_not_prove": (
            "Absence of an analyzer does not by itself prove external exposure or that a "
            "breach has occurred."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing account-wide detective control for external-access analysis",
                "Can reduce visibility into unintended external access on supported resources",
                "Applies across supported resources in the affected Region",
            ],
            "context": [
                "Does not prove active exploitation or current external exposure",
                "Severity reflects the risk of the missing control, not a confirmed incident",
            ],
        },
        "remediation_plain_english": (
            "Create one account-level IAM Access Analyzer in the finding Region "
            "(Terraform resource aws_accessanalyzer_analyzer, type ACCOUNT)."
        ),
        "remediation_artifact_hints": ("aws_accessanalyzer_analyzer", "type", "ACCOUNT"),
        "remediation_does_not_do": [
            "Rewrite IAM users or groups",
            "Change user passwords",
            "Revoke roles or permission policies",
            "Automatically modify resource policies",
            "Prove that resources are currently exposed externally",
        ],
        "manager_prechecks": [
            "Confirm the intended AWS Region matches the finding (lab default us-east-1)",
            "Confirm no ACTIVE ACCOUNT analyzer already exists in that Region",
            "Review the Terraform plan — it should create one account-level analyzer",
            "Confirm the implementing identity can create Access Analyzer resources",
        ],
        "verification_plain_english": (
            "Re-query IAM Access Analyzer in the finding Region and confirm an ACTIVE "
            "ACCOUNT analyzer exists, then re-scan so CLOUD-IAM-013 no longer fails."
        ),
        "observed_template": (
            "Sentinel checked IAM Access Analyzer in {region} and found no ACTIVE "
            "account-level analyzer."
        ),
        "meaning_template": (
            "AWS is not currently running this external-access analysis capability for "
            "this account in {region}."
        ),
    },
    "CLOUD-DFT-001": {
        "family": FAMILY_GUARDDUTY,
        "service": "Amazon GuardDuty",
        "technology_tokens": ("guardduty",),
        "forbidden_family_terms": (
            r"access analyzer",
            r"least privilege",
            r"\bs3\b",
            r"block public",
            r"\bnginx\b",
            r"password policy",
        ),
        "plain_english_name": "Amazon GuardDuty",
        "what_it_is": (
            "Amazon GuardDuty is an AWS threat-detection service. It analyzes AWS "
            "activity and related signals to help identify suspicious or unexpected behavior."
        ),
        "security_concept": "Detective control — threat detection",
        "why_it_matters": (
            "Without GuardDuty enabled in the account/Region, AWS is not providing this "
            "managed threat-detection coverage for the environment Sentinel checked."
        ),
        "realistic_risk_example": (
            "If unusual API activity or other suspicious signals appear later, GuardDuty "
            "is one of the AWS services that can help raise findings for investigation. "
            "Without it enabled, that detection layer is unavailable."
        ),
        "absence_does_not_prove": (
            "GuardDuty being absent or not subscribed does not by itself prove an active attack."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing managed threat-detection capability required by the Sentinel baseline",
                "Reduces visibility into suspicious AWS activity signals",
                "Affects account/Region security monitoring posture",
            ],
            "context": [
                "Does not prove compromise is occurring now",
                "SubscriptionRequiredException means the service is not enabled/subscribed",
            ],
        },
        "remediation_plain_english": (
            "Enable Amazon GuardDuty for the account in the intended Region so threat "
            "detection can run against AWS activity signals."
        ),
        "remediation_artifact_hints": ("guardduty", "detector"),
        "remediation_does_not_do": [
            "Automatically block attackers",
            "Rewrite IAM permissions",
            "Prove that malicious activity is currently happening",
            "Replace other logging or monitoring tools by itself",
        ],
        "manager_prechecks": [
            "Confirm the intended AWS Region",
            "Confirm whether GuardDuty should be enabled for this account (cost/coverage)",
            "Review the remediation plan before approving enablement",
        ],
        "verification_plain_english": (
            "Confirm GuardDuty is enabled/subscribed in the Region (for example a detector "
            "exists and is ENABLED), then re-scan so the GuardDuty control no longer fails."
        ),
        "observed_template": (
            "Sentinel checked for GuardDuty as required by the baseline and found it "
            "absent or not enabled/subscribed in the affected Region."
        ),
        "meaning_template": (
            "GuardDuty is not currently providing threat-detection coverage for this "
            "account in the Region Sentinel evaluated."
        ),
        "subscription_required_note": (
            "If AWS returned SubscriptionRequiredException, GuardDuty is not currently "
            "enabled/subscribed for this account in the affected Region — not merely an empty detector list."
        ),
    },
    "CLOUD-LOG-002": {
        "family": FAMILY_CONFIG,
        "service": "AWS Config",
        "technology_tokens": ("aws config", "config recorder"),
        "forbidden_family_terms": (
            r"\bnginx\b",
            r"\bwaf\b",
            r"access analyzer",
            r"\bguardduty\b",
            r"flow logs?",
            r"\bcloudtrail\b",
            r"trail_count",
        ),
        "plain_english_name": "AWS Config recorder",
        "what_it_is": (
            "AWS Config records the configuration of supported AWS resources over time "
            "so you can see what changed and whether resources still match expected settings."
        ),
        "security_concept": "Detective control — configuration recording",
        "why_it_matters": (
            "Without a Config recorder, it is harder to detect configuration drift and to "
            "answer what changed when investigating a security or compliance issue."
        ),
        "realistic_risk_example": (
            "A security setting on a resource is changed during troubleshooting and never "
            "restored. Without Config recording, that drift may go unnoticed longer."
        ),
        "absence_does_not_prove": (
            "A missing Config recorder does not prove resources are currently misconfigured."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing account configuration-recording capability",
                "Weakens drift detection and investigation evidence",
                "Affects continuous compliance visibility",
            ],
            "context": ["Does not prove an active misconfiguration incident"],
        },
        "remediation_plain_english": (
            "Enable an AWS Config recorder (and related delivery settings per the kit) "
            "so resource configuration changes can be recorded."
        ),
        "remediation_artifact_hints": ("config", "recorder"),
        "remediation_does_not_do": [
            "Automatically fix misconfigured resources",
            "Replace GuardDuty or Access Analyzer",
            "Prove current configurations are correct without further review",
        ],
        "manager_prechecks": [
            "Confirm recording scope and delivery location (for example S3) are acceptable",
            "Review cost/impact of continuous configuration recording",
            "Confirm the Terraform/plan matches the intended recorder settings",
        ],
        "verification_plain_english": (
            "Confirm an AWS Config recorder is present and recording, then re-scan so "
            "CLOUD-LOG-002 no longer fails."
        ),
        "observed_template": (
            "Sentinel evaluated AWS Config recorder status and found the required recorder "
            "control not satisfied for this account/environment."
        ),
        "meaning_template": (
            "AWS Config is not currently recording resource configuration as this control requires."
        ),
    },
    "CLOUD-NET-001": {
        "family": FAMILY_NETWORK,
        "service": "VPC Flow Logs",
        "technology_tokens": ("flow log", "vpc flow"),
        "forbidden_family_terms": (
            r"access analyzer",
            r"password policy",
            r"\bguardduty\b",
            r"\bnginx\b",
            r"block public access",
        ),
        "plain_english_name": "VPC Flow Logs",
        "what_it_is": (
            "VPC Flow Logs capture information about IP traffic going to and from network "
            "interfaces in a Virtual Private Cloud (VPC). Security and operations teams "
            "use them to investigate connectivity and suspicious network patterns."
        ),
        "security_concept": "Detective control — network traffic visibility",
        "why_it_matters": (
            "Without flow logs on a VPC, it is harder to investigate unusual network "
            "traffic or confirm whether unexpected communication paths existed."
        ),
        "realistic_risk_example": (
            "During an investigation of unexpected outbound traffic, flow logs can help "
            "show which interfaces talked where. Without them, that evidence may be unavailable."
        ),
        "absence_does_not_prove": (
            "Missing flow logs do not prove that malicious traffic is occurring now."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing network telemetry for the referenced VPC",
                "Reduces ability to investigate network-related incidents",
                "Affects visibility for that VPC's traffic paths",
            ],
            "context": ["Does not prove active network compromise"],
        },
        "remediation_plain_english": (
            "Enable VPC Flow Logs for the referenced VPC so traffic metadata can be captured "
            "to the configured destination."
        ),
        "remediation_artifact_hints": ("flow_log", "vpc"),
        "remediation_does_not_do": [
            "Block malicious traffic by itself",
            "Change security group rules automatically",
            "Prove current traffic is malicious",
        ],
        "manager_prechecks": [
            "Confirm the VPC ID matches the intended network",
            "Confirm log destination and retention are acceptable",
            "Review cost of flow log volume for this VPC",
        ],
        "verification_plain_english": (
            "Confirm flow logs are enabled for the VPC, then re-scan so CLOUD-NET-001 no longer fails."
        ),
        "observed_template": (
            "Sentinel checked VPC Flow Logs for the referenced VPC and found the required "
            "flow-log control not enabled as expected."
        ),
        "meaning_template": (
            "Network traffic metadata for that VPC is not currently being captured as this control requires."
        ),
    },
    "CLOUD-STO-004": {
        "family": FAMILY_STORAGE,
        "service": "EBS encryption by default",
        "technology_tokens": ("ebs", "encryption by default"),
        "forbidden_family_terms": (
            r"\bguardduty\b",
            r"access analyzer",
            r"flow logs?",
            r"\bnginx\b",
            r"identity center",
        ),
        "plain_english_name": "EBS encryption by default",
        "what_it_is": (
            "Amazon EBS (Elastic Block Store) provides disk volumes for EC2 instances. "
            "Encryption by default means new EBS volumes are encrypted automatically "
            "unless overridden."
        ),
        "security_concept": "Preventive control — data-at-rest encryption",
        "why_it_matters": (
            "Without default encryption, new volumes may be created unencrypted, increasing "
            "the chance that disk data is stored without encryption protections."
        ),
        "realistic_risk_example": (
            "An engineer launches an instance and forgets to enable volume encryption. "
            "Default encryption helps prevent that class of mistake for new volumes."
        ),
        "absence_does_not_prove": (
            "Missing default encryption does not prove existing volumes are currently readable by attackers."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing account default for encrypting new EBS volumes",
                "Increases likelihood of unencrypted volumes being created",
                "Affects data-at-rest posture for new EC2 storage",
            ],
            "context": ["Does not prove existing data has been accessed"],
        },
        "remediation_plain_english": (
            "Enable EBS encryption by default for the account/Region so new volumes are encrypted."
        ),
        "remediation_artifact_hints": ("ebs", "encryption"),
        "remediation_does_not_do": [
            "Automatically encrypt all existing volumes without a migration plan",
            "Change IAM users or network rules",
            "Prove current volumes were accessed improperly",
        ],
        "manager_prechecks": [
            "Confirm the intended Region",
            "Confirm KMS key expectations if the plan specifies one",
            "Understand impact on new volume creation workflows",
        ],
        "verification_plain_english": (
            "Confirm EBS encryption by default is enabled, then re-scan so CLOUD-STO-004 no longer fails."
        ),
        "observed_template": (
            "Sentinel checked EBS encryption-by-default and found it not enabled as required."
        ),
        "meaning_template": (
            "New EBS volumes are not guaranteed to be encrypted by account default in this environment."
        ),
    },
    "CLOUD-STO-001": {
        "family": FAMILY_STORAGE,
        "service": "S3 server access logging",
        "technology_tokens": ("access logging", "s3 access log"),
        "forbidden_family_terms": (
            r"\bguardduty\b",
            r"access analyzer",
            r"flow logs?",
            r"\bnginx\b",
            r"identity center",
        ),
        "plain_english_name": "S3 access logging",
        "what_it_is": (
            "S3 server access logging records requests made to an Amazon S3 bucket. "
            "Those logs help investigate who accessed objects and when."
        ),
        "security_concept": "Detective control — object storage access visibility",
        "why_it_matters": (
            "Without access logging on important buckets, it is harder to investigate "
            "unexpected reads or writes after an incident."
        ),
        "realistic_risk_example": (
            "If objects are read unexpectedly, access logs can help show the request "
            "pattern. Without logging, that investigation trail may be missing."
        ),
        "absence_does_not_prove": (
            "Missing access logging does not prove the bucket contents were accessed improperly."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing access telemetry for the referenced S3 bucket",
                "Weakens investigation of object access events",
            ],
            "context": ["Does not prove data exfiltration occurred"],
        },
        "remediation_plain_english": (
            "Enable S3 server access logging for the referenced bucket to a designated target bucket."
        ),
        "remediation_artifact_hints": ("logging", "s3"),
        "remediation_does_not_do": [
            "Make the bucket private by itself",
            "Enable Block Public Access by itself",
            "Prove current unauthorized access",
        ],
        "manager_prechecks": [
            "Confirm the target logging bucket is appropriate",
            "Confirm log retention and access to logs meet policy",
        ],
        "verification_plain_english": (
            "Confirm access logging is enabled on the bucket, then re-scan so the control no longer fails."
        ),
        "observed_template": (
            "Sentinel checked S3 access logging for the referenced bucket and found it not enabled as required."
        ),
        "meaning_template": (
            "Request-level access records are not currently being captured for that bucket as this control requires."
        ),
    },
    "CLOUD-STO-002": {
        "family": FAMILY_STORAGE,
        "service": "S3 versioning",
        "technology_tokens": ("versioning",),
        "forbidden_family_terms": (
            r"\bguardduty\b",
            r"access analyzer",
            r"flow logs?",
            r"\bnginx\b",
            r"identity center",
        ),
        "plain_english_name": "S3 versioning",
        "what_it_is": (
            "S3 versioning keeps multiple variants of an object in the same bucket so "
            "overwrites and deletes can often be recovered."
        ),
        "security_concept": "Resilience control — object recoverability",
        "why_it_matters": (
            "Without versioning, accidental or malicious deletes/overwrites may be harder "
            "or impossible to reverse."
        ),
        "realistic_risk_example": (
            "An automation overwrites a critical object. With versioning, a prior version "
            "can often be restored; without it, recovery may depend on backups alone."
        ),
        "absence_does_not_prove": (
            "Missing versioning does not prove objects have already been deleted or corrupted."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Missing object version history for the referenced bucket",
                "Increases impact of accidental overwrite or delete",
            ],
            "context": ["Does not prove destructive activity already happened"],
        },
        "remediation_plain_english": (
            "Enable S3 versioning on the referenced bucket so object versions can be retained."
        ),
        "remediation_artifact_hints": ("versioning",),
        "remediation_does_not_do": [
            "By itself prevent all unauthorized access",
            "Replace backups or cross-region replication unless also configured",
            "Prove objects were already modified",
        ],
        "manager_prechecks": [
            "Confirm storage-cost impact of retaining versions",
            "Confirm lifecycle rules if versions should expire",
        ],
        "verification_plain_english": (
            "Confirm versioning status is Enabled on the bucket, then re-scan so the control no longer fails."
        ),
        "observed_template": (
            "Sentinel checked S3 versioning for the referenced bucket and found it not enabled as required."
        ),
        "meaning_template": (
            "Prior object versions are not currently retained for that bucket as this control requires."
        ),
    },
    "CLOUD-IAM-014": {
        "family": FAMILY_IDENTITY,
        "service": "IAM Identity Center",
        "technology_tokens": ("identity center", "sso"),
        "forbidden_family_terms": (
            r"\bguardduty\b",
            r"\bs3\b",
            r"flow logs?",
            r"\bnginx\b",
            r"\bebs\b",
        ),
        "plain_english_name": "IAM Identity Center (AWS SSO)",
        "what_it_is": (
            "IAM Identity Center (formerly AWS SSO) is AWS's preferred way to give people "
            "workforce access with federated sign-in and temporary credentials, instead of "
            "many long-lived IAM users."
        ),
        "security_concept": "Identity hygiene — prefer federation over standing IAM users",
        "why_it_matters": (
            "Long-lived IAM user credentials increase standing access risk if keys are "
            "leaked. Identity Center reduces reliance on permanent user passwords/keys."
        ),
        "realistic_risk_example": (
            "A long-lived access key is copied into a script and later exposed. Federated "
            "Identity Center access with short-lived credentials reduces that class of risk."
        ),
        "absence_does_not_prove": (
            "Preferring Identity Center does not by itself prove IAM users have already been abused."
        ),
        "severity_rationale": {
            "rating_source": "Sentinel policy severity",
            "basis": [
                "Standing IAM-user posture instead of preferred Identity Center federation",
                "Increases credential longevity risk relative to federated access",
            ],
            "context": [
                "This is often a migration/recommendation finding — confirm business readiness",
            ],
        },
        "remediation_plain_english": (
            "Move workforce access toward IAM Identity Center (federated permission sets) "
            "and reduce reliance on long-lived IAM users where appropriate."
        ),
        "remediation_artifact_hints": ("identity center", "sso", "permission set"),
        "remediation_does_not_do": [
            "Instantly delete all IAM users without a migration plan",
            "Enable Access Analyzer by itself",
            "Prove credentials were already leaked",
        ],
        "manager_prechecks": [
            "Confirm Identity Center is the intended workforce access model",
            "Confirm break-glass emergency access remains defined",
            "Plan migration for existing IAM users before disabling them",
        ],
        "verification_plain_english": (
            "Confirm Identity Center usage and reduced standing IAM-user risk per the control, "
            "then re-scan so CLOUD-IAM-014 no longer fails."
        ),
        "observed_template": (
            "Sentinel reviewed identity posture and found long-lived IAM user access still "
            "preferred over IAM Identity Center for this environment."
        ),
        "meaning_template": (
            "Workforce access is not aligned with the Sentinel preference for Identity Center federation."
        ),
    },
}


# Stable finding ID used by scan_cloud_pack maps to the GuardDuty explanation family.
CONTROL_EXPLANATIONS["CLOUD-LOG-003"] = CONTROL_EXPLANATIONS["CLOUD-DFT-001"]


def lookup_explanation(finding_id: str | None, title: str | None = None) -> dict[str, Any] | None:
    fid = str(finding_id or "").upper().strip()
    if fid in CONTROL_EXPLANATIONS:
        return dict(CONTROL_EXPLANATIONS[fid])
    title_l = str(title or "").lower()
    # Title-based fallbacks for related IDs
    if "access analyzer" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-IAM-013"])
    if "guardduty" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-DFT-001"])
    if "config recorder" in title_l or title_l.startswith("aws config"):
        return dict(CONTROL_EXPLANATIONS["CLOUD-LOG-002"])
    if "flow log" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-NET-001"])
    if "ebs" in title_l and "encryption" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-STO-004"])
    if "access logging" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-STO-001"])
    if "versioning" in title_l:
        return dict(CONTROL_EXPLANATIONS["CLOUD-STO-002"])
    if "identity center" in title_l or ("sso" in title_l and "iam" in title_l):
        return dict(CONTROL_EXPLANATIONS["CLOUD-IAM-014"])
    return None


def unsupported_risk_claim_reason(
    text: str,
    *,
    evidence_quality: str | None = None,
    finding_status: str | None = None,
    exposure_confirmed: bool = False,
) -> str | None:
    """Reject breach/current-access claims not supported by evidence."""
    body = text or ""
    if exposure_confirmed:
        return None
    quality = str(evidence_quality or "").upper()
    status = str(finding_status or "").upper()
    # Remove educational negation sentences so "does not ... currently has access" is allowed
    scrubbed = re.sub(
        r"(does not[^.]*?(prove|mean|confirm)[^.]*?\.)",
        " ",
        body,
        flags=re.I,
    )
    scrubbed = re.sub(r"(absence of[^.]*?does not[^.]*?\.)", " ", scrubbed, flags=re.I)
    for pat in _UNSAFE_BREACH_PATTERNS:
        if pat.search(scrubbed):
            return (
                "UNSUPPORTED_RISK_CLAIM: explanation claims current breach/access "
                f"without supporting exposure evidence (quality={quality}, status={status})"
            )
    return None


def explanation_control_mismatch_reason(
    finding_id: str | None,
    title: str | None,
    explanation_text: str,
) -> str | None:
    meta = lookup_explanation(finding_id, title)
    if not meta:
        return None
    text = explanation_text or ""
    # Capability overclaims first (e.g. unused-access on external-access analyzer).
    for pat in meta.get("forbidden_capability_claims") or ():
        if re.search(pat, text, re.I):
            return (
                "CASE_NARRATIVE_CONTROL_MISMATCH: "
                f"{finding_id} narrative claims incompatible capability /{pat}/"
            )
    if str(meta.get("analyzer_capability") or "") == "external_access":
        if re.search(r"unused[\s-]?access", text, re.I):
            return (
                "CASE_NARRATIVE_CONTROL_MISMATCH: external-access analyzer remediation "
                "must not claim unused-access analysis"
            )
    for pat in meta.get("forbidden_family_terms") or ():
        if re.search(pat, text, re.I):
            # Unused-access patterns may also appear in family terms — keep narrative code.
            if re.search(r"unused", pat, re.I):
                return (
                    "CASE_NARRATIVE_CONTROL_MISMATCH: "
                    f"{finding_id} narrative claims incompatible capability /{pat}/"
                )
            return (
                "EXPLANATION_CONTROL_MISMATCH: "
                f"{finding_id} explanation contains incompatible term /{pat}/"
            )
    return None


def casebook_why_it_mattered(finding_id: str | None, title: str | None = None) -> str | None:
    """Canonical Casebook/Manager-compatible why-it-mattered text for a control."""
    meta = lookup_explanation(finding_id, title)
    if not meta:
        return None
    return str(meta.get("why_it_matters") or "") or None


def remediation_explanation_mismatch_reason(
    meta: dict[str, Any] | None,
    remediation_plain: str,
    *,
    artifact_preview: str | None = None,
) -> str | None:
    if not meta:
        return None
    hints = [str(h).lower() for h in (meta.get("remediation_artifact_hints") or [])]
    plain = (remediation_plain or "").lower()
    preview = (artifact_preview or "").lower()
    if not hints:
        return None
    # If we have Terraform/preview content, require at least one hint to appear in plain or preview
    if preview.strip():
        if not any(h in preview or h in plain for h in hints):
            return (
                "REMEDIATION_EXPLANATION_MISMATCH: remediation explanation does not match "
                "artifact hints for this control"
            )
    # Plain English should mention service family token
    service = str(meta.get("service") or "").lower()
    token = service.split()[0] if service else ""
    if token and token not in plain and not any(h in plain for h in hints):
        return (
            "REMEDIATION_EXPLANATION_MISMATCH: plain remediation text does not reference "
            f"service/hints for {meta.get('plain_english_name')}"
        )
    return None


def _evidence_context(impact: dict[str, Any] | None, ca: dict[str, Any] | None) -> dict[str, Any]:
    assessment = (ca or {}).get("evidence_assessment") or (impact or {}).get("evidence_assessment") or {}
    quality = str(assessment.get("evidence_quality") or (ca or {}).get("evidence_quality") or "").upper()
    status = str(
        assessment.get("finding_status")
        or (impact or {}).get("finding_status")
        or (ca or {}).get("finding_status")
        or ""
    ).upper()
    result = str(assessment.get("result") or "").upper()
    observed = assessment.get("observed")
    source = str(assessment.get("evidence_source") or "")
    human = None
    if isinstance(observed, dict):
        human = observed.get("human_observed")
    return {
        "assessment": assessment,
        "quality": quality,
        "status": status,
        "result": result,
        "observed": observed,
        "human_observed": human,
        "source": source,
    }


def _evidence_aware_observation(
    meta: dict[str, Any],
    finding: dict[str, Any],
    impact: dict[str, Any] | None,
    ctx: dict[str, Any],
) -> tuple[str, str]:
    """Return (what_sentinel_found, what_it_means) with evidence-aware wording."""
    region = _region(finding, impact)
    quality = ctx["quality"]
    status = ctx["status"]
    result = ctx["result"]
    base_obs = str(meta.get("observed_template") or "").format(region=region)
    base_mean = str(meta.get("meaning_template") or "").format(region=region)
    human = ctx.get("human_observed")

    if quality == "ERROR" or status == "ERROR":
        found = (
            "Sentinel could not verify this control because the AWS API request failed "
            f"or returned an error{(' (' + str(ctx.get('source')) + ')') if ctx.get('source') else ''}."
        )
        meaning = (
            "The current evidence does not confirm whether the control is present or missing; "
            "treat this as unverified until the API error is resolved."
        )
        return found, meaning

    if status in {"UNVERIFIED", "UNKNOWN"} or quality in {"INSUFFICIENT", "UNAVAILABLE"}:
        found = (
            "Sentinel has an indication related to this control, but current evidence does not "
            "directly prove the control state."
        )
        meaning = (
            "More direct evidence is needed before treating this as a confirmed gap. "
            + str(meta.get("absence_does_not_prove") or "")
        ).strip()
        return found, meaning

    if status == "ALREADY_REMEDIATED" or result == "PASS":
        found = (
            "Sentinel directly verified that the required control appears present "
            f"in the checked environment{(f' ({region})' if region else '')}."
        )
        meaning = "No remediation change should be applied unless you verify otherwise."
        return found, meaning

    # DIRECT / CONFIRMED (or confirmed without explicit quality label)
    if human:
        found = f"Sentinel directly queried AWS and observed: {human}."
    elif quality == "DIRECT" or status == "CONFIRMED":
        found = (
            "Sentinel directly queried AWS and confirmed the control condition described below. "
            + base_obs
        )
    else:
        found = base_obs
    # GuardDuty subscription nuance
    obs = ctx.get("observed")
    if meta.get("family") == FAMILY_GUARDDUTY and isinstance(obs, dict):
        blob = str(obs).lower()
        if "subscriptionrequired" in blob:
            found = str(meta.get("subscription_required_note") or found)
    meaning = base_mean + " " + str(meta.get("absence_does_not_prove") or "")
    return found.strip(), meaning.strip()


def build_severity_block(finding: dict[str, Any], meta: dict[str, Any] | None) -> dict[str, Any]:
    rating = str(finding.get("severity") or "info").upper()
    if not meta or not meta.get("severity_rationale"):
        return {
            "rating": rating,
            "label": f"Sentinel severity: {rating}",
            "source": "unknown",
            "basis": [],
            "context": [],
            "incomplete": True,
            "error": "SEVERITY_RATIONALE_INCOMPLETE",
            "explanation": (
                f"Sentinel severity is {rating}, but a control-specific rationale is not yet "
                "available for this finding."
            ),
        }
    rat = meta["severity_rationale"]
    basis = list(rat.get("basis") or [])
    context = list(rat.get("context") or [])
    source = str(rat.get("rating_source") or "Sentinel policy severity")
    lines = [
        f"{source}: {rating}.",
        "Why:",
    ] + [f"- {b}" for b in basis]
    if context:
        lines.append("Context:")
        lines.extend(f"- {c}" for c in context)
    return {
        "rating": rating,
        "label": f"{source}: {rating}",
        "source": source,
        "basis": basis,
        "context": context,
        "incomplete": False,
        "error": None,
        "explanation": "\n".join(lines),
    }


def build_understanding(
    finding: dict[str, Any],
    impact: dict[str, Any] | None = None,
    ca: dict[str, Any] | None = None,
    *,
    artifact_preview: str | None = None,
) -> dict[str, Any]:
    """
    Build the Manager Mode 'Understand this finding' payload.
    Returns readiness errors when explanations are unsafe or mismatched.
    """
    fid = str(finding.get("id") or "")
    title = str(finding.get("title") or "")
    meta = lookup_explanation(fid, title)
    region = _region(finding, impact)
    ctx = _evidence_context(impact, ca)
    errors: list[str] = []

    if not meta:
        return {
            "available": False,
            "control_id": fid,
            "errors": ["EXPLANATION_METADATA_MISSING"],
            "severity": build_severity_block(finding, None),
        }

    found, meaning = _evidence_aware_observation(meta, finding, impact, ctx)
    rem_plain = str(meta.get("remediation_plain_english") or "").replace("{region}", region)
    if "{region}" in rem_plain or "finding Region" in rem_plain:
        rem_plain = rem_plain.replace("finding Region", region).replace("{region}", region)
    # Prefer explicit region phrasing for AA
    if fid == "CLOUD-IAM-013" or "access analyzer" in title.lower():
        rem_plain = f"Create an account-level IAM Access Analyzer in {region}."

    will_not = list(meta.get("remediation_does_not_do") or [])
    prechecks = [
        p.replace("us-east-1", region).replace("{region}", region)
        for p in (meta.get("manager_prechecks") or [])
    ]
    verify = str(meta.get("verification_plain_english") or "").replace("{region}", region)
    if fid == "CLOUD-IAM-013" or "access analyzer" in title.lower():
        verify = (
            f"Re-query IAM Access Analyzer in {region} and confirm an ACTIVE ACCOUNT "
            "analyzer exists, then re-scan so CLOUD-IAM-013 no longer fails."
        )

    severity = build_severity_block(finding, meta)

    payload = {
        "available": True,
        "control_id": fid,
        "family": meta.get("family"),
        "service": meta.get("service"),
        "plain_english_name": meta.get("plain_english_name"),
        "what_is_this": meta.get("what_it_is"),
        "what_sentinel_found": found,
        "what_it_means": meaning,
        "why_care": meta.get("why_it_matters"),
        "realistic_example": meta.get("realistic_risk_example"),
        "absence_does_not_prove": meta.get("absence_does_not_prove"),
        "security_concept": meta.get("security_concept"),
        "severity": severity,
        "fix_will_do": rem_plain,
        "fix_will_not_do": will_not,
        "manager_prechecks": prechecks,
        "how_we_verify": verify,
        "region": region,
        "evidence_quality": ctx["quality"],
        "finding_status": ctx["status"],
        "errors": errors,
    }

    # Assemble text for consistency / risk guards
    blob = " ".join(
        str(payload.get(k) or "")
        for k in (
            "what_is_this",
            "what_sentinel_found",
            "what_it_means",
            "why_care",
            "realistic_example",
            "fix_will_do",
            "how_we_verify",
        )
    )
    claim = unsupported_risk_claim_reason(
        blob,
        evidence_quality=ctx["quality"],
        finding_status=ctx["status"],
        exposure_confirmed=False,
    )
    if claim:
        errors.append(claim)
    mismatch = explanation_control_mismatch_reason(fid, title, blob)
    if mismatch:
        errors.append(mismatch)
    rem_mis = remediation_explanation_mismatch_reason(
        meta, rem_plain, artifact_preview=artifact_preview
    )
    if rem_mis:
        errors.append(rem_mis)
    if severity.get("incomplete"):
        errors.append("SEVERITY_RATIONALE_INCOMPLETE")

    payload["errors"] = errors
    payload["safe_to_present"] = not any(
        e.startswith(
            (
                "UNSUPPORTED_RISK_CLAIM",
                "EXPLANATION_CONTROL_MISMATCH",
                "REMEDIATION_EXPLANATION_MISMATCH",
            )
        )
        for e in errors
    )
    return payload
