# change_assurance/domains/cloud/evidence_registry.py
# Data-driven evidence contracts for Cloud Security controls.
# Match by title tokens (stable) — finding IDs may renumber across pack versions.

from __future__ import annotations

from change_assurance.evidence_quality import EvidenceSpec


def _all_pab_true(observed: dict) -> tuple[bool | None, str]:
    keys = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    vals = {k: observed.get(k) for k in keys}
    if any(v is None for v in vals.values()):
        return None, "incomplete public access block fields"
    ok = all(bool(v) for v in vals.values())
    return ok, "all four Block Public Access settings enabled" if ok else "one or more BPA settings disabled"


def _access_analyzer_active_account(observed: dict) -> tuple[bool | None, str]:
    """PASS only when at least one ACTIVE ACCOUNT analyzer exists in the checked region."""
    if not isinstance(observed, dict):
        return None, "observed value missing"
    if observed.get("error"):
        return None, str(observed.get("error"))
    region = observed.get("region") or "unknown-region"
    analyzers = observed.get("analyzers")
    if analyzers is None and observed.get("active_account_analyzer_count") is None:
        return None, "analyzer list missing"
    active_account: list[dict] = []
    for a in analyzers or []:
        if not isinstance(a, dict):
            continue
        status = str(a.get("status") or a.get("Status") or "").upper()
        atype = str(a.get("type") or a.get("Type") or "").upper()
        if status == "ACTIVE" and atype == "ACCOUNT":
            active_account.append(a)
    count = int(observed.get("active_account_analyzer_count") or len(active_account) or 0)
    if count >= 1 and active_account:
        a0 = active_account[0]
        name = a0.get("name") or a0.get("analyzerName") or a0.get("arn") or "analyzer"
        return True, f"Analyzer name: {name}; Type: ACCOUNT; Status: ACTIVE ({region})"
    if count >= 1:
        return True, f"At least one ACTIVE ACCOUNT analyzer in {region}"
    if analyzers == [] or count == 0:
        return False, f"analyzers = [] (no ACTIVE ACCOUNT analyzer in {region})"
    # Analyzers present but none ACTIVE+ACCOUNT
    return False, f"no ACTIVE ACCOUNT analyzer in {region}"


CLOUD_EVIDENCE_SPECS: list[EvidenceSpec] = [
    # —— IAM password policy (must use get_account_password_policy) ——
    EvidenceSpec(
        control_key="iam_password_min_length",
        title_tokens=("password", "minimum length"),
        preferred_sources=("iam.get_account_password_policy",),
        required_fields=("MinimumPasswordLength",),
        operator=">=",
        expected_value=14,
        human_label="Minimum password length",
        human_expected="14 or greater",
    ),
    EvidenceSpec(
        control_key="iam_password_complexity_upper_symbols",
        title_tokens=("password complexity", "uppercase"),
        preferred_sources=("iam.get_account_password_policy",),
        required_fields=("RequireUppercaseCharacters", "RequireSymbols"),
        operator="all_true",
        expected_value=True,
        human_label="Password complexity (uppercase + symbols)",
        human_expected="RequireUppercaseCharacters and RequireSymbols enabled",
    ),
    EvidenceSpec(
        control_key="iam_password_complexity_lower_numbers",
        title_tokens=("password complexity", "lowercase"),
        preferred_sources=("iam.get_account_password_policy",),
        required_fields=("RequireLowercaseCharacters", "RequireNumbers"),
        operator="all_true",
        expected_value=True,
        human_label="Password complexity (lowercase + numbers)",
        human_expected="RequireLowercaseCharacters and RequireNumbers enabled",
    ),
    EvidenceSpec(
        control_key="iam_password_max_age",
        title_tokens=("password", "max age"),
        preferred_sources=("iam.get_account_password_policy",),
        required_fields=("MaxPasswordAge",),
        operator="custom",
        expected_value="1–90",
        human_label="Max password age (days)",
        human_expected="1–90 days (set and <= 90)",
        custom_eval=lambda o: (
            (False, "MaxPasswordAge unset/0")
            if int((o or {}).get("MaxPasswordAge") or 0) <= 0
            else (
                (True, f"MaxPasswordAge={int(o.get('MaxPasswordAge'))}")
                if int(o.get("MaxPasswordAge")) <= 90
                else (False, f"MaxPasswordAge={int(o.get('MaxPasswordAge'))} > 90")
            )
        ),
    ),
    EvidenceSpec(
        control_key="iam_password_reuse",
        title_tokens=("password", "reuse"),
        preferred_sources=("iam.get_account_password_policy",),
        required_fields=("PasswordReusePrevention",),
        operator=">=",
        expected_value=24,
        human_label="Password reuse prevention",
        human_expected="24 or greater",
    ),
    # —— IAM account summary fields (these ARE on get_account_summary) ——
    EvidenceSpec(
        control_key="iam_root_mfa",
        title_tokens=("root", "mfa"),
        preferred_sources=("iam.get_account_summary",),
        required_fields=("AccountMFAEnabled",),
        operator="==",
        expected_value=1,
        human_label="Root account MFA",
        human_expected="Enabled (1)",
    ),
    EvidenceSpec(
        control_key="iam_root_no_access_keys",
        title_tokens=("root", "access keys"),
        preferred_sources=("iam.get_account_summary",),
        required_fields=("AccountAccessKeysPresent",),
        operator="==",
        expected_value=0,
        human_label="Root access keys present",
        human_expected="0 (none)",
    ),
    # —— IAM Access Analyzer (regional; never infer from get_account_summary) ——
    EvidenceSpec(
        control_key="iam_access_analyzer",
        title_tokens=("access", "analyzer"),
        preferred_sources=("accessanalyzer.list_analyzers",),
        required_fields=("active_account_analyzer_count", "region", "human_observed"),
        operator="custom",
        expected_value=">= 1 ACTIVE ACCOUNT analyzer",
        human_label="IAM Access Analyzer",
        human_expected="At least one active account-level analyzer",
        custom_eval=_access_analyzer_active_account,
    ),
    # —— S3 account BPA ——
    EvidenceSpec(
        control_key="s3_account_bpa",
        title_tokens=("public access",),
        id_prefixes=("CLOUD-STO",),
        preferred_sources=("s3control.get_public_access_block",),
        required_fields=(
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ),
        operator="all_true",
        expected_value=True,
        human_label="S3 account Block Public Access",
        human_expected="All four settings enabled",
        custom_eval=_all_pab_true,
    ),
    EvidenceSpec(
        control_key="s3_account_bpa_alt",
        title_tokens=("s3", "block public"),
        preferred_sources=("s3control.get_public_access_block",),
        required_fields=(
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ),
        operator="all_true",
        expected_value=True,
        human_label="S3 account Block Public Access",
        human_expected="All four settings enabled",
        custom_eval=_all_pab_true,
    ),
    # —— CloudTrail ——
    EvidenceSpec(
        control_key="cloudtrail_present",
        title_tokens=("cloudtrail",),
        id_prefixes=("CLOUD-LOG",),
        preferred_sources=("cloudtrail.describe_trails", "cloudtrail.get_trail_status"),
        required_fields=("trail_count",),
        operator=">=",
        expected_value=1,
        human_label="CloudTrail trails",
        human_expected="At least one trail configured",
    ),
    # —— Security groups ——
    EvidenceSpec(
        control_key="sg_open_world",
        title_tokens=("security group",),
        id_prefixes=("CLOUD-NET",),
        preferred_sources=("ec2.describe_security_groups",),
        required_fields=("open_world_count",),
        operator="==",
        expected_value=0,
        human_label="Open-world security group rules",
        human_expected="0",
    ),
]


def cloud_specs() -> list[EvidenceSpec]:
    return list(CLOUD_EVIDENCE_SPECS)
