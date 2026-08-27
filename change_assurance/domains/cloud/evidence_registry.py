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


def _config_recorder_enabled(observed: dict) -> tuple[bool | None, str]:
    """
    CLOUD-LOG-002 contract: an AWS Config configuration recorder must exist and be recording.
    Empty ConfigurationRecorders → FAIL. Exists but recording=false → FAIL.
    """
    if not isinstance(observed, dict):
        return None, "observed value missing"
    if observed.get("error"):
        return None, str(observed.get("error"))
    region = observed.get("region") or "unknown-region"
    recorders = observed.get("ConfigurationRecorders")
    if recorders is None:
        recorders = observed.get("recorders")
    if recorders is None and observed.get("recorder_count") is not None:
        count = int(observed.get("recorder_count") or 0)
        recorders = [] if count == 0 else [{"name": "present"}]
    if recorders is None:
        return None, "configuration recorder list missing"
    if recorders == [] or int(observed.get("recorder_count") or len(recorders) or 0) == 0:
        return False, f"No AWS Config configuration recorder found in {region}"

    recording = observed.get("recording")
    if recording is True:
        return True, f"AWS Config configuration recorder is recording in {region}"
    if recording is False:
        return False, f"AWS Config configuration recorder exists but is not recording in {region}"

    statuses = observed.get("ConfigurationRecordersStatus") or observed.get("recorder_statuses") or []
    if statuses:
        if any(bool(s.get("recording") if isinstance(s, dict) else False) for s in statuses):
            return True, f"AWS Config configuration recorder is recording in {region}"
        return False, f"AWS Config configuration recorder exists but is not recording in {region}"
    return None, f"recorder present in {region} but recording status unavailable"


def _guardduty_detector_enabled(observed: dict) -> tuple[bool | None, str]:
    """
    CLOUD-LOG-003: GuardDuty must have an ENABLED detector in the Region.
    Empty DetectorIds → FAIL. SubscriptionRequiredException (semantic) → FAIL.
    """
    if not isinstance(observed, dict):
        return None, "observed value missing"
    region = observed.get("region") or "unknown-region"

    # Semantic control-state from known AWS exceptions (not a transport/permission failure)
    if observed.get("semantic") or observed.get("control_state") == "SERVICE_NOT_SUBSCRIBED":
        human = observed.get("human_observed") or (
            f"Amazon GuardDuty is not subscribed/enabled in {region}"
        )
        return False, str(human)
    code = str(observed.get("code") or observed.get("error_code") or "")
    if "SubscriptionRequired" in code or "subscriptionrequired" in str(
        observed.get("error") or ""
    ).lower():
        return False, (
            observed.get("human_observed")
            or f"Amazon GuardDuty is not subscribed/enabled in {region}"
        )

    if observed.get("error") and not observed.get("DetectorIds") and observed.get("detectors") is None:
        # Non-semantic API error — cannot evaluate
        return None, str(observed.get("error") or "GuardDuty API error")

    detectors = observed.get("detectors")
    if detectors is None:
        ids = observed.get("DetectorIds")
        if ids is not None:
            detectors = [{"id": d, "status": observed.get("status")} for d in (ids or [])]
    if detectors is None and observed.get("detector_count") is not None:
        count = int(observed.get("detector_count") or 0)
        detectors = [] if count == 0 else [{"id": "present", "status": observed.get("status")}]
    if detectors is None:
        return None, "GuardDuty detector list missing"

    if detectors == [] or int(observed.get("detector_count") or len(detectors) or 0) == 0:
        return False, f"No GuardDuty detector exists in the account/Region ({region})"

    enabled = []
    for d in detectors:
        if not isinstance(d, dict):
            continue
        status = str(d.get("status") or d.get("Status") or "").upper()
        if status == "ENABLED" or d.get("enabled") is True:
            enabled.append(d)
    if enabled:
        did = enabled[0].get("id") or enabled[0].get("DetectorId") or "detector"
        return True, f"GuardDuty detector {did} is ENABLED in {region}"
    # Detectors exist but none ENABLED
    return False, f"GuardDuty detector(s) exist in {region} but none are ENABLED"


CLOUD_EVIDENCE_SPECS: list[EvidenceSpec] = [
    # —— IAM password policy (must use get_account_password_policy) ——
    EvidenceSpec(
        control_key="iam_password_min_length",
        title_tokens=("password", "minimum length"),
        preferred_sources=("iam.get_account_password_policy",),
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer.", "guardduty."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="iam",
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
        control_ids=("CLOUD-IAM-013",),
        preferred_sources=("accessanalyzer.list_analyzers",),
        incompatible_sources=(
            "cloudtrail.",
            "configservice.",
            "iam.get_account_password_policy",
            "iam.get_account_summary",
            "guardduty.",
        ),
        aws_service="accessanalyzer",
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
        incompatible_sources=("cloudtrail.", "configservice.", "iam.", "accessanalyzer."),
        aws_service="s3",
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
        incompatible_sources=("cloudtrail.", "configservice.", "iam.", "accessanalyzer."),
        aws_service="s3",
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
    # —— AWS Config recorder (must NOT use CloudTrail evidence) ——
    EvidenceSpec(
        control_key="aws_config_recorder",
        title_tokens=("config", "recorder"),
        preferred_sources=(
            "configservice.describe_configuration_recorders",
            "config.describe_configuration_recorders",
            "configservice.describe_configuration_recorder_status",
            "config.describe_configuration_recorder_status",
        ),
        incompatible_sources=(
            "cloudtrail.",
            "iam.get_account_password_policy",
            "iam.get_account_summary",
            "accessanalyzer.",
            "guardduty.",
            "s3control.",
            "ec2.describe_security_groups",
        ),
        aws_service="config",
        required_fields=("region", "human_observed"),
        operator="custom",
        expected_value="enabled/recording configuration recorder",
        human_label="AWS Config configuration recorder",
        human_expected="An enabled/recording AWS Config configuration recorder",
        custom_eval=_config_recorder_enabled,
    ),
    # —— Amazon GuardDuty detector ——
    EvidenceSpec(
        control_key="aws_guardduty_detector",
        title_tokens=("guardduty",),
        control_ids=("CLOUD-LOG-003",),
        preferred_sources=(
            "guardduty.list_detectors",
            "guardduty.get_detector",
        ),
        incompatible_sources=(
            "cloudtrail.",
            "configservice.",
            "config.describe_configuration",
            "accessanalyzer.",
            "iam.get_account_password_policy",
            "iam.get_account_summary",
            "s3control.",
        ),
        aws_service="guardduty",
        required_fields=("region", "human_observed"),
        operator="custom",
        expected_value="enabled GuardDuty detector",
        human_label="Amazon GuardDuty detector",
        human_expected="An enabled GuardDuty detector",
        custom_eval=_guardduty_detector_enabled,
    ),
    # —— CloudTrail (title/service match only — never all CLOUD-LOG* IDs) ——
    EvidenceSpec(
        control_key="cloudtrail_present",
        title_tokens=("cloudtrail",),
        preferred_sources=("cloudtrail.describe_trails", "cloudtrail.get_trail_status"),
        incompatible_sources=(
            "configservice.",
            "config.describe_configuration",
            "accessanalyzer.",
            "iam.get_account_password_policy",
            "guardduty.",
        ),
        aws_service="cloudtrail",
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
        incompatible_sources=("cloudtrail.", "configservice.", "accessanalyzer."),
        aws_service="ec2",
        required_fields=("open_world_count",),
        operator="==",
        expected_value=0,
        human_label="Open-world security group rules",
        human_expected="0",
    ),
]


def cloud_specs() -> list[EvidenceSpec]:
    return list(CLOUD_EVIDENCE_SPECS)
