# predeploy/aws_dependency_discovery.py
# Read-only AWS discovery for pre-deployment impact analysis.

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

VERSION = "0.1.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence(
    *,
    finding_id: str | None,
    api_call: str,
    resource_id: str | None,
    resource_type: str,
    observed_value: Any,
    expected_value: Any = None,
    confidence: str = "high",
    account_id: str | None = None,
    region: str | None = None,
    quality: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    row = {
        "finding_id": finding_id,
        "account_id": account_id,
        "region": region,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "evidence_source": "aws_api",
        "api_call": api_call,
        "observed_value": observed_value,
        "expected_value": expected_value,
        "timestamp": _now(),
        "confidence": confidence,
    }
    if quality:
        row["quality"] = quality
    if purpose:
        row["purpose"] = purpose
    return row


def discover_for_findings(
    finding_ids: list[str],
    findings: list[dict[str, Any]] | None = None,
    *,
    profile: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    """
    Route to specialized discovery based on finding IDs / titles.
    Always read-only. Soft-fails to empty discovery if creds missing.
    """
    profile = profile or os.environ.get("AWS_PROFILE") or "sentinel-demo"
    region = region or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    ids = [str(x) for x in (finding_ids or [])]
    findings = findings or []
    primary = findings[0] if findings else {}
    titles = " ".join(str(f.get("title") or "") for f in findings).lower()
    joined = " ".join(ids).upper() + " " + titles

    if any(x.startswith("CLOUD-STO") for x in ids) or "public access block" in titles or "s3" in joined.lower():
        return discover_s3_account_bpa(
            profile=profile,
            region=region,
            finding_id=ids[0] if ids else "CLOUD-STO-001",
            finding=primary,
        )
    if any(x.startswith("CLOUD-LOG") for x in ids) or "cloudtrail" in titles:
        return discover_cloudtrail(
            profile=profile,
            region=region,
            finding_id=next((i for i in ids if i.startswith("CLOUD-LOG")), ids[0] if ids else "CLOUD-LOG-001"),
            finding=primary,
        )
    if any(x.startswith("CLOUD-NET") for x in ids) or "security group" in titles:
        return discover_security_groups(
            profile=profile,
            region=region,
            finding_id=ids[0] if ids else "CLOUD-NET-001",
            finding=primary,
        )
    if any(x.startswith("CLOUD-IAM") for x in ids) or "iam" in titles or "password" in titles:
        return discover_iam_light(
            profile=profile,
            region=region,
            finding_id=ids[0] if ids else "CLOUD-IAM-001",
            finding=primary,
        )

    return {
        "version": VERSION,
        "profile": profile,
        "region": region,
        "kind": "generic",
        "status": "SKIP",
        "summary": {"finding_status": "UNVERIFIED"},
        "evidence": [],
        "evidence_assessment": {
            "finding_status": "UNVERIFIED",
            "evidence_quality": "UNAVAILABLE",
            "reason": "No specialized discovery mapper for these finding IDs",
        },
        "notes": ["No specialized discovery mapper for these finding IDs — manager context may be required."],
    }


def discover_s3_account_bpa(
    *,
    profile: str,
    region: str,
    finding_id: str = "CLOUD-STO-001",
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "account_pab": {},
        "bucket_count": 0,
        "public_buckets": 0,
        "public_policy_buckets": 0,
        "public_acl_buckets": 0,
        "website_buckets": 0,
        "finding_status": "UNKNOWN",
    }
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return {
            "version": VERSION,
            "kind": "s3_account_bpa",
            "status": "FAIL",
            "error": "boto3 not installed",
            "summary": summary,
            "evidence": evidence,
        }

    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        account = ident.get("Account")
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="sts.get_caller_identity",
                resource_id=account,
                resource_type="aws_account",
                observed_value=ident.get("Arn"),
                account_id=account,
                region=region,
            )
        )
        s3 = session.client("s3")
        s3c = session.client("s3control")
        try:
            pab = s3c.get_public_access_block(AccountId=account).get("PublicAccessBlockConfiguration") or {}
        except ClientError as e:
            code = (e.response.get("Error") or {}).get("Code")
            pab = {}
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfig"}:
                pab = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            evidence.append(
                _evidence(
                    finding_id=finding_id,
                    api_call="s3control.get_public_access_block",
                    resource_id=account,
                    resource_type="aws_s3_account_public_access_block",
                    observed_value={"error": code or str(e)},
                    expected_value={"all_four": True},
                    account_id=account,
                    region=region,
                    confidence="medium",
                )
            )
        summary["account_pab"] = {
            "BlockPublicAcls": bool(pab.get("BlockPublicAcls")),
            "IgnorePublicAcls": bool(pab.get("IgnorePublicAcls")),
            "BlockPublicPolicy": bool(pab.get("BlockPublicPolicy")),
            "RestrictPublicBuckets": bool(pab.get("RestrictPublicBuckets")),
        }
        all_on = all(summary["account_pab"].values())
        # Tentative only — evidence assessment below is authoritative (no CONFIRMED from presence alone)
        summary["finding_status"] = "UNVERIFIED"
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="s3control.get_public_access_block",
                resource_id=account,
                resource_type="aws_s3_account_public_access_block",
                observed_value=summary["account_pab"],
                expected_value={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                account_id=account,
                region=region,
                quality="DIRECT",
                purpose="proof",
            )
        )

        buckets = s3.list_buckets().get("Buckets") or []
        summary["bucket_count"] = len(buckets)
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="s3.list_buckets",
                resource_id=account,
                resource_type="aws_s3_bucket_list",
                observed_value={"count": len(buckets), "names": [b["Name"] for b in buckets[:50]]},
                account_id=account,
                region=region,
            )
        )
        public_names: list[str] = []
        website_names: list[str] = []
        policy_public: list[str] = []
        acl_public: list[str] = []
        for b in buckets[:80]:
            name = b["Name"]
            # policy status
            try:
                st = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus") or {}
                if st.get("IsPublic"):
                    summary["public_policy_buckets"] += 1
                    summary["public_buckets"] += 1
                    policy_public.append(name)
                    public_names.append(name)
            except ClientError:
                pass
            try:
                acl = s3.get_bucket_acl(Bucket=name).get("Grants") or []
                for g in acl:
                    uri = ((g.get("Grantee") or {}).get("URI") or "").lower()
                    if "allusers" in uri or "authenticatedusers" in uri:
                        summary["public_acl_buckets"] += 1
                        summary["public_buckets"] += 1
                        acl_public.append(name)
                        if name not in public_names:
                            public_names.append(name)
                        break
            except ClientError:
                pass
            try:
                web = s3.get_bucket_website(Bucket=name)
                if web:
                    summary["website_buckets"] += 1
                    website_names.append(name)
            except ClientError:
                pass

        if public_names:
            evidence.append(
                _evidence(
                    finding_id=finding_id,
                    api_call="s3.get_bucket_policy_status|get_bucket_acl",
                    resource_id="multiple",
                    resource_type="aws_s3_bucket",
                    observed_value={"public_buckets": public_names[:20]},
                    expected_value={"public_buckets": []},
                    account_id=account,
                    region=region,
                    quality="INDIRECT",
                    purpose="account context",
                )
            )
        if website_names:
            evidence.append(
                _evidence(
                    finding_id=finding_id,
                    api_call="s3.get_bucket_website",
                    resource_id="multiple",
                    resource_type="aws_s3_bucket_website",
                    observed_value={"website_buckets": website_names[:20]},
                    account_id=account,
                    region=region,
                    confidence="medium",
                    quality="INDIRECT",
                    purpose="account context",
                )
            )

        from change_assurance.domains.cloud.evidence_registry import cloud_specs
        from change_assurance.evidence_quality import assess_finding_evidence

        assessment = assess_finding_evidence(
            finding_id=finding_id,
            title=str((finding or {}).get("title") or finding_id),
            evidence=evidence,
            specs=cloud_specs(),
        )
        summary["finding_status"] = assessment.get("finding_status") or summary.get("finding_status")

        return {
            "version": VERSION,
            "kind": "s3_account_bpa",
            "status": "OK",
            "profile": profile,
            "region": region,
            "account_id": account,
            "summary": summary,
            "public_bucket_names": public_names,
            "website_bucket_names": website_names,
            "policy_public_buckets": policy_public,
            "acl_public_buckets": acl_public,
            "evidence": assessment.get("labeled_evidence") or evidence,
            "evidence_assessment": assessment,
            "scope": "account-wide",
            "potentially_affected_workloads": (
                "MANAGER CONTEXT REQUIRED — public/website buckets may be intentional"
                if (public_names or website_names)
                else "None detected"
            ),
        }
    except Exception as e:
        return {
            "version": VERSION,
            "kind": "s3_account_bpa",
            "status": "FAIL",
            "error": str(e),
            "summary": summary,
            "evidence": evidence,
            "profile": profile,
            "region": region,
        }


def discover_cloudtrail(
    *,
    profile: str,
    region: str,
    finding_id: str,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from change_assurance.domains.cloud.evidence_registry import cloud_specs
    from change_assurance.evidence_quality import assess_finding_evidence

    evidence: list[dict] = []
    summary = {"trail_count": 0, "multi_region": False, "finding_status": "UNKNOWN"}
    try:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList") or []
        summary["trail_count"] = len(trails)
        summary["multi_region"] = any(t.get("IsMultiRegionTrail") for t in trails)
        account = session.client("sts").get_caller_identity().get("Account")
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="cloudtrail.describe_trails",
                resource_id=account,
                resource_type="aws_cloudtrail",
                observed_value={
                    "trail_count": len(trails),
                    "multi_region": summary["multi_region"],
                    "trails": [
                        {
                            "name": t.get("Name"),
                            "multi": t.get("IsMultiRegionTrail"),
                            "bucket": t.get("S3BucketName"),
                        }
                        for t in trails
                    ],
                },
                expected_value={"trail_count": ">= 1"},
                account_id=account,
                region=region,
                quality="DIRECT",
                purpose="proof",
            )
        )
        assessment = assess_finding_evidence(
            finding_id=finding_id,
            title=str((finding or {}).get("title") or finding_id),
            evidence=evidence,
            specs=cloud_specs(),
        )
        summary["finding_status"] = assessment.get("finding_status") or "UNVERIFIED"
        return {
            "version": VERSION,
            "kind": "cloudtrail",
            "status": "OK",
            "profile": profile,
            "region": region,
            "account_id": account,
            "summary": summary,
            "evidence": assessment.get("labeled_evidence") or evidence,
            "evidence_assessment": assessment,
            "scope": "account-wide",
            "potentially_affected_workloads": "None detected (logging control)",
        }
    except Exception as e:
        return {
            "version": VERSION,
            "kind": "cloudtrail",
            "status": "FAIL",
            "error": str(e),
            "summary": {**summary, "finding_status": "ERROR"},
            "evidence": evidence,
            "evidence_assessment": {
                "finding_status": "ERROR",
                "evidence_quality": "ERROR",
                "reason": str(e),
            },
        }


def discover_security_groups(
    *,
    profile: str,
    region: str,
    finding_id: str,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from change_assurance.domains.cloud.evidence_registry import cloud_specs
    from change_assurance.evidence_quality import assess_finding_evidence

    try:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups") or []
        open_world = []
        for sg in sgs:
            for perm in sg.get("IpPermissions") or []:
                for r in perm.get("IpRanges") or []:
                    if r.get("CidrIp") == "0.0.0.0/0":
                        open_world.append(
                            {
                                "id": sg.get("GroupId"),
                                "name": sg.get("GroupName"),
                                "from": perm.get("FromPort"),
                                "to": perm.get("ToPort"),
                            }
                        )
        evidence = [
            _evidence(
                finding_id=finding_id,
                api_call="ec2.describe_security_groups",
                resource_id="account",
                resource_type="aws_security_group",
                observed_value={"open_world_count": len(open_world), "examples": open_world[:10]},
                expected_value={"open_world_count": 0},
                region=region,
                quality="DIRECT",
                purpose="proof",
            )
        ]
        assessment = assess_finding_evidence(
            finding_id=finding_id,
            title=str((finding or {}).get("title") or finding_id),
            evidence=evidence,
            specs=cloud_specs(),
        )
        status = assessment.get("finding_status") or "UNVERIFIED"
        return {
            "version": VERSION,
            "kind": "security_groups",
            "status": "OK",
            "summary": {
                "sg_count": len(sgs),
                "open_world_rules": len(open_world),
                "finding_status": status,
            },
            "open_world_rules": open_world[:30],
            "evidence": assessment.get("labeled_evidence") or evidence,
            "evidence_assessment": assessment,
            "scope": "regional",
            "potentially_affected_workloads": (
                "MANAGER CONTEXT REQUIRED — open ingress may be intentional for edge services"
                if open_world
                else "None detected"
            ),
            "flags_hint": {"networking_change": True, "public_workload_dependency": bool(open_world)},
        }
    except Exception as e:
        return {
            "version": VERSION,
            "kind": "security_groups",
            "status": "FAIL",
            "error": str(e),
            "summary": {"finding_status": "ERROR"},
            "evidence": [],
            "evidence_assessment": {
                "finding_status": "ERROR",
                "evidence_quality": "ERROR",
                "reason": str(e),
            },
        }


def discover_iam_light(
    *,
    profile: str,
    region: str,
    finding_id: str,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Collect IAM evidence appropriate to the finding.
    Password-policy controls require iam.get_account_password_policy (DIRECT).
    get_account_summary alone is INDIRECT context for those controls.
    """
    from change_assurance.domains.cloud.evidence_registry import cloud_specs
    from change_assurance.evidence_quality import assess_finding_evidence

    finding = finding or {}
    title = str(finding.get("title") or "")
    evidence: list[dict[str, Any]] = []
    collection_error = None
    summary_map: dict[str, Any] = {}
    password_policy: dict[str, Any] = {}
    aa_summary: dict[str, Any] = {}

    try:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        iam = session.client("iam")
        try:
            summary_map = iam.get_account_summary().get("SummaryMap") or {}
            evidence.append(
                _evidence(
                    finding_id=finding_id,
                    api_call="iam.get_account_summary",
                    resource_id="account",
                    resource_type="aws_iam_account",
                    observed_value={
                        "Users": summary_map.get("Users"),
                        "AccountMFAEnabled": summary_map.get("AccountMFAEnabled"),
                        "AccountAccessKeysPresent": summary_map.get("AccountAccessKeysPresent"),
                    },
                    region=region,
                    quality="INDIRECT",
                    purpose="account context",
                )
            )
        except Exception as e:
            collection_error = f"iam.get_account_summary: {e}"

        # Access Analyzer is regional — collect DIRECT proof only for AA findings.
        title_l_early = title.lower()
        needs_access_analyzer = (
            ("access" in title_l_early and "analyzer" in title_l_early)
            or str(finding_id or "").upper() == "CLOUD-IAM-013"
        )
        if needs_access_analyzer:
            try:
                aa = session.client("accessanalyzer", region_name=region)
                analyzers_raw = aa.list_analyzers().get("analyzers") or []
                analyzers: list[dict[str, Any]] = []
                active_account: list[dict[str, Any]] = []
                for a in analyzers_raw:
                    if not isinstance(a, dict):
                        continue
                    row = {
                        "name": a.get("name") or a.get("analyzerName"),
                        "arn": a.get("arn"),
                        "type": a.get("type"),
                        "status": a.get("status"),
                    }
                    analyzers.append(row)
                    if (
                        str(row.get("status") or "").upper() == "ACTIVE"
                        and str(row.get("type") or "").upper() == "ACCOUNT"
                    ):
                        active_account.append(row)
                if active_account:
                    human = (
                        f"Analyzer name: {active_account[0].get('name')}; "
                        f"Type: ACCOUNT; Status: ACTIVE"
                    )
                else:
                    human = f"No Access Analyzer found in {region}"
                aa_summary = {
                    "analyzers": analyzers,
                    "analyzer_count": len(analyzers),
                    "active_account_analyzer_count": len(active_account),
                    "region": region,
                    "human_observed": human,
                    "matching_analyzer": active_account[0] if active_account else None,
                }
                evidence.append(
                    _evidence(
                        finding_id=finding_id,
                        api_call="accessanalyzer.list_analyzers",
                        resource_id=f"accessanalyzer:{region}",
                        resource_type="aws_accessanalyzer_analyzer",
                        observed_value=aa_summary,
                        expected_value={
                            "active_account_analyzer_count": ">= 1",
                            "type": "ACCOUNT",
                            "status": "ACTIVE",
                            "region": region,
                        },
                        region=region,
                        quality="DIRECT",
                        purpose="proof",
                    )
                )
            except Exception as e:
                err_name = type(e).__name__
                code = ""
                try:
                    code = str((getattr(e, "response", {}) or {}).get("Error", {}).get("Code") or "")
                except Exception:
                    code = ""
                evidence.append(
                    _evidence(
                        finding_id=finding_id,
                        api_call="accessanalyzer.list_analyzers",
                        resource_id=f"accessanalyzer:{region}",
                        resource_type="aws_accessanalyzer_analyzer",
                        observed_value={
                            "error": str(e),
                            "error_type": err_name,
                            "code": code,
                            "region": region,
                        },
                        region=region,
                        quality="ERROR",
                        purpose="error",
                        confidence="low",
                    )
                )
                collection_error = f"accessanalyzer.list_analyzers: {e}"

        try:
            password_policy = iam.get_account_password_policy().get("PasswordPolicy") or {}
            evidence.append(
                _evidence(
                    finding_id=finding_id,
                    api_call="iam.get_account_password_policy",
                    resource_id="account",
                    resource_type="aws_iam_password_policy",
                    observed_value={
                        "MinimumPasswordLength": password_policy.get("MinimumPasswordLength"),
                        "RequireUppercaseCharacters": password_policy.get("RequireUppercaseCharacters"),
                        "RequireLowercaseCharacters": password_policy.get("RequireLowercaseCharacters"),
                        "RequireNumbers": password_policy.get("RequireNumbers"),
                        "RequireSymbols": password_policy.get("RequireSymbols"),
                        "MaxPasswordAge": password_policy.get("MaxPasswordAge"),
                        "PasswordReusePrevention": password_policy.get("PasswordReusePrevention"),
                        "HardExpiry": password_policy.get("HardExpiry"),
                    },
                    region=region,
                    quality="DIRECT",
                    purpose="proof",
                )
            )
        except Exception as e:
            # No password policy configured is itself signal for password controls
            err_name = type(e).__name__
            code = ""
            try:
                code = str((getattr(e, "response", {}) or {}).get("Error", {}).get("Code") or "")
            except Exception:
                code = ""
            if "NoSuchEntity" in code or "NoSuchEntity" in str(e):
                password_policy = {"PasswordPolicy": "NOT_CONFIGURED"}
                evidence.append(
                    _evidence(
                        finding_id=finding_id,
                        api_call="iam.get_account_password_policy",
                        resource_id="account",
                        resource_type="aws_iam_password_policy",
                        observed_value={
                            "PasswordPolicy": "NOT_CONFIGURED",
                            "MinimumPasswordLength": 0,
                            "RequireUppercaseCharacters": False,
                            "RequireLowercaseCharacters": False,
                            "RequireNumbers": False,
                            "RequireSymbols": False,
                            "MaxPasswordAge": 0,
                            "PasswordReusePrevention": 0,
                            "policy_present": False,
                        },
                        expected_value={"MinimumPasswordLength": ">= 14", "policy_present": True},
                        region=region,
                        quality="DIRECT",
                        purpose="proof",
                        confidence="high",
                    )
                )
            else:
                evidence.append(
                    _evidence(
                        finding_id=finding_id,
                        api_call="iam.get_account_password_policy",
                        resource_id="account",
                        resource_type="aws_iam_password_policy",
                        observed_value={"error": str(e), "error_type": err_name, "code": code},
                        region=region,
                        quality="ERROR",
                        purpose="error",
                        confidence="low",
                    )
                )
                if not collection_error:
                    collection_error = f"iam.get_account_password_policy: {e}"
    except Exception as e:
        return {
            "version": VERSION,
            "kind": "iam",
            "status": "FAIL",
            "error": str(e),
            "summary": {"finding_status": "ERROR"},
            "evidence": evidence,
            "evidence_assessment": {
                "finding_status": "ERROR",
                "evidence_quality": "ERROR",
                "reason": str(e),
            },
            "scope": "account-wide",
            "potentially_affected_workloads": "MANAGER CONTEXT REQUIRED for IAM privilege reductions",
            "flags_hint": {"iam_change": True},
        }

    # For root MFA / access-key controls, also emit a DIRECT summary-shaped proof row
    # so assessment can confirm those fields from get_account_summary.
    title_l = title.lower()
    if summary_map and (("root" in title_l and "mfa" in title_l) or ("root" in title_l and "access key" in title_l)):
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="iam.get_account_summary",
                resource_id="account",
                resource_type="aws_iam_account",
                observed_value={
                    "AccountMFAEnabled": int(summary_map.get("AccountMFAEnabled") or 0),
                    "AccountAccessKeysPresent": int(summary_map.get("AccountAccessKeysPresent") or 0),
                },
                region=region,
                quality="DIRECT",
                purpose="proof",
            )
        )

    assessment = assess_finding_evidence(
        finding_id=finding_id,
        title=title or finding_id,
        evidence=evidence,
        specs=cloud_specs(),
        collection_error=None,  # partial errors already labeled on rows; don't fail whole assessment
    )
    # If password-policy API hard-errored and this is a password finding, surface ERROR
    if "password" in title_l and any(
        (e.get("quality") == "ERROR" and "password_policy" in str(e.get("api_call") or "")) for e in evidence
    ):
        if assessment.get("finding_status") == "UNVERIFIED" and collection_error:
            assessment = assess_finding_evidence(
                finding_id=finding_id,
                title=title or finding_id,
                evidence=evidence,
                specs=cloud_specs(),
                collection_error=collection_error,
            )
    # Access Analyzer API errors (AccessDenied / failure) → ERROR / UNVERIFIED path
    if ("access" in title_l and "analyzer" in title_l) or str(finding_id or "").upper() == "CLOUD-IAM-013":
        if any(
            (e.get("quality") == "ERROR" and "accessanalyzer" in str(e.get("api_call") or "").lower())
            for e in evidence
        ):
            assessment = assess_finding_evidence(
                finding_id=finding_id,
                title=title or finding_id,
                evidence=evidence,
                specs=cloud_specs(),
                collection_error=None,  # prefer ERROR row classification in assess_finding_evidence
            )

    status = assessment.get("finding_status") or "UNVERIFIED"
    is_aa = ("access" in title_l and "analyzer" in title_l) or str(finding_id or "").upper() == "CLOUD-IAM-013"
    return {
        "version": VERSION,
        "kind": "iam",
        "status": "OK",
        "summary": {
            "users": summary_map.get("Users"),
            "AccountMFAEnabled": summary_map.get("AccountMFAEnabled"),
            "AccountAccessKeysPresent": summary_map.get("AccountAccessKeysPresent"),
            "MinimumPasswordLength": password_policy.get("MinimumPasswordLength"),
            "access_analyzer_region": region if is_aa else None,
            "active_account_analyzer_count": (aa_summary.get("active_account_analyzer_count") if is_aa else None),
            "finding_status": status,
        },
        "evidence": assessment.get("labeled_evidence") or evidence,
        "evidence_assessment": assessment,
        "scope": "regional" if is_aa else "account-wide",
        "region": region if is_aa else None,
        "potentially_affected_workloads": "MANAGER CONTEXT REQUIRED for IAM privilege reductions",
        "flags_hint": {"iam_change": True},
    }
