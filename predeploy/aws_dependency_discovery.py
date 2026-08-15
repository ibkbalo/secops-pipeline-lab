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
) -> dict[str, Any]:
    return {
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
    titles = " ".join(str(f.get("title") or "") for f in (findings or [])).lower()
    joined = " ".join(ids).upper() + " " + titles

    if any(x.startswith("CLOUD-STO") for x in ids) or "public access block" in titles or "s3" in joined.lower():
        return discover_s3_account_bpa(profile=profile, region=region, finding_id=ids[0] if ids else "CLOUD-STO-001")
    if any(x.startswith("CLOUD-LOG") for x in ids) or "cloudtrail" in titles:
        return discover_cloudtrail(profile=profile, region=region, finding_id=next((i for i in ids if i.startswith("CLOUD-LOG")), ids[0] if ids else "CLOUD-LOG-001"))
    if any(x.startswith("CLOUD-NET") for x in ids) or "security group" in titles:
        return discover_security_groups(profile=profile, region=region, finding_id=ids[0] if ids else "CLOUD-NET-001")
    if any(x.startswith("CLOUD-IAM") for x in ids) or "iam" in titles:
        return discover_iam_light(profile=profile, region=region, finding_id=ids[0] if ids else "CLOUD-IAM-001")

    return {
        "version": VERSION,
        "profile": profile,
        "region": region,
        "kind": "generic",
        "status": "SKIP",
        "summary": {},
        "evidence": [],
        "notes": ["No specialized discovery mapper for these finding IDs — manager context may be required."],
    }


def discover_s3_account_bpa(
    *,
    profile: str,
    region: str,
    finding_id: str = "CLOUD-STO-001",
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
        summary["finding_status"] = "ALREADY_REMEDIATED" if all_on else "CONFIRMED"
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
                )
            )

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
            "evidence": evidence,
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


def discover_cloudtrail(*, profile: str, region: str, finding_id: str) -> dict[str, Any]:
    evidence: list[dict] = []
    summary = {"trail_count": 0, "multi_region": False, "finding_status": "UNKNOWN"}
    try:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList") or []
        summary["trail_count"] = len(trails)
        summary["multi_region"] = any(t.get("IsMultiRegionTrail") for t in trails)
        summary["finding_status"] = "ALREADY_REMEDIATED" if trails else "CONFIRMED"
        account = session.client("sts").get_caller_identity().get("Account")
        evidence.append(
            _evidence(
                finding_id=finding_id,
                api_call="cloudtrail.describe_trails",
                resource_id=account,
                resource_type="aws_cloudtrail",
                observed_value={
                    "trails": [
                        {
                            "name": t.get("Name"),
                            "multi": t.get("IsMultiRegionTrail"),
                            "bucket": t.get("S3BucketName"),
                        }
                        for t in trails
                    ]
                },
                expected_value={"trail_count_gt": 0},
                account_id=account,
                region=region,
            )
        )
        return {
            "version": VERSION,
            "kind": "cloudtrail",
            "status": "OK",
            "profile": profile,
            "region": region,
            "account_id": account,
            "summary": summary,
            "evidence": evidence,
            "scope": "account-wide",
            "potentially_affected_workloads": "None detected (logging control)",
        }
    except Exception as e:
        return {
            "version": VERSION,
            "kind": "cloudtrail",
            "status": "FAIL",
            "error": str(e),
            "summary": summary,
            "evidence": evidence,
        }


def discover_security_groups(*, profile: str, region: str, finding_id: str) -> dict[str, Any]:
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
        return {
            "version": VERSION,
            "kind": "security_groups",
            "status": "OK",
            "summary": {
                "sg_count": len(sgs),
                "open_world_rules": len(open_world),
                "finding_status": "CONFIRMED" if open_world else "ALREADY_REMEDIATED",
            },
            "open_world_rules": open_world[:30],
            "evidence": [
                _evidence(
                    finding_id=finding_id,
                    api_call="ec2.describe_security_groups",
                    resource_id="account",
                    resource_type="aws_security_group",
                    observed_value={"open_world_count": len(open_world)},
                    region=region,
                )
            ],
            "scope": "regional",
            "potentially_affected_workloads": (
                "MANAGER CONTEXT REQUIRED — open ingress may be intentional for edge services"
                if open_world
                else "None detected"
            ),
            "flags_hint": {"networking_change": True, "public_workload_dependency": bool(open_world)},
        }
    except Exception as e:
        return {"version": VERSION, "kind": "security_groups", "status": "FAIL", "error": str(e), "summary": {}, "evidence": []}


def discover_iam_light(*, profile: str, region: str, finding_id: str) -> dict[str, Any]:
    try:
        import boto3

        session = boto3.Session(profile_name=profile, region_name=region)
        iam = session.client("iam")
        summary_map = iam.get_account_summary().get("SummaryMap") or {}
        return {
            "version": VERSION,
            "kind": "iam",
            "status": "OK",
            "summary": {
                "users": summary_map.get("Users"),
                "AccountMFAEnabled": summary_map.get("AccountMFAEnabled"),
                "finding_status": "CONFIRMED",
            },
            "evidence": [
                _evidence(
                    finding_id=finding_id,
                    api_call="iam.get_account_summary",
                    resource_id="account",
                    resource_type="aws_iam_account",
                    observed_value=dict(list(summary_map.items())[:20]),
                    region=region,
                )
            ],
            "scope": "account-wide",
            "potentially_affected_workloads": "MANAGER CONTEXT REQUIRED for IAM privilege reductions",
            "flags_hint": {"iam_change": True},
        }
    except Exception as e:
        return {"version": VERSION, "kind": "iam", "status": "FAIL", "error": str(e), "summary": {}, "evidence": []}
