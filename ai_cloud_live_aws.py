# ai_cloud_live_aws.py
# Sentinel Stacks — read-only AWS inventory collectors for scan_cloud_pack.
# Builds the same fixture shape engines already consume. No mutations.

from __future__ import annotations

import csv
import io
import os
import time
from datetime import datetime, timezone
from typing import Any

DEFAULT_PROFILE = "sentinel-demo"
DEFAULT_REGION = "us-east-1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _client(session: Any, service: str, region: str | None = None):
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    return session.client(service, **kwargs)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _policy_has_admin_star(doc: dict) -> bool:
    stmts = doc.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if not isinstance(s, dict):
            continue
        if str(s.get("Effect", "")).lower() != "allow":
            continue
        actions = s.get("Action", [])
        resources = s.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _parse_credential_report(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    out: list[dict] = []
    now = datetime.now(timezone.utc)
    for row in reader:
        user = row.get("user") or ""
        if user == "<root_account>":
            continue
        age_days = None
        rotated = row.get("access_key_1_last_rotated") or "N/A"
        if rotated and rotated not in ("N/A", "not_supported"):
            try:
                # AWS format: 2024-01-15T12:00:00+00:00
                dt = datetime.fromisoformat(rotated.replace("Z", "+00:00"))
                age_days = max(0, int((now - dt.astimezone(timezone.utc)).total_seconds() // 86400))
            except Exception:
                age_days = None
        entry = {
            "user": user,
            "PasswordEnabled": row.get("password_enabled") or "false",
            "AccessKey1Active": row.get("access_key_1_active") or "false",
            "AccessKey1LastRotated": rotated if rotated != "N/A" else None,
            "MfaActive": row.get("mfa_active") or "false",
        }
        if age_days is not None:
            entry["AccessKey1AgeDays"] = age_days
        out.append(entry)
    return out


def _collect_iam(session: Any) -> dict[str, Any]:
    iam = _client(session, "iam")
    summary = _safe(lambda: iam.get_account_summary().get("SummaryMap") or {}, {})
    pw = _safe(lambda: iam.get_account_password_policy().get("PasswordPolicy") or {}, {})
    iam_account_summary = {
        "AccountMFAEnabled": int(summary.get("AccountMFAEnabled") or 0),
        "AccountAccessKeysPresent": int(summary.get("AccountAccessKeysPresent") or 0),
        "MinimumPasswordLength": int(pw.get("MinimumPasswordLength") or 0),
        "RequireUppercaseCharacters": bool(pw.get("RequireUppercaseCharacters")),
        "RequireLowercaseCharacters": bool(pw.get("RequireLowercaseCharacters")),
        "RequireNumbers": bool(pw.get("RequireNumbers")),
        "RequireSymbols": bool(pw.get("RequireSymbols")),
        "HardExpiry": bool(pw.get("HardExpiry")),
        "MaxPasswordAge": int(pw.get("MaxPasswordAge") or 0),
        "PasswordReusePrevention": int(pw.get("PasswordReusePrevention") or 0),
    }

    # Credential report (may need generate + wait)
    cred_report: list[dict] = []
    try:
        iam.generate_credential_report()
        for _ in range(12):
            resp = iam.get_credential_report()
            if resp.get("Content"):
                cred_report = _parse_credential_report(resp["Content"])
                break
            time.sleep(1.0)
    except Exception:
        # Fallback: list users + MFA + access keys (partial)
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for u in page.get("Users") or []:
                    name = u["UserName"]
                    mfa = iam.list_mfa_devices(UserName=name).get("MFADevices") or []
                    keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata") or []
                    active = [k for k in keys if k.get("Status") == "Active"]
                    age = None
                    if active and active[0].get("CreateDate"):
                        age = max(
                            0,
                            int(
                                (
                                    datetime.now(timezone.utc)
                                    - active[0]["CreateDate"].astimezone(timezone.utc)
                                ).total_seconds()
                                // 86400
                            ),
                        )
                    login = _safe(lambda n=name: iam.get_login_profile(UserName=n), None)
                    entry = {
                        "user": name,
                        "PasswordEnabled": "true" if login else "false",
                        "AccessKey1Active": "true" if active else "false",
                        "MfaActive": "true" if mfa else "false",
                    }
                    if age is not None:
                        entry["AccessKey1AgeDays"] = age
                    cred_report.append(entry)
        except Exception:
            cred_report = []

    stale = [
        {"user": u.get("user"), "age_days": u.get("AccessKey1AgeDays")}
        for u in cred_report
        if int(u.get("AccessKey1AgeDays") or 0) > 90
        and str(u.get("AccessKey1Active", "false")).lower() == "true"
    ]

    # Customer-managed policies with admin star (cap for speed)
    policies: list[dict] = []
    try:
        paginator = iam.get_paginator("list_policies")
        count = 0
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for p in page.get("Policies") or []:
                if count >= 40:
                    break
                arn = p["Arn"]
                ver = p.get("DefaultVersionId")
                doc = _safe(
                    lambda a=arn, v=ver: iam.get_policy_version(PolicyArn=a, VersionId=v)
                    .get("PolicyVersion", {})
                    .get("Document"),
                    {},
                )
                if isinstance(doc, str):
                    import json

                    doc = json.loads(doc)
                if isinstance(doc, dict) and _policy_has_admin_star(doc):
                    policies.append(
                        {
                            "name": p.get("PolicyName"),
                            "arn": arn,
                            "has_admin_star": True,
                        }
                    )
                count += 1
            if count >= 40:
                break
    except Exception:
        pass

    aa_enabled = False
    try:
        aa = _client(session, "accessanalyzer", region=session.region_name)
        analyzers = aa.list_analyzers().get("analyzers") or []
        aa_enabled = any(str(a.get("status", "")).upper() == "ACTIVE" for a in analyzers)
    except Exception:
        aa_enabled = False

    sso_enabled = False
    try:
        sso = _client(session, "sso-admin", region=session.region_name)
        instances = sso.list_instances().get("Instances") or []
        sso_enabled = len(instances) > 0
    except Exception:
        sso_enabled = False

    support_role = False
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles") or []:
                name = str(r.get("RoleName") or "")
                if "AWSSupport" in name or name.endswith("SupportRole"):
                    support_role = True
                    break
            if support_role:
                break
    except Exception:
        pass

    return {
        "iam_account_summary": iam_account_summary,
        "iam_credential_report": cred_report,
        "iam_policies": policies,
        "stale_access_keys": stale,
        "iam_access_analyzer": {"enabled": aa_enabled},
        "iam_identity_center": {"enabled": sso_enabled},
        "support_role_present": support_role,
    }


def _bucket_is_public(s3, name: str, pab: dict) -> bool:
    # Prefer public access block; fall back to ACL / policy status
    if pab and all(
        pab.get(k)
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    ):
        return False
    status = _safe(
        lambda: s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic"),
        False,
    )
    if status:
        return True
    acl = _safe(lambda: s3.get_bucket_acl(Bucket=name).get("Grants") or [], [])
    for g in acl:
        uri = ((g.get("Grantee") or {}).get("URI") or "").lower()
        if "allusers" in uri or "authenticatedusers" in uri:
            return True
    return False


def _collect_storage(session: Any, region: str) -> dict[str, Any]:
    s3 = _client(session, "s3", region)
    s3control = None
    account_pab: dict = {}
    try:
        sts = _client(session, "sts", region)
        acct = sts.get_caller_identity()["Account"]
        s3control = _client(session, "s3control", region)
        cfg = s3control.get_public_access_block(AccountId=acct).get("PublicAccessBlockConfiguration") or {}
        account_pab = {
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls")),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls")),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy")),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets")),
        }
    except Exception:
        account_pab = {}

    buckets: list[dict] = []
    for b in _safe(lambda: s3.list_buckets().get("Buckets") or [], []):
        name = b["Name"]
        loc = _safe(
            lambda n=name: (s3.get_bucket_location(Bucket=n).get("LocationConstraint") or "us-east-1"),
            region,
        )
        if loc in (None, ""):
            loc = "us-east-1"
        # Use region-specific client when needed
        bs3 = s3 if loc == region else _client(session, "s3", loc)
        bpab = _safe(
            lambda: bs3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration") or {},
            {},
        )
        enc = _safe(
            lambda: bs3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration"),
            None,
        )
        logging = _safe(lambda: bs3.get_bucket_logging(Bucket=name).get("LoggingEnabled"), None)
        ver = _safe(lambda: bs3.get_bucket_versioning(Bucket=name) or {}, {})
        buckets.append(
            {
                "name": name,
                "public_access": _bucket_is_public(bs3, name, bpab or account_pab),
                "default_encryption": bool(enc),
                "logging_enabled": bool(logging),
                "versioning": str(ver.get("Status") or "").upper() == "ENABLED",
                "mfa_delete": str(ver.get("MFADelete") or "").upper() == "ENABLED",
                "region": loc,
            }
        )

    ec2 = _client(session, "ec2", region)
    ebs_default = _safe(
        lambda: bool(ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault")),
        False,
    )
    efs = _client(session, "efs", region)
    efs_list = []
    for fs in _safe(lambda: efs.describe_file_systems().get("FileSystems") or [], []):
        efs_list.append({"id": fs.get("FileSystemId"), "encrypted": bool(fs.get("Encrypted"))})

    return {
        "s3_account_public_access_block": account_pab,
        "s3_buckets": buckets,
        "ebs_encryption_by_default": ebs_default,
        "efs_file_systems": efs_list,
    }


def _collect_network(session: Any, region: str) -> dict[str, Any]:
    ec2 = _client(session, "ec2", region)
    sgs = []
    for sg in _safe(lambda: ec2.describe_security_groups().get("SecurityGroups") or [], []):
        rules = []
        for perm in sg.get("IpPermissions") or []:
            proto = perm.get("IpProtocol", "-1")
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            for r in perm.get("IpRanges") or []:
                rules.append(
                    {
                        "protocol": proto,
                        "from_port": fp,
                        "to_port": tp,
                        "cidr": r.get("CidrIp"),
                        "description": r.get("Description"),
                    }
                )
            for r in perm.get("Ipv6Ranges") or []:
                rules.append(
                    {
                        "protocol": proto,
                        "from_port": fp,
                        "to_port": tp,
                        "cidr": r.get("CidrIpv6"),
                        "description": r.get("Description"),
                    }
                )
        sgs.append(
            {
                "id": sg.get("GroupId"),
                "name": sg.get("GroupName"),
                "vpc_id": sg.get("VpcId"),
                "inbound_rules": rules,
            }
        )

    flow_map: dict[str, bool] = {}
    for fl in _safe(lambda: ec2.describe_flow_logs().get("FlowLogs") or [], []):
        rid = fl.get("ResourceId")
        if rid:
            flow_map[rid] = True

    vpcs = []
    for v in _safe(lambda: ec2.describe_vpcs().get("Vpcs") or [], []):
        vid = v.get("VpcId")
        vpcs.append(
            {
                "id": vid,
                "cidr": (v.get("CidrBlock")),
                "flow_logs_enabled": bool(flow_map.get(vid)),
            }
        )

    subnets = []
    for s in _safe(lambda: ec2.describe_subnets().get("Subnets") or [], []):
        subnets.append(
            {
                "id": s.get("SubnetId"),
                "map_public_ip": bool(s.get("MapPublicIpOnLaunch")),
                "elb_only": False,
            }
        )

    return {
        "security_groups": sgs,
        "vpcs": vpcs,
        "subnets": subnets,
    }


def _collect_logging(session: Any, region: str) -> dict[str, Any]:
    ct = _client(session, "cloudtrail", region)
    trails_out = []
    for t in _safe(lambda: ct.describe_trails(includeShadowTrails=True).get("trailList") or [], []):
        name = t.get("Name")
        status = _safe(lambda n=name: ct.get_trail_status(Name=n), {})
        trails_out.append(
            {
                "name": name,
                "is_multi_region": bool(t.get("IsMultiRegionTrail")),
                "log_file_validation_enabled": bool(t.get("LogFileValidationEnabled")),
                "status": "LOGGING" if status.get("IsLogging") else "STOPPED",
            }
        )

    cfg = _client(session, "config", region)
    recorders = _safe(lambda: cfg.describe_configuration_recorders().get("ConfigurationRecorders") or [], [])
    statuses = _safe(
        lambda: cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus") or [],
        [],
    )
    recording = any(s.get("recording") for s in statuses) if statuses else False

    gd = _client(session, "guardduty", region)
    detectors = []
    guardduty_meta: dict[str, Any] = {"region": region}
    try:
        detector_ids = gd.list_detectors().get("DetectorIds") or []
        guardduty_meta["aws_response_classification"] = (
            "EmptyDetectorList" if not detector_ids else "DetectorList"
        )
        for did in detector_ids:
            try:
                det = gd.get_detector(DetectorId=did) or {}
                status = str(det.get("Status") or "DISABLED").upper()
                detectors.append(
                    {
                        "id": did,
                        "status": status,
                        "enabled": status == "ENABLED",
                    }
                )
            except Exception as e:
                detectors.append(
                    {
                        "id": did,
                        "status": "UNKNOWN",
                        "enabled": False,
                        "error": str(e),
                    }
                )
    except Exception as e:
        # Preserve semantic control-state exceptions (e.g. SubscriptionRequiredException)
        # instead of silently treating them as an empty detector list.
        try:
            from change_assurance.aws_response_semantics import (
                interpret_aws_exception,
                normalize_error_code,
            )

            code = normalize_error_code(e)
            semantic = interpret_aws_exception(
                service="guardduty",
                error_code=code,
                exc=e,
                region=region,
                api_call="guardduty.list_detectors",
            )
            if semantic:
                guardduty_meta.update(
                    {
                        "semantic": True,
                        "control_state": semantic.get("control_state"),
                        "aws_response_classification": code,
                        "human_observed": semantic.get("human_observed"),
                        "notes": semantic.get("notes"),
                        "DetectorIds": [],
                        "detector_count": 0,
                    }
                )
            else:
                guardduty_meta.update(
                    {
                        "error": str(e),
                        "code": code,
                        "aws_response_classification": code or type(e).__name__,
                    }
                )
        except Exception:
            guardduty_meta["error"] = str(e)
            guardduty_meta["aws_response_classification"] = type(e).__name__

    sechub_enabled = False
    try:
        sh = _client(session, "securityhub", region)
        sh.describe_hub()
        sechub_enabled = True
    except Exception:
        sechub_enabled = False

    return {
        "cloudtrail_trails": trails_out,
        "aws_config": {"recording_enabled": recording, "config_recorders": recorders},
        "guardduty_detectors": detectors,
        "guardduty": guardduty_meta,
        "security_hub": {"enabled": sechub_enabled},
    }


def _collect_compute(session: Any, region: str) -> dict[str, Any]:
    ec2 = _client(session, "ec2", region)
    instances = []
    reservations = _safe(lambda: ec2.describe_instances().get("Reservations") or [], [])
    for res in reservations:
        for inst in res.get("Instances") or []:
            state = (inst.get("State") or {}).get("Name")
            if state == "terminated":
                continue
            meta = inst.get("MetadataOptions") or {}
            vols = []
            for bdm in inst.get("BlockDeviceMappings") or []:
                ebs = bdm.get("Ebs") or {}
                vol_id = ebs.get("VolumeId")
                enc = None
                if vol_id:
                    vdesc = _safe(
                        lambda v=vol_id: ec2.describe_volumes(VolumeIds=[v])["Volumes"][0],
                        {},
                    )
                    enc = bool(vdesc.get("Encrypted")) if vdesc else None
                vols.append({"id": vol_id, "encrypted": enc})
            name = None
            for tag in inst.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name = tag.get("Value")
            instances.append(
                {
                    "id": inst.get("InstanceId"),
                    "name": name,
                    "state": state,
                    "imdsv2_required": str(meta.get("HttpTokens") or "").lower() == "required",
                    "public_ip": inst.get("PublicIpAddress"),
                    "volumes": vols,
                    "is_production": True,
                    "ebs_optimized": bool(inst.get("EbsOptimized")),
                    "detailed_monitoring": str((inst.get("Monitoring") or {}).get("State") or "").lower()
                    == "enabled",
                }
            )
    return {"ec2_instances": instances}


def _collect_database(session: Any, region: str) -> dict[str, Any]:
    rds = _client(session, "rds", region)
    rds_list = []
    for db in _safe(lambda: rds.describe_db_instances().get("DBInstances") or [], []):
        rds_list.append(
            {
                "id": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "storage_encrypted": bool(db.get("StorageEncrypted")),
                "deletion_protection": bool(db.get("DeletionProtection")),
                "publicly_accessible": bool(db.get("PubliclyAccessible")),
                "backup_retention_period": int(db.get("BackupRetentionPeriod") or 0),
                "multi_az": bool(db.get("MultiAZ")),
                "auto_minor_version_upgrade": bool(db.get("AutoMinorVersionUpgrade")),
                "iam_auth": bool(db.get("IAMDatabaseAuthenticationEnabled")),
            }
        )
    ddb = _client(session, "dynamodb", region)
    tables = []
    for name in _safe(lambda: ddb.list_tables().get("TableNames") or [], [])[:30]:
        desc = _safe(lambda n=name: ddb.describe_table(TableName=n).get("Table") or {}, {})
        sse = (desc.get("SSEDescription") or {}).get("Status") == "ENABLED"
        pitr = _safe(
            lambda n=name: bool(
                ddb.describe_continuous_backups(TableName=n)
                .get("ContinuousBackupsDescription", {})
                .get("PointInTimeRecoveryDescription", {})
                .get("PointInTimeRecoveryStatus")
                == "ENABLED"
            ),
            False,
        )
        tables.append({"name": name, "sse_enabled": sse, "point_in_time_recovery": pitr})
    return {"rds_instances": rds_list, "dynamodb_tables": tables}


def _collect_crypto(session: Any, region: str) -> dict[str, Any]:
    kms = _client(session, "kms", region)
    keys = []
    try:
        paginator = kms.get_paginator("list_keys")
        n = 0
        for page in paginator.paginate():
            for k in page.get("Keys") or []:
                if n >= 25:
                    break
                kid = k["KeyId"]
                meta = _safe(lambda i=kid: kms.describe_key(KeyId=i).get("KeyMetadata") or {}, {})
                if str(meta.get("KeyManager") or "").upper() != "CUSTOMER":
                    continue
                rot = _safe(lambda i=kid: kms.get_key_rotation_status(KeyId=i).get("KeyRotationEnabled"), False)
                keys.append(
                    {
                        "id": kid,
                        "alias": None,
                        "rotation_enabled": bool(rot),
                        "key_manager": "CUSTOMER",
                        "key_state": meta.get("KeyState"),
                    }
                )
                n += 1
            if n >= 25:
                break
    except Exception:
        pass
    return {"kms_keys": keys}


def _collect_serverless(session: Any, region: str) -> dict[str, Any]:
    lam = _client(session, "lambda", region)
    functions = []
    try:
        paginator = lam.get_paginator("list_functions")
        n = 0
        for page in paginator.paginate():
            for fn in page.get("Functions") or []:
                if n >= 40:
                    break
                name = fn.get("FunctionName")
                url_auth = None
                public_url = False
                cfg = _safe(lambda n=name: lam.get_function_url_config(FunctionName=n), None)
                if cfg:
                    url_auth = cfg.get("AuthType")
                    public_url = url_auth == "NONE"
                env = (fn.get("Environment") or {}).get("Variables") or {}
                secretish = any(
                    any(x in k.lower() for x in ("password", "secret", "api_key", "apikey", "token"))
                    for k in env
                )
                functions.append(
                    {
                        "name": name,
                        "public_url": public_url,
                        "function_url_auth": url_auth,
                        "env_has_secrets": secretish,
                        "tracing": ((fn.get("TracingConfig") or {}).get("Mode") or "PassThrough"),
                        "in_vpc": bool((fn.get("VpcConfig") or {}).get("VpcId")),
                    }
                )
                n += 1
            if n >= 40:
                break
    except Exception:
        pass
    return {"lambda_functions": functions}


def collect_aws_inventory(
    profile: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    """
    Read-only collect → fixture-shaped inventory for PackContext.
    Raises RuntimeError if boto3 missing or credentials cannot assume identity.
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as e:
        raise RuntimeError(
            "boto3 is required for live AWS collectors. Install: pip install boto3"
        ) from e

    profile = profile or os.environ.get("AWS_PROFILE") or DEFAULT_PROFILE
    region = region or os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client("sts", region_name=region)
    try:
        ident = sts.get_caller_identity()
    except (BotoCoreError, ClientError) as e:
        raise RuntimeError(
            f"AWS live collect failed with profile={profile!r} region={region!r}: {e}"
        ) from e

    account_id = ident.get("Account")
    arn = ident.get("Arn")

    aws: dict[str, Any] = {}
    errors: list[str] = []

    collectors = (
        ("iam", lambda: _collect_iam(session)),
        ("storage", lambda: _collect_storage(session, region)),
        ("network", lambda: _collect_network(session, region)),
        ("logging", lambda: _collect_logging(session, region)),
        ("compute", lambda: _collect_compute(session, region)),
        ("database", lambda: _collect_database(session, region)),
        ("crypto", lambda: _collect_crypto(session, region)),
        ("serverless", lambda: _collect_serverless(session, region)),
    )
    for name, fn in collectors:
        try:
            aws.update(fn())
        except Exception as e:
            errors.append(f"{name}: {e}")

    # Public exposure drift signals from collected inventory
    unexpected = []
    for b in aws.get("s3_buckets") or []:
        if b.get("public_access"):
            unexpected.append(
                {"id": f"s3://{b.get('name')}", "severity": "critical", "reason": "public_s3"}
            )
    for sg in aws.get("security_groups") or []:
        for rule in sg.get("inbound_rules") or []:
            if rule.get("cidr") in {"0.0.0.0/0", "::/0"} and rule.get("from_port") in {
                22,
                3389,
                3306,
                5432,
            }:
                unexpected.append(
                    {
                        "id": sg.get("id"),
                        "severity": "critical",
                        "reason": f"open_{rule.get('from_port')}",
                    }
                )
    aws["unexpected_public_resources"] = unexpected

    fixture = {
        "_cloud_fixture": True,
        "_profile": "live-aws",
        "_schema_version": "1.0",
        "_collected_at": _now(),
        "_aws_profile": profile,
        "_region": region,
        "_collector_errors": errors,
        "account": {
            "name": f"aws-{account_id}",
            "id": account_id,
            "arn": arn,
            "providers": ["aws"],
        },
        "baseline": {
            "require_guardduty": True,
            "require_multi_region_cloudtrail": True,
        },
        "aws": aws,
    }
    return fixture


def aws_live_ready(profile: str | None = None) -> bool:
    """True if boto3 is importable and STS works for the profile."""
    try:
        import boto3
    except ImportError:
        return False
    profile = profile or os.environ.get("AWS_PROFILE") or DEFAULT_PROFILE
    region = os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        session.client("sts").get_caller_identity()
        return True
    except Exception:
        return False
