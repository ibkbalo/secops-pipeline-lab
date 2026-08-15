# ai_cloud_pack.py
# Sentinel Stacks — Cloud Security Engineer Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase C1: full enterprise multi-engine cloud pack — AWS + Azure.
# 12 engines cover cloud security engineer scope at enterprise scale
# (no 18-check ceiling). Deterministic embedded fixtures + legacy AWS/Azure
# mock reuse. Live AWS collectors via ai_cloud_live_aws (boto3, read-only).
#
# Engines: iam, storage, network, logging, crypto, compute, database,
#          containers, serverless, identity, compliance, drift
# ID scheme: CLOUD-{ENGINE_CODE}-{NNN}

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import datetime
from pathlib import Path
from typing import Any, Callable

TOOL_ID = "scan_cloud_pack"
VERSION = "0.3.0-c3"
DOMAIN = "infrastructure"
SUBDOMAIN = "infrastructure/cloud"
SENTINEL = "infrastructure"
TIER = 1
TAGS = [
    "cloud",
    "multi-engine",
    "aws",
    "azure",
    "iam",
    "cis",
    "enterprise",
    "cloud-security-engineer",
    "c1",
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

ENGINE_CODES = {
    "iam": "IAM",
    "storage": "STO",
    "network": "NET",
    "logging": "LOG",
    "crypto": "CRY",
    "compute": "CMP",
    "database": "DB",
    "containers": "CTR",
    "serverless": "SLS",
    "identity": "ID",
    "compliance": "CML",
    "drift": "DFT",
}

PACK_PHASE = "C1"
PACK_LABEL = "enterprise_cloud_pack_all_engines_active"


def _ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _which(name: str) -> str | None:
    return shutil.which(name)


def _tool_version(cmd: list[str]) -> str | None:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        return out[0][:200] if out else "present"
    except Exception:
        return None


def detect_backends() -> dict[str, dict[str, Any]]:
    """Optional live CLIs. Embedded fixtures always work offline."""
    backends: dict[str, dict[str, Any]] = {}
    for name, eng, ver_args in (
        ("aws", ["iam", "storage", "network", "logging", "crypto", "compute", "database", "containers", "serverless"], ["--version"]),
        ("az", ["identity", "storage", "network", "logging", "crypto", "compute", "database", "containers"], ["version"]),
        ("prowler", ["compliance", "iam", "storage", "network"], ["--version"]),
        ("scout", ["iam", "storage", "network"], ["--version"]),
    ):
        p = _which(name)
        backends[name] = {
            "available": bool(p),
            "path": p,
            "version": _tool_version([p, *ver_args]) if p else None,
            "engines": eng,
        }
    backends["embedded"] = {
        "available": True,
        "path": None,
        "version": VERSION,
        "engines": list(ENGINE_CODES.keys()),
    }
    return backends


class PackContext:
    def __init__(
        self,
        target: str,
        fixture: dict | None,
        mode: str,
        backends: dict,
        engines_filter: list[str] | None,
    ):
        self.target = target
        self.fixture = fixture or {}
        self.mode = mode
        self.backends = backends
        self.engines_filter = engines_filter
        self._counters: dict[str, int] = {k: 0 for k in ENGINE_CODES}
        # Unified provider views
        self.aws: dict[str, Any] = {}
        self.azure: dict[str, Any] = {}
        self._bind_providers()

    def _bind_providers(self) -> None:
        fx = self.fixture or {}
        if isinstance(fx.get("aws"), dict):
            self.aws = fx["aws"]
        elif any(k.startswith("iam_") or k in ("s3_buckets", "vpcs", "kms_keys", "rds_instances") for k in fx):
            # Legacy mock_aws_*.json shape at root
            skip = {"_description", "_account_id", "_region", "_profile", "_cloud_fixture",
                    "_schema_version", "aws", "azure", "engines", "account", "baseline", "drift"}
            self.aws = {k: v for k, v in fx.items() if k not in skip and not k.startswith("_")}
        if isinstance(fx.get("azure"), dict):
            self.azure = fx["azure"]
        elif any(k.startswith("entra_") or k in ("storage_accounts", "nsg_rules", "key_vaults") for k in fx):
            skip = {"_description", "_subscription_id", "_tenant_id", "_region", "_profile",
                    "_cloud_fixture", "_schema_version", "aws", "azure", "engines", "account",
                    "baseline", "drift"}
            # Prefer azure key if already set above from nested form
            if not self.azure:
                self.azure = {k: v for k, v in fx.items() if k not in skip and not k.startswith("_")
                              and k not in self.aws}

    def aws_has(self) -> bool:
        return bool(self.aws)

    def az_has(self) -> bool:
        return bool(self.azure)

    def section(self, key: str) -> dict:
        eng = (self.fixture or {}).get("engines") or {}
        sec = eng.get(key)
        if isinstance(sec, dict):
            return sec
        top = (self.fixture or {}).get(key)
        return top if isinstance(top, dict) else {}

    def next_id(self, engine_key: str) -> str:
        code = ENGINE_CODES[engine_key]
        self._counters[engine_key] = self._counters.get(engine_key, 0) + 1
        return f"CLOUD-{code}-{self._counters[engine_key]:03d}"

    def account_label(self) -> str:
        acc = (self.fixture or {}).get("account") or {}
        if isinstance(acc, dict):
            return str(acc.get("name") or acc.get("id") or self.target)
        return str(self.aws.get("_account_id") or self.azure.get("_subscription_id") or self.target)


def _finding(
    fid: str,
    title: str,
    severity: str,
    description: str,
    *,
    resource: dict | None = None,
    evidence: dict | None = None,
    remediation: dict | None = None,
    compliance: list | None = None,
    engine: str = "",
    provider: str = "",
    backend: str = "embedded",
) -> dict:
    ev = dict(evidence or {})
    ev.setdefault("engine", engine)
    ev.setdefault("provider", provider)
    ev.setdefault("backend", backend)
    ev.setdefault("check_id", fid)
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": "high",
        "description": description,
        "resource": resource
        or {"type": "cloud_account", "id": provider or "multi-cloud", "provider": provider},
        "evidence": ev,
        "remediation": remediation
        or {
            "steps": [
                f"Remediate {fid}: {title}",
                "Apply least-privilege / CIS harden guidance for the resource.",
                "Re-run scan_cloud_pack to verify the control passes.",
            ],
            "effort": "medium",
        },
        "compliance": compliance
        or [
            "CIS Cloud Foundations",
            "NIST 800-53 AC-3",
            "SOC 2 CC6.1",
            "ISO 27001 A.9.4.1",
        ],
    }


def _fail(
    ctx: PackContext,
    findings: list,
    engine: str,
    provider: str,
    ok: bool,
    title: str,
    sev: str,
    desc: str,
    *,
    resource: dict | None = None,
    evidence: dict | None = None,
    remediation: dict | None = None,
    compliance: list | None = None,
) -> None:
    if ok:
        return
    findings.append(
        _finding(
            ctx.next_id(engine),
            title,
            sev,
            desc,
            resource=resource,
            evidence=evidence,
            remediation=remediation,
            compliance=compliance,
            engine=engine,
            provider=provider,
        )
    )


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "enabled", "on"}
    return bool(v)


def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ═══════════════════════ Engines ═══════════════════════════════════════════════


def _engine_iam(ctx: PackContext) -> list[dict]:
    """IAM / RBAC — root guards, password policy, admin star, role hygiene."""
    f: list[dict] = []
    eng = "iam"

    if ctx.aws_has():
        d = ctx.aws
        summ = d.get("iam_account_summary") or {}
        _fail(ctx, f, eng, "aws", int(summ.get("AccountMFAEnabled") or 0) == 1,
              "AWS root account MFA enabled", "critical",
              "Root MFA is disabled. Compromised root password yields full account takeover.",
              evidence={"source": "iam_account_summary", "AccountMFAEnabled": summ.get("AccountMFAEnabled")},
              compliance=["CIS AWS 1.5", "NIST 800-53 IA-2", "SOC 2 CC6.1"])
        _fail(ctx, f, eng, "aws", int(summ.get("MinimumPasswordLength") or 0) >= 14,
              "AWS IAM password policy minimum length >= 14", "high",
              "Password minimum length is below the CIS 14-character floor.",
              evidence={"MinimumPasswordLength": summ.get("MinimumPasswordLength")})
        _fail(ctx, f, eng, "aws",
              _truthy(summ.get("RequireUppercaseCharacters")) and _truthy(summ.get("RequireSymbols")),
              "AWS IAM password complexity (uppercase + symbols)", "high",
              "Password policy does not require both uppercase characters and symbols.")
        _fail(ctx, f, eng, "aws",
              _truthy(summ.get("RequireLowercaseCharacters")) and _truthy(summ.get("RequireNumbers")),
              "AWS IAM password complexity (lowercase + numbers)", "medium",
              "Password policy missing lowercase and/or numeric requirements.")
        max_age = int(summ.get("MaxPasswordAge") or 0)
        _fail(ctx, f, eng, "aws", max_age > 0 and max_age <= 90,
              "AWS IAM password max age <= 90 days", "medium",
              f"MaxPasswordAge={max_age or 'unset'}; passwords should expire within 90 days.")
        reuse = int(summ.get("PasswordReusePrevention") or 0)
        _fail(ctx, f, eng, "aws", reuse >= 24,
              "AWS IAM password reuse prevention >= 24", "low",
              f"PasswordReusePrevention={reuse}; CIS expects 24 prior passwords blocked.")
        root_keys = int(summ.get("AccountAccessKeysPresent") or d.get("root_access_keys_active") or 0)
        _fail(ctx, f, eng, "aws", root_keys == 0,
              "AWS root account has no active access keys", "critical",
              "Root access keys exist. Never issue access keys for the root user.",
              evidence={"AccountAccessKeysPresent": root_keys})

        cred = _as_list(d.get("iam_credential_report"))
        both = [u for u in cred
                if str(u.get("AccessKey1Active", "false")).lower() == "true"
                and str(u.get("PasswordEnabled", "false")).lower() == "true"]
        _fail(ctx, f, eng, "aws", len(both) == 0,
              "No IAM users with both console password and active access keys", "high",
              f"{len(both)} user(s) hold console + access keys (human dual credential risk).",
              evidence={"users": [u.get("user") for u in both][:10]})
        no_mfa = [u for u in cred
                  if str(u.get("PasswordEnabled", "false")).lower() == "true"
                  and str(u.get("MfaActive", "false")).lower() != "true"]
        _fail(ctx, f, eng, "aws", len(no_mfa) == 0,
              "All console IAM users have MFA", "critical",
              f"{len(no_mfa)} console user(s) lack MFA.",
              evidence={"users": [u.get("user") for u in no_mfa][:10]})
        stale = _as_list(d.get("stale_access_keys") or d.get("iam_stale_keys"))
        # Also derive from credential report dates if provided as age_days
        for u in cred:
            for k in ("AccessKey1AgeDays", "access_key_1_age_days"):
                if int(u.get(k) or 0) > 90:
                    stale.append({"user": u.get("user"), "age_days": u.get(k)})
        _fail(ctx, f, eng, "aws", len(stale) == 0,
              "No IAM access keys older than 90 days", "high",
              f"{len(stale)} access key(s) exceed 90-day rotation.",
              evidence={"keys": stale[:10]})

        pols = _as_list(d.get("iam_policies"))
        wild = [p for p in pols if p.get("has_admin_star") or (
            p.get("Action") == "*" and p.get("Resource") == "*")]
        _fail(ctx, f, eng, "aws", len(wild) == 0,
              "No IAM policies with Action:* Resource:*", "critical",
              f"{len(wild)} customer-managed policy(ies) grant full admin star.",
              evidence={"policies": [p.get("name") or p.get("arn") for p in wild][:10]})
        inline_admin = [p for p in pols if p.get("inline_admin") or p.get("attached_to_user")]
        # only flag if explicit inline_admin marker
        flagged_inline = [p for p in pols if p.get("inline_admin")]
        _fail(ctx, f, eng, "aws", len(flagged_inline) == 0,
              "No inline admin policies on IAM users", "high",
              f"{len(flagged_inline)} user inline admin policy(ies) should move to groups/roles.")

        aa = d.get("iam_access_analyzer") or {}
        _fail(ctx, f, eng, "aws", _truthy(aa.get("enabled")),
              "IAM Access Analyzer enabled", "high",
              "Access Analyzer is off — external share paths are not continuously evaluated.")
        sso = d.get("iam_identity_center") or d.get("sso") or {}
        _fail(ctx, f, eng, "aws",
              _truthy(sso.get("enabled")) or _truthy(d.get("identity_center_enabled")),
              "IAM Identity Center (SSO) preferred over long-lived IAM users", "medium",
              "Workforce access still centers on long-lived IAM users without Identity Center.")
        support = d.get("iam_support_role") or d.get("support_role") or {}
        _fail(ctx, f, eng, "aws",
              _truthy(support.get("exists")) if support else _truthy(d.get("support_role_present")),
              "AWS Support IAM role present for incident response", "low",
              "No dedicated support/break-glass role evidenced for premium support cases.")

    if ctx.az_has():
        d = ctx.azure
        # Azure RBAC / subscription IAM (identity engine owns Entra MFA etc.)
        role_assign = _as_list(d.get("role_assignments") or (d.get("rbac") or {}).get("assignments"))
        owner_wild = [r for r in role_assign if str(r.get("role") or "").lower() in
                      {"owner", "user access administrator"} and str(r.get("scope") or "").endswith("/")]
        # if fixture has explicit overprivileged_role_assignments
        over = _as_list(d.get("overprivileged_role_assignments") or owner_wild)
        _fail(ctx, f, eng, "azure", len(over) == 0,
              "No standing Owner on subscription root scope", "critical",
              f"{len(over)} Owner/User Access Admin assignment(s) at subscription root.",
              evidence={"assignments": over[:10]})
        custom = _as_list(d.get("custom_roles_with_wildcard") or (d.get("rbac") or {}).get("wildcard_custom_roles"))
        _fail(ctx, f, eng, "azure", len(custom) == 0,
              "No custom roles with Actions:*", "high",
              f"{len(custom)} custom role(s) grant wildcard actions.")
        sp_owners = _as_list(d.get("service_principals_with_owner") or [])
        _fail(ctx, f, eng, "azure", len(sp_owners) == 0,
              "No service principals with permanent Owner role", "high",
              f"{len(sp_owners)} service principal(s) hold permanent Owner.")
        mfa_admins = d.get("admin_mfa_enforced")
        if mfa_admins is None:
            mfa_admins = (d.get("rbac") or {}).get("admin_mfa_enforced")
        # default fail if missing — enterprise expects evidence
        _fail(ctx, f, eng, "azure", _truthy(mfa_admins) if mfa_admins is not None else False,
              "Azure privileged role MFA enforced", "critical",
              "No evidence that MFA is enforced for privileged Azure RBAC roles.")

    return f


def _engine_storage(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "storage"
    if ctx.aws_has():
        d = ctx.aws
        pab = d.get("s3_account_public_access_block") or {}
        all_block = all(_truthy(pab.get(k)) for k in
                        ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        _fail(ctx, f, eng, "aws", all_block and bool(pab),
              "S3 account public access block fully enabled", "critical",
              "Account-level S3 public access block is incomplete — buckets can be exposed.",
              evidence={"public_access_block": pab})
        for b in _as_list(d.get("s3_buckets")):
            name = b.get("name") or "unknown"
            _fail(ctx, f, eng, "aws", not _truthy(b.get("public_access")),
                  f"S3 bucket not public: {name}", "critical",
                  f"Bucket '{name}' allows public access.",
                  resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"},
                  evidence={"bucket": b})
            _fail(ctx, f, eng, "aws", _truthy(b.get("default_encryption")),
                  f"S3 default encryption: {name}", "high",
                  f"Bucket '{name}' lacks default encryption.",
                  resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"})
            _fail(ctx, f, eng, "aws", _truthy(b.get("logging_enabled")),
                  f"S3 access logging: {name}", "medium",
                  f"Bucket '{name}' has access logging disabled.",
                  resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"})
            if "versioning" in b:
                _fail(ctx, f, eng, "aws", _truthy(b.get("versioning")),
                      f"S3 versioning: {name}", "medium",
                      f"Bucket '{name}' versioning is off.",
                      resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"})
            if "mfa_delete" in b:
                _fail(ctx, f, eng, "aws", _truthy(b.get("mfa_delete")),
                      f"S3 MFA delete: {name}", "low",
                      f"Bucket '{name}' MFA Delete is not enabled.",
                      resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"})
            if "object_lock" in b:
                _fail(ctx, f, eng, "aws", _truthy(b.get("object_lock")),
                      f"S3 object lock (compliance data): {name}", "medium",
                      f"Sensitive bucket '{name}' lacks Object Lock.",
                      resource={"type": "aws_s3_bucket", "id": name, "provider": "aws"})
        ebs = d.get("ebs_encryption_by_default")
        _fail(ctx, f, eng, "aws", _truthy(ebs),
              "EBS encryption by default enabled", "high",
              "Account EBS encryption-by-default is disabled.")
        efs = _as_list(d.get("efs_file_systems") or [])
        open_efs = [e for e in efs if not _truthy(e.get("encrypted"))]
        _fail(ctx, f, eng, "aws", len(open_efs) == 0,
              "EFS file systems encrypted", "high",
              f"{len(open_efs)} EFS filesystem(s) unencrypted.")

    if ctx.az_has():
        d = ctx.azure
        for sa in _as_list(d.get("storage_accounts")):
            name = sa.get("name") or "unknown"
            _fail(ctx, f, eng, "azure", _truthy(sa.get("secure_transfer_required")),
                  f"Storage secure transfer (HTTPS) required: {name}", "high",
                  f"Storage account '{name}' allows non-HTTPS traffic.",
                  resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
            _fail(ctx, f, eng, "azure", not _truthy(sa.get("allow_blob_public_access")),
                  f"Storage blob public access disabled: {name}", "critical",
                  f"Storage account '{name}' allows blob public access.",
                  resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
            key_src = str(sa.get("encryption_key_source") or sa.get("encryption") or "").lower()
            enc_ok = key_src in {"microsoft.storage", "microsoft.keyvault", "keyvault", "microsoft_managed", "cmk", "mmk"} or _truthy(sa.get("encryption_enabled", True))
            if "encryption_key_source" in sa or "encryption_enabled" in sa:
                _fail(ctx, f, eng, "azure", enc_ok and key_src not in {"", "none", "false"},
                      f"Storage encryption configured: {name}", "high",
                      f"Storage account '{name}' encryption source is weak/unset ({key_src or 'none'}).",
                      resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
            if "shared_key_access" in sa:
                _fail(ctx, f, eng, "azure", not _truthy(sa.get("shared_key_access")),
                      f"Storage shared key access disabled: {name}", "medium",
                      f"Storage account '{name}' still allows shared key auth (prefer Entra ID).",
                      resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
            if "minimum_tls_version" in sa:
                tls = str(sa.get("minimum_tls_version") or "")
                _fail(ctx, f, eng, "azure", tls in {"TLS1_2", "TLS1_3", "1.2", "1.3"},
                      f"Storage minimum TLS 1.2+: {name}", "medium",
                      f"Storage account '{name}' minimum TLS is {tls or 'unset'}.",
                      resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
            if "network_default_action" in sa or "network_acls" in sa:
                acl = sa.get("network_acls") or {}
                default = str(sa.get("network_default_action") or acl.get("default_action") or "").lower()
                _fail(ctx, f, eng, "azure", default == "deny",
                      f"Storage network default deny: {name}", "high",
                      f"Storage account '{name}' network default_action is not Deny.",
                      resource={"type": "azure_storage_account", "id": name, "provider": "azure"})
    return f


def _engine_network(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "network"
    dangerous_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 11211}

    if ctx.aws_has():
        d = ctx.aws
        for sg in _as_list(d.get("security_groups")):
            sid = sg.get("id") or sg.get("name") or "sg"
            for rule in _as_list(sg.get("inbound_rules") or sg.get("ip_permissions")):
                cidr = str(rule.get("cidr") or rule.get("cidr_ip") or rule.get("source") or "")
                open_world = cidr in {"0.0.0.0/0", "::/0", "*", "any", "internet"}
                proto = str(rule.get("protocol") or "").lower()
                fp = rule.get("from_port", rule.get("FromPort"))
                tp = rule.get("to_port", rule.get("ToPort"))
                try:
                    ports = set(range(int(fp), int(tp) + 1)) if fp is not None and tp is not None else set()
                except Exception:
                    ports = set()
                if open_world and (proto in {"-1", "all"} or not ports or ports & dangerous_ports or 0 in ports):
                    _fail(ctx, f, eng, "aws", False,
                          f"Security group open management/DB port to world: {sid}",
                          "critical",
                          f"SG '{sid}' allows {proto}/{fp}-{tp} from {cidr}.",
                          resource={"type": "aws_security_group", "id": sid, "provider": "aws"},
                          evidence={"rule": rule})
                elif open_world and ports and not (ports <= {80, 443}):
                    _fail(ctx, f, eng, "aws", False,
                          f"Security group broad ingress from world: {sid}",
                          "high",
                          f"SG '{sid}' allows non-web ports {sorted(ports)[:8]} from {cidr}.",
                          resource={"type": "aws_security_group", "id": sid, "provider": "aws"},
                          evidence={"rule": rule})
        for vpc in _as_list(d.get("vpcs")):
            vid = vpc.get("id") or "vpc"
            _fail(ctx, f, eng, "aws", _truthy(vpc.get("flow_logs_enabled")),
                  f"VPC flow logs enabled: {vid}", "high",
                  f"VPC '{vid}' has flow logs disabled.",
                  resource={"type": "aws_vpc", "id": vid, "provider": "aws"})
        nacl_open = _as_list(d.get("network_acls_open") or d.get("public_nacls"))
        _fail(ctx, f, eng, "aws", len(nacl_open) == 0,
              "No NACLs allowing all inbound from 0.0.0.0/0", "medium",
              f"{len(nacl_open)} NACL(s) are overly permissive.")
        igw_default = d.get("default_sg_restrictive")
        if igw_default is not None:
            _fail(ctx, f, eng, "aws", _truthy(igw_default),
                  "Default security group restricts all traffic", "medium",
                  "Default security group is not locked down.")
        # public subnets without purpose
        pub_sub = [s for s in _as_list(d.get("subnets")) if _truthy(s.get("map_public_ip")) and not s.get("elb_only")]
        if d.get("subnets") is not None:
            _fail(ctx, f, eng, "aws", len(pub_sub) == 0,
                  "No unexpected public subnets auto-assigning public IPs", "medium",
                  f"{len(pub_sub)} subnet(s) auto-assign public IPs outside edge tiers.")

    if ctx.az_has():
        d = ctx.azure
        for rule in _as_list(d.get("nsg_rules")):
            src = str(rule.get("source") or rule.get("source_address_prefix") or "").lower()
            open_world = src in {"internet", "*", "0.0.0.0/0", "any", "0.0.0.0", "::/0"}
            port = str(rule.get("destination_port") or rule.get("destination_port_range") or "")
            direction = str(rule.get("direction") or "Inbound").lower()
            access = str(rule.get("access") or "Allow").lower()
            if direction == "inbound" and access != "deny" and open_world:
                risky = False
                try:
                    if port in {"*", "0-65535"}:
                        risky = True
                    elif "-" in port:
                        a, b = port.split("-", 1)
                        risky = any(p in range(int(a), int(b) + 1) for p in dangerous_ports)
                    else:
                        risky = int(port) in dangerous_ports or int(port) not in (80, 443)
                except Exception:
                    risky = port not in {"80", "443"}
                if risky:
                    _fail(ctx, f, eng, "azure", False,
                          f"NSG allows management/DB from Internet: {rule.get('name')}",
                          "critical",
                          f"NSG rule '{rule.get('name')}' permits {port} from {src}.",
                          resource={"type": "azure_nsg_rule", "id": rule.get("name"), "provider": "azure"},
                          evidence={"rule": rule})
        for pep in _as_list(d.get("public_endpoints") or []):
            _fail(ctx, f, eng, "azure", False,
                  f"Resource has unexpected public endpoint: {pep.get('name') or pep}",
                  "high",
                  "Public network endpoint should be private-link only for this class.",
                  evidence={"endpoint": pep})
        # DDoS standard
        ddos = d.get("ddos_protection") or {}
        if d.get("ddos_protection") is not None:
            _fail(ctx, f, eng, "azure", _truthy(ddos.get("standard_enabled") or ddos.get("enabled")),
                  "Azure DDoS Protection Standard enabled on hub", "low",
                  "DDoS Protection Standard is not enabled.")
    return f


def _engine_logging(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "logging"
    if ctx.aws_has():
        d = ctx.aws
        trails = _as_list(d.get("cloudtrail_trails"))
        _fail(ctx, f, eng, "aws", len(trails) > 0,
              "CloudTrail trail exists", "critical",
              "No CloudTrail trails configured — API activity is not recorded.")
        multi = any(_truthy(t.get("is_multi_region")) for t in trails)
        _fail(ctx, f, eng, "aws", multi,
              "CloudTrail multi-region trail enabled", "high",
              "No multi-region CloudTrail trail — events outside home region may be missed.")
        valid = all(_truthy(t.get("log_file_validation_enabled")) for t in trails) if trails else False
        _fail(ctx, f, eng, "aws", valid,
              "CloudTrail log file validation enabled", "medium",
              "CloudTrail log file validation is off — integrity of logs is weaker.")
        cfg = d.get("aws_config") or {}
        _fail(ctx, f, eng, "aws", _truthy(cfg.get("recording_enabled")),
              "AWS Config recorder enabled", "high",
              "AWS Config is not recording resource configuration history.")
        gd = _as_list(d.get("guardduty_detectors"))
        gd_on = any(str(g.get("status") or "").upper() == "ENABLED" or _truthy(g.get("enabled")) for g in gd)
        _fail(ctx, f, eng, "aws", gd_on,
              "GuardDuty detector enabled", "high",
              "GuardDuty is not enabled — threat detection for the account is blind.")
        sechub = d.get("security_hub") or {}
        if d.get("security_hub") is not None:
            _fail(ctx, f, eng, "aws", _truthy(sechub.get("enabled")),
                  "AWS Security Hub enabled", "medium",
                  "Security Hub is disabled — findings are not centralized.")
        cw = d.get("cloudwatch_log_metric_filters") or d.get("cloudwatch_alarms_cis") or {}
        if isinstance(cw, dict) and cw:
            _fail(ctx, f, eng, "aws", _truthy(cw.get("cis_alarms_enabled") or cw.get("enabled")),
                  "CIS CloudWatch metric filters/alarms present", "medium",
                  "CIS metric filter alarms for root usage / unauthorized API are missing.")
        elif isinstance(cw, list):
            _fail(ctx, f, eng, "aws", len(cw) > 0,
                  "CIS CloudWatch metric filters/alarms present", "medium",
                  "No CIS CloudWatch metric filters configured.")

    if ctx.az_has():
        d = ctx.azure
        ale = d.get("activity_log_export") or {}
        _fail(ctx, f, eng, "azure",
              _truthy(ale.get("export_to_log_analytics")) or _truthy(ale.get("export_to_event_hub")),
              "Azure activity log exported to Log Analytics or Event Hub", "high",
              "Activity logs are not exported — investigation of control-plane changes is impaired.")
        law = d.get("log_analytics_workspace") or {}
        ret = int(law.get("retention_days") or 0)
        _fail(ctx, f, eng, "azure", ret >= 365,
              "Log Analytics retention >= 365 days", "medium",
              f"Log Analytics retention is {ret} days (enterprise target >= 365).")
        dfc = d.get("defender_for_cloud") or {}
        tier = str(dfc.get("tier") or "").lower()
        plans = dfc.get("plans") or {}
        def_on = tier in {"standard", "p2", "enabled"} or any(
            str(v).lower() in {"on", "standard", "enabled", "true"} for v in (plans.values() if isinstance(plans, dict) else []))
        _fail(ctx, f, eng, "azure", def_on,
              "Microsoft Defender for Cloud standard plans enabled", "high",
              "Defender for Cloud is Free/partial — key resource plans are not Standard.")
        # diagnostic settings
        diag_missing = _as_list(d.get("resources_missing_diagnostics") or [])
        _fail(ctx, f, eng, "azure", len(diag_missing) == 0,
              "Critical resources have diagnostic settings", "medium",
              f"{len(diag_missing)} resource(s) lack diagnostic settings to Log Analytics.",
              evidence={"resources": diag_missing[:10]})
    return f


def _engine_crypto(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "crypto"
    if ctx.aws_has():
        d = ctx.aws
        for k in _as_list(d.get("kms_keys")):
            kid = k.get("id") or k.get("alias") or "key"
            if str(k.get("key_manager") or "CUSTOMER").upper() == "CUSTOMER":
                _fail(ctx, f, eng, "aws", _truthy(k.get("rotation_enabled")),
                      f"KMS CMK rotation enabled: {kid}", "high",
                      f"Customer-managed key '{kid}' does not have annual rotation enabled.",
                      resource={"type": "aws_kms_key", "id": kid, "provider": "aws"},
                      evidence={"key": k})
            if "key_state" in k:
                _fail(ctx, f, eng, "aws", str(k.get("key_state")).upper() in {"ENABLED", "ACTIVE"},
                      f"KMS key usable state: {kid}", "medium",
                      f"KMS key '{kid}' state is {k.get('key_state')}.",
                      resource={"type": "aws_kms_key", "id": kid, "provider": "aws"})
            if k.get("policy_allows_world"):
                _fail(ctx, f, eng, "aws", False,
                      f"KMS key policy not world-principal: {kid}", "critical",
                      f"KMS key '{kid}' policy allows broad principals.",
                      resource={"type": "aws_kms_key", "id": kid, "provider": "aws"})
        secrets = _as_list(d.get("secrets_manager") or [])
        for s in secrets:
            sid = s.get("name") or s.get("arn") or "secret"
            if "rotation_enabled" in s:
                _fail(ctx, f, eng, "aws", _truthy(s.get("rotation_enabled")),
                      f"Secrets Manager rotation: {sid}", "medium",
                      f"Secret '{sid}' auto-rotation is disabled.",
                      resource={"type": "aws_secretsmanager_secret", "id": sid, "provider": "aws"})
        acm = _as_list(d.get("acm_certificates") or [])
        exp = [c for c in acm if int(c.get("days_to_expiry") or 999) < 30]
        _fail(ctx, f, eng, "aws", len(exp) == 0,
              "No ACM certificates expiring within 30 days", "medium",
              f"{len(exp)} certificate(s) expire within 30 days.")

    if ctx.az_has():
        d = ctx.azure
        for kv in _as_list(d.get("key_vaults")):
            name = kv.get("name") or "kv"
            _fail(ctx, f, eng, "azure", _truthy(kv.get("soft_delete_enabled")),
                  f"Key Vault soft-delete enabled: {name}", "high",
                  f"Key Vault '{name}' soft-delete is off — deleted secrets may be unrecoverable.",
                  resource={"type": "azure_key_vault", "id": name, "provider": "azure"})
            _fail(ctx, f, eng, "azure", _truthy(kv.get("purge_protection_enabled")),
                  f"Key Vault purge protection enabled: {name}", "high",
                  f"Key Vault '{name}' purge protection is off.",
                  resource={"type": "azure_key_vault", "id": name, "provider": "azure"})
            acl = kv.get("network_acls") or {}
            default = str(acl.get("default_action") or kv.get("network_default_action") or "").lower()
            if default or "network_acls" in kv:
                _fail(ctx, f, eng, "azure", default == "deny",
                      f"Key Vault network default deny: {name}", "high",
                      f"Key Vault '{name}' is reachable more broadly than private endpoints allow.")
            if "rbac_authorization" in kv:
                _fail(ctx, f, eng, "azure", _truthy(kv.get("rbac_authorization")),
                      f"Key Vault RBAC authorization: {name}", "medium",
                      f"Key Vault '{name}' still uses access policies instead of Azure RBAC.")
            if "public_network_access" in kv:
                _fail(ctx, f, eng, "azure", str(kv.get("public_network_access")).lower() in {"disabled", "false"},
                      f"Key Vault public network access disabled: {name}", "high",
                      f"Key Vault '{name}' allows public network access.")
    return f


def _engine_compute(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "compute"
    if ctx.aws_has():
        d = ctx.aws
        for i in _as_list(d.get("ec2_instances")):
            iid = i.get("id") or i.get("name") or "instance"
            _fail(ctx, f, eng, "aws", _truthy(i.get("imdsv2_required")),
                  f"EC2 IMDSv2 required: {iid}", "high",
                  f"Instance '{iid}' does not require IMDSv2 — SSRF can steal role creds.",
                  resource={"type": "aws_instance", "id": iid, "provider": "aws"},
                  evidence={"instance": i})
            if i.get("public_ip") and _truthy(i.get("is_production", True)):
                _fail(ctx, f, eng, "aws", False,
                      f"Production EC2 without public IP: {iid}", "high",
                      f"Production instance '{iid}' has public IP {i.get('public_ip')}.",
                      resource={"type": "aws_instance", "id": iid, "provider": "aws"})
            if "ebs_optimized" in i:
                _fail(ctx, f, eng, "aws", _truthy(i.get("ebs_optimized")),
                      f"EC2 EBS optimized: {iid}", "low",
                      f"Instance '{iid}' is not EBS-optimized.")
            if "detailed_monitoring" in i:
                _fail(ctx, f, eng, "aws", _truthy(i.get("detailed_monitoring")),
                      f"EC2 detailed monitoring: {iid}", "low",
                      f"Instance '{iid}' lacks detailed CloudWatch monitoring.")
            vols = _as_list(i.get("volumes") or i.get("block_devices"))
            unenc = [v for v in vols if v.get("encrypted") is False]
            if vols:
                _fail(ctx, f, eng, "aws", len(unenc) == 0,
                      f"EC2 volumes encrypted: {iid}", "high",
                      f"Instance '{iid}' has {len(unenc)} unencrypted volume(s).")
        # SSM / unmanaged instances
        unmanaged = _as_list(d.get("ec2_not_in_ssm") or d.get("unmanaged_instances") or [])
        _fail(ctx, f, eng, "aws", len(unmanaged) == 0,
              "All EC2 instances managed by SSM", "medium",
              f"{len(unmanaged)} instance(s) are not SSM-managed.")

    if ctx.az_has():
        d = ctx.azure
        for vm in _as_list(d.get("virtual_machines")):
            name = vm.get("name") or "vm"
            _fail(ctx, f, eng, "azure", _truthy(vm.get("disk_encryption_enabled")),
                  f"VM disk encryption: {name}", "high",
                  f"VM '{name}' disks are not encrypted (ADE/PMK/CMK).",
                  resource={"type": "azure_vm", "id": name, "provider": "azure"})
            if _truthy(vm.get("is_production", True)) and _truthy(vm.get("has_public_ip")):
                _fail(ctx, f, eng, "azure", False,
                      f"Production VM has no public IP: {name}", "high",
                      f"Production VM '{name}' exposes a public IP.",
                      resource={"type": "azure_vm", "id": name, "provider": "azure"})
            if "secure_boot" in vm:
                _fail(ctx, f, eng, "azure", _truthy(vm.get("secure_boot")),
                      f"VM secure boot: {name}", "medium",
                      f"VM '{name}' Secure Boot is disabled.")
            if "patch_orchestration" in vm:
                _fail(ctx, f, eng, "azure", _truthy(vm.get("patch_orchestration")),
                      f"VM patch orchestration configured: {name}", "medium",
                      f"VM '{name}' has no guest patch orchestration.")
        for ag in _as_list(d.get("vm_scale_sets") or []):
            if ag.get("overprovisioned_admin"):
                _fail(ctx, f, eng, "azure", False,
                      f"VMSS admin hardened: {ag.get('name')}", "medium",
                      "Scale set uses weak admin credential configuration.")
    return f


def _engine_database(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "database"
    if ctx.aws_has():
        d = ctx.aws
        for db in _as_list(d.get("rds_instances")):
            did = db.get("id") or "rds"
            _fail(ctx, f, eng, "aws", _truthy(db.get("storage_encrypted")),
                  f"RDS storage encrypted: {did}", "critical",
                  f"RDS '{did}' storage is not encrypted.",
                  resource={"type": "aws_db_instance", "id": did, "provider": "aws"})
            _fail(ctx, f, eng, "aws", _truthy(db.get("deletion_protection")),
                  f"RDS deletion protection: {did}", "high",
                  f"RDS '{did}' deletion protection is off.",
                  resource={"type": "aws_db_instance", "id": did, "provider": "aws"})
            _fail(ctx, f, eng, "aws", not _truthy(db.get("publicly_accessible")),
                  f"RDS not publicly accessible: {did}", "critical",
                  f"RDS '{did}' is publicly accessible.",
                  resource={"type": "aws_db_instance", "id": did, "provider": "aws"})
            if "backup_retention_period" in db:
                _fail(ctx, f, eng, "aws", int(db.get("backup_retention_period") or 0) >= 7,
                      f"RDS backup retention >= 7 days: {did}", "medium",
                      f"RDS '{did}' backup retention is {db.get('backup_retention_period')}.")
            if "multi_az" in db:
                _fail(ctx, f, eng, "aws", _truthy(db.get("multi_az")),
                      f"RDS Multi-AZ: {did}", "medium",
                      f"RDS '{did}' is not Multi-AZ.")
            if "auto_minor_version_upgrade" in db:
                _fail(ctx, f, eng, "aws", _truthy(db.get("auto_minor_version_upgrade")),
                      f"RDS auto minor version upgrade: {did}", "low",
                      f"RDS '{did}' auto minor upgrades disabled.")
            if "iam_auth" in db:
                _fail(ctx, f, eng, "aws", _truthy(db.get("iam_auth")),
                      f"RDS IAM authentication: {did}", "medium",
                      f"RDS '{did}' IAM DB auth is disabled.")
        for ddb in _as_list(d.get("dynamodb_tables") or []):
            tid = ddb.get("name") or "table"
            if "sse_enabled" in ddb or "encrypted" in ddb:
                _fail(ctx, f, eng, "aws", _truthy(ddb.get("sse_enabled", ddb.get("encrypted"))),
                      f"DynamoDB encryption: {tid}", "high",
                      f"DynamoDB table '{tid}' encryption is off.")
            if "point_in_time_recovery" in ddb:
                _fail(ctx, f, eng, "aws", _truthy(ddb.get("point_in_time_recovery")),
                      f"DynamoDB PITR: {tid}", "medium",
                      f"DynamoDB table '{tid}' point-in-time recovery is off.")

    if ctx.az_has():
        d = ctx.azure
        for db in _as_list(d.get("sql_databases")):
            name = db.get("name") or "sqldb"
            _fail(ctx, f, eng, "azure", _truthy(db.get("tde_enabled")),
                  f"Azure SQL TDE enabled: {name}", "high",
                  f"SQL database '{name}' Transparent Data Encryption is off.",
                  resource={"type": "azure_sql_db", "id": name, "provider": "azure"})
            _fail(ctx, f, eng, "azure", _truthy(db.get("auditing_enabled")),
                  f"Azure SQL auditing enabled: {name}", "medium",
                  f"SQL database '{name}' auditing is disabled.",
                  resource={"type": "azure_sql_db", "id": name, "provider": "azure"})
            pna = str(db.get("public_network_access") or "").lower()
            if "public_network_access" in db:
                _fail(ctx, f, eng, "azure", pna in {"disabled", "false", "no"},
                      f"Azure SQL public network access disabled: {name}", "critical",
                      f"SQL database/server '{name}' allows public network access.",
                      resource={"type": "azure_sql_db", "id": name, "provider": "azure"})
            if "threat_detection" in db:
                _fail(ctx, f, eng, "azure", _truthy(db.get("threat_detection")),
                      f"Azure SQL advanced threat protection: {name}", "medium",
                      f"SQL '{name}' ATP/Defender is off.")
        for cos in _as_list(d.get("cosmos_accounts") or []):
            if cos.get("public_network_access") and str(cos.get("public_network_access")).lower() not in {"disabled", "false"}:
                _fail(ctx, f, eng, "azure", False,
                      f"Cosmos public access disabled: {cos.get('name')}", "high",
                      "Cosmos DB account allows public network access.")
    return f


def _engine_containers(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "containers"
    if ctx.aws_has():
        d = ctx.aws
        for c in _as_list(d.get("eks_clusters") or (d.get("containers") or {}).get("eks") or []):
            name = c.get("name") or "eks"
            _fail(ctx, f, eng, "aws", _truthy(c.get("private_endpoint") or not c.get("public_endpoint", True)),
                  f"EKS API endpoint not public: {name}", "critical",
                  f"EKS cluster '{name}' has a public API endpoint without private-only control.",
                  resource={"type": "aws_eks_cluster", "id": name, "provider": "aws"})
            _fail(ctx, f, eng, "aws", _truthy(c.get("secrets_encryption")),
                  f"EKS secrets envelope encryption: {name}", "high",
                  f"EKS cluster '{name}' etcd secrets encryption is not enabled.")
            _fail(ctx, f, eng, "aws", _truthy(c.get("audit_logs") or c.get("control_plane_logging")),
                  f"EKS control plane logging: {name}", "medium",
                  f"EKS cluster '{name}' control-plane logs are incomplete.")
            if "version_supported" in c:
                _fail(ctx, f, eng, "aws", _truthy(c.get("version_supported")),
                      f"EKS version supported: {name}", "high",
                      f"EKS cluster '{name}' runs an unsupported Kubernetes version.")
        for r in _as_list(d.get("ecr_repositories") or []):
            rn = r.get("name") or "repo"
            if "scan_on_push" in r:
                _fail(ctx, f, eng, "aws", _truthy(r.get("scan_on_push")),
                      f"ECR scan on push: {rn}", "medium",
                      f"ECR repo '{rn}' scan-on-push is disabled.")
            if "image_tag_mutability" in r:
                _fail(ctx, f, eng, "aws", str(r.get("image_tag_mutability")).upper() == "IMMUTABLE",
                      f"ECR image tag immutability: {rn}", "medium",
                      f"ECR repo '{rn}' allows mutable tags.")
        # ECS tasks privileged
        for t in _as_list(d.get("ecs_task_definitions") or []):
            if t.get("privileged") or t.get("host_network"):
                _fail(ctx, f, eng, "aws", False,
                      f"ECS task not privileged/host-network: {t.get('family') or t.get('name')}",
                      "high",
                      "ECS task definition uses privileged mode or host network.")

    if ctx.az_has():
        d = ctx.azure
        for c in _as_list(d.get("aks_clusters") or (d.get("containers") or {}).get("aks") or []):
            name = c.get("name") or "aks"
            _fail(ctx, f, eng, "azure", _truthy(c.get("private_cluster") or not c.get("public_fqdn", True)),
                  f"AKS private cluster: {name}", "critical",
                  f"AKS cluster '{name}' API is publicly reachable.",
                  resource={"type": "azure_aks", "id": name, "provider": "azure"})
            _fail(ctx, f, eng, "azure", _truthy(c.get("azure_rbac") or c.get("aad_rbac")),
                  f"AKS Azure AD RBAC: {name}", "high",
                  f"AKS cluster '{name}' is not integrated with Entra ID RBAC.")
            _fail(ctx, f, eng, "azure", _truthy(c.get("defender_enabled") or c.get("security_profile")),
                  f"AKS Defender/security profile: {name}", "medium",
                  f"AKS cluster '{name}' lacks Defender for Containers.")
            if "authorized_ip_ranges" in c:
                _fail(ctx, f, eng, "azure", bool(c.get("authorized_ip_ranges")),
                      f"AKS API authorized IP ranges: {name}", "high",
                      f"AKS cluster '{name}' has no authorized IP ranges on public API.")
        for r in _as_list(d.get("acr_registries") or []):
            rn = r.get("name") or "acr"
            if "admin_enabled" in r:
                _fail(ctx, f, eng, "azure", not _truthy(r.get("admin_enabled")),
                      f"ACR admin user disabled: {rn}", "high",
                      f"ACR '{rn}' admin user is enabled.")
            if "public_network_access" in r:
                _fail(ctx, f, eng, "azure",
                      str(r.get("public_network_access")).lower() in {"disabled", "false"},
                      f"ACR public network disabled: {rn}", "medium",
                      f"ACR '{rn}' allows public network access.")
    return f


def _engine_serverless(ctx: PackContext) -> list[dict]:
    f: list[dict] = []
    eng = "serverless"
    if ctx.aws_has():
        d = ctx.aws
        for fn in _as_list(d.get("lambda_functions") or (d.get("serverless") or {}).get("lambda") or []):
            name = fn.get("name") or "fn"
            if "public_url" in fn or fn.get("function_url_auth") == "NONE":
                _fail(ctx, f, eng, "aws", not (_truthy(fn.get("public_url")) or fn.get("function_url_auth") == "NONE"),
                      f"Lambda function URL not open: {name}", "critical",
                      f"Lambda '{name}' has an unauthenticated function URL.",
                      resource={"type": "aws_lambda_function", "id": name, "provider": "aws"})
            if "tracing" in fn:
                _fail(ctx, f, eng, "aws", str(fn.get("tracing")).upper() in {"ACTIVE", "PASSTHROUGH", "ENABLED"},
                      f"Lambda X-Ray tracing: {name}", "low",
                      f"Lambda '{name}' tracing is disabled.")
            if fn.get("env_has_secrets"):
                _fail(ctx, f, eng, "aws", False,
                      f"Lambda env without plaintext secrets: {name}", "critical",
                      f"Lambda '{name}' environment appears to hold plaintext secrets.",
                      resource={"type": "aws_lambda_function", "id": name, "provider": "aws"})
            if "runtime_supported" in fn:
                _fail(ctx, f, eng, "aws", _truthy(fn.get("runtime_supported")),
                      f"Lambda runtime supported: {name}", "high",
                      f"Lambda '{name}' uses a deprecated runtime.")
            if "vpc_config_required" in fn and _truthy(fn.get("vpc_config_required")):
                _fail(ctx, f, eng, "aws", _truthy(fn.get("in_vpc")),
                      f"Lambda in VPC when required: {name}", "medium",
                      f"Lambda '{name}' should run inside a VPC for private resource access.")
            role = fn.get("role_policy") or {}
            if role.get("admin") or role.get("action_star"):
                _fail(ctx, f, eng, "aws", False,
                      f"Lambda execution role least privilege: {name}", "high",
                      f"Lambda '{name}' execution role is over-privileged.")
        for api in _as_list(d.get("api_gateways") or []):
            if api.get("logging_level") in (None, "OFF", "off", False):
                _fail(ctx, f, eng, "aws", False,
                      f"API Gateway execution logging: {api.get('name') or api.get('id')}",
                      "medium",
                      "API Gateway stage has execution logging off.")
            if api.get("waf_associated") is False:
                _fail(ctx, f, eng, "aws", False,
                      f"API Gateway WAF associated: {api.get('name') or api.get('id')}",
                      "high",
                      "API Gateway stage is not protected by WAF.")

    if ctx.az_has():
        d = ctx.azure
        for fn in _as_list(d.get("function_apps") or (d.get("serverless") or {}).get("functions") or []):
            name = fn.get("name") or "func"
            if "https_only" in fn:
                _fail(ctx, f, eng, "azure", _truthy(fn.get("https_only")),
                      f"Function App HTTPS only: {name}", "high",
                      f"Function App '{name}' allows HTTP.",
                      resource={"type": "azure_function_app", "id": name, "provider": "azure"})
            if "public_network_access" in fn:
                _fail(ctx, f, eng, "azure",
                      str(fn.get("public_network_access")).lower() in {"disabled", "false"},
                      f"Function App public access disabled: {name}", "high",
                      f"Function App '{name}' is publicly reachable.")
            if fn.get("remote_debugging"):
                _fail(ctx, f, eng, "azure", False,
                      f"Function App remote debugging off: {name}", "medium",
                      f"Function App '{name}' has remote debugging enabled.")
            if "managed_identity" in fn:
                _fail(ctx, f, eng, "azure", _truthy(fn.get("managed_identity")),
                      f"Function App managed identity: {name}", "medium",
                      f"Function App '{name}' lacks a managed identity.")
    return f


def _engine_identity(ctx: PackContext) -> list[dict]:
    """Entra ID / workforce identity (Azure-heavy) + AWS org/federation signals."""
    f: list[dict] = []
    eng = "identity"
    if ctx.az_has():
        d = ctx.azure
        sd = d.get("entra_id_security_defaults") or {}
        caps = _as_list(d.get("conditional_access_policies"))
        mfa_ok = _truthy(sd.get("enabled") or sd.get("security_defaults_enabled")) or any(
            str(p.get("state")).lower() == "enabled"
            and _truthy((p.get("grant_controls") or {}).get("require_mfa"))
            for p in caps
        )
        _fail(ctx, f, eng, "azure", mfa_ok,
              "Entra Security Defaults or CA MFA for users", "critical",
              "Tenant lacks Security Defaults and has no enabled CA policy requiring MFA.",
              compliance=["CIS Azure 1.1", "NIST 800-53 IA-2", "SOC 2 CC6.1"])
        auth = d.get("entra_id_auth_methods") or {}
        _fail(ctx, f, eng, "azure", not _truthy(auth.get("legacy_auth_enabled")),
              "Legacy authentication protocols disabled", "high",
              "Legacy auth is enabled and can bypass modern MFA controls.")
        for proto in ("smtp_auth", "imap", "pop3"):
            if proto in auth:
                _fail(ctx, f, eng, "azure", not _truthy(auth.get(proto)),
                      f"Legacy protocol disabled: {proto}", "medium",
                      f"Auth method '{proto}' remains enabled.")
        guest = d.get("entra_id_guest_settings") or {}
        _fail(ctx, f, eng, "azure", _truthy(guest.get("guest_invite_restricted_to_admins")),
              "Guest invites restricted to admins", "medium",
              "Any user can invite guests — external identity sprawl risk.")
        _fail(ctx, f, eng, "azure", _truthy(guest.get("guest_users_permission_limited")),
              "Guest user permissions limited", "medium",
              "Guest users have excessive directory permissions.")
        pim = d.get("entra_pim") or {}
        pim_on = _truthy(d.get("pim_enabled") or pim.get("enabled"))
        _fail(ctx, f, eng, "azure", pim_on,
              "Privileged Identity Management enabled for admin roles", "high",
              "Standing admin roles without PIM/JIT elevation.")
        gcount = d.get("global_admin_count")
        if gcount is None:
            gcount = (d.get("entra_id_users") or {}).get("global_admin_count")
        if gcount is None:
            gcount = 99  # fail closed when unscored — vuln fixture must set in clean
        # In clean fixture set <=5; in vuln set >5 or omit (fail)
        # But offline clean without key would falsely fail — use fixture profile
        profile = str((ctx.fixture or {}).get("_profile") or "").lower()
        if gcount is not None:
            _fail(ctx, f, eng, "azure", int(gcount) <= 5,
                  "Global Administrator count <= 5", "high",
                  f"Global Administrator count is {gcount} (target <= 5).")
        block_legacy = _truthy(d.get("ca_block_legacy_or_risky")) or any(
            _truthy((p.get("grant_controls") or {}).get("block_legacy_auth"))
            or _truthy((p.get("grant_controls") or {}).get("block_high_risk"))
            for p in caps
        )
        _fail(ctx, f, eng, "azure", block_legacy,
              "Conditional Access blocks legacy/high-risk sign-ins", "high",
              "No Conditional Access control blocking legacy or high-risk sign-ins.")
        idp = d.get("identity_protection") or {}
        if d.get("identity_protection") is not None:
            _fail(ctx, f, eng, "azure", _truthy(idp.get("enabled") or idp.get("policies_enabled")),
                  "Entra Identity Protection policies enabled", "high",
                  "Identity Protection risk policies are not enabled.")
        # named locations / trusted IPs
        if d.get("ca_require_compliant_device") is not None:
            _fail(ctx, f, eng, "azure", _truthy(d.get("ca_require_compliant_device")),
                  "CA requires compliant or hybrid-joined device for admins", "medium",
                  "No device-compliance CA for privileged roles.")

    if ctx.aws_has():
        d = ctx.aws
        # federation / org
        org = d.get("organizations") or d.get("aws_organizations") or {}
        if d.get("organizations") is not None or d.get("aws_organizations") is not None:
            _fail(ctx, f, eng, "aws", _truthy(org.get("all_features") or org.get("enabled")),
                  "AWS Organizations with all features", "medium",
                  "AWS Organizations is not fully enabled for SCPs.")
        scp = _as_list(d.get("service_control_policies") or org.get("scps") or [])
        if d.get("service_control_policies") is not None or org.get("scps") is not None:
            _fail(ctx, f, eng, "aws", len(scp) > 0,
                  "Service Control Policies attached", "high",
                  "No SCPs guardrails attached at org/OU.")
        federated = d.get("federation") or {}
        if d.get("federation") is not None:
            _fail(ctx, f, eng, "aws", _truthy(federated.get("sso_or_saml")),
                  "Workforce federation (SSO/SAML) configured", "medium",
                  "No SSO/SAML federation evidenced for workforce access.")
    return f


def _engine_compliance(ctx: PackContext) -> list[dict]:
    """Cross-cutting CIS/framework posture & security services baseline."""
    f: list[dict] = []
    eng = "compliance"
    sec = ctx.section("compliance")
    missing = _as_list(sec.get("missing_baselines") or (ctx.fixture or {}).get("missing_baselines"))
    for m in missing:
        name = m.get("name") if isinstance(m, dict) else str(m)
        sev = (m.get("severity") if isinstance(m, dict) else None) or "high"
        _fail(ctx, f, eng, m.get("provider", "multi") if isinstance(m, dict) else "multi", False,
              f"Missing security baseline: {name}", sev,
              f"Required enterprise baseline '{name}' is not applied.",
              evidence={"baseline": m})

    if ctx.aws_has():
        d = ctx.aws
        benchmarks = d.get("cis_benchmark") or d.get("security_hub_standards") or sec.get("aws_cis") or {}
        if benchmarks:
            score = benchmarks.get("score_pct", benchmarks.get("score"))
            if score is not None:
                _fail(ctx, f, eng, "aws", float(score) >= 80,
                      "CIS AWS Foundations score >= 80%", "high",
                      f"CIS AWS score is {score}%.",
                      evidence={"cis": benchmarks})
            failed_controls = _as_list(benchmarks.get("failed_controls"))
            for c in failed_controls[:15]:
                cid = c.get("id") if isinstance(c, dict) else str(c)
                title = c.get("title") if isinstance(c, dict) else str(c)
                _fail(ctx, f, eng, "aws", False,
                      f"CIS AWS control failed: {cid}",
                      (c.get("severity") if isinstance(c, dict) else None) or "medium",
                      f"Control '{title}' is non-compliant.",
                      evidence={"control": c})
        # tag policy
        tag_pol = d.get("tag_policy") or {}
        if d.get("tag_policy") is not None:
            _fail(ctx, f, eng, "aws", _truthy(tag_pol.get("enforced")),
                  "Resource tagging policy enforced", "low",
                  "Mandatory tags (Owner/Env/DataClass) are not enforced.")
        # backup plan
        backup = d.get("aws_backup") or {}
        if d.get("aws_backup") is not None:
            _fail(ctx, f, eng, "aws", _truthy(backup.get("plan_present")),
                  "AWS Backup plan covers critical resources", "medium",
                  "No organization backup plan evidenced.")

    if ctx.az_has():
        d = ctx.azure
        secure_score = d.get("secure_score") or sec.get("azure_secure_score") or {}
        if secure_score:
            pct = secure_score.get("pct", secure_score.get("score"))
            if pct is not None:
                _fail(ctx, f, eng, "azure", float(pct) >= 70,
                      "Microsoft Secure Score >= 70%", "high",
                      f"Secure Score is {pct}%.",
                      evidence={"secure_score": secure_score})
        initiatives = _as_list(d.get("policy_initiatives") or (d.get("azure_policy") or {}).get("initiatives"))
        if d.get("policy_initiatives") is not None or d.get("azure_policy") is not None:
            _fail(ctx, f, eng, "azure", len(initiatives) > 0,
                  "Azure Policy security initiatives assigned", "high",
                  "No security initiative (CIS/MCSB) assigned to the subscription.")
        noncomp = _as_list(d.get("policy_noncompliant") or [])
        for p in noncomp[:12]:
            _fail(ctx, f, eng, "azure", False,
                  f"Azure Policy non-compliant: {p.get('policy') or p.get('name') or p}",
                  p.get("severity") or "medium",
                  "Resource is outside required policy state.",
                  evidence={"policy": p})
    return f


def _engine_drift(ctx: PackContext) -> list[dict]:
    """Config drift vs approved baseline / unexpected public exposure."""
    f: list[dict] = []
    eng = "drift"
    sec = ctx.section("drift")
    drifts = _as_list(sec.get("items") or (ctx.fixture or {}).get("drift_items") or sec.get("drifts"))
    for item in drifts:
        if not isinstance(item, dict):
            item = {"name": str(item), "severity": "medium"}
        sev = item.get("severity") or "medium"
        title = item.get("title") or item.get("name") or "configuration drift"
        prov = item.get("provider") or "multi"
        _fail(ctx, f, eng, prov, False,
              f"Drift: {title}", sev,
              item.get("description") or f"Live configuration drifts from approved baseline for '{title}'.",
              resource={"type": item.get("resource_type") or "cloud_resource",
                        "id": item.get("resource_id") or title, "provider": prov},
              evidence={"drift": item})

    # Derived drift signals from inventory mismatches
    if ctx.aws_has():
        d = ctx.aws
        unexpected = _as_list(d.get("unexpected_public_resources") or [])
        for r in unexpected:
            _fail(ctx, f, eng, "aws", False,
                  f"Unexpected public resource: {r.get('id') or r.get('name') or r}",
                  r.get("severity") or "high",
                  "Resource is publicly exposed outside the approved architecture.",
                  evidence={"resource": r})
        # disabled trail while baseline expects one
        baseline = (ctx.fixture or {}).get("baseline") or {}
        if baseline.get("require_guardduty") and not _as_list(d.get("guardduty_detectors")):
            _fail(ctx, f, eng, "aws", False,
                  "Drift from baseline: GuardDuty required but absent", "high",
                  "Baseline requires GuardDuty; detectors list is empty.")
        if baseline.get("require_multi_region_cloudtrail"):
            trails = _as_list(d.get("cloudtrail_trails"))
            if not any(_truthy(t.get("is_multi_region")) for t in trails):
                _fail(ctx, f, eng, "aws", False,
                      "Drift from baseline: multi-region CloudTrail required", "high",
                      "Baseline requires multi-region CloudTrail.")

    if ctx.az_has():
        d = ctx.azure
        unexpected = _as_list(d.get("unexpected_public_resources") or [])
        for r in unexpected:
            _fail(ctx, f, eng, "azure", False,
                  f"Unexpected public resource: {r.get('id') or r.get('name') or r}",
                  r.get("severity") or "high",
                  "Azure resource is publicly exposed outside approved design.",
                  evidence={"resource": r})
        baseline = (ctx.fixture or {}).get("baseline") or {}
        if baseline.get("require_defender_standard"):
            dfc = d.get("defender_for_cloud") or {}
            tier = str(dfc.get("tier") or "").lower()
            if tier not in {"standard", "p2", "enabled"}:
                _fail(ctx, f, eng, "azure", False,
                      "Drift from baseline: Defender for Cloud Standard required", "high",
                      f"Baseline requires Defender Standard; tier={tier or 'unset'}.")
        if baseline.get("require_pim") and not (
            _truthy(d.get("pim_enabled")) or _truthy((d.get("entra_pim") or {}).get("enabled"))
        ):
            _fail(ctx, f, eng, "azure", False,
                  "Drift from baseline: PIM required", "high",
                  "Baseline requires Entra PIM; it is not enabled.")
    return f


# ── Engine registry ──────────────────────────────────────────────────────────

EngineFn = Callable[[PackContext], list[dict]]

ENGINE_REGISTRY: list[dict[str, Any]] = [
    {"key": "iam", "code": "IAM", "name": "Identity & Access Management (IAM/RBAC)",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_iam, "weight": 1.3},
    {"key": "storage", "code": "STO", "name": "Object & File Storage",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_storage, "weight": 1.2},
    {"key": "network", "code": "NET", "name": "Network Security & Exposure",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_network, "weight": 1.2},
    {"key": "logging", "code": "LOG", "name": "Logging, Detection & Monitoring",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_logging, "weight": 1.1},
    {"key": "crypto", "code": "CRY", "name": "Cryptography & Key Management",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_crypto, "weight": 1.1},
    {"key": "compute", "code": "CMP", "name": "Compute Hardening (EC2/VM)",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_compute, "weight": 1.0},
    {"key": "database", "code": "DB", "name": "Database Security",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_database, "weight": 1.1},
    {"key": "containers", "code": "CTR", "name": "Containers & Kubernetes (EKS/AKS)",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_containers, "weight": 1.0},
    {"key": "serverless", "code": "SLS", "name": "Serverless & API Platforms",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_serverless, "weight": 0.9},
    {"key": "identity", "code": "ID", "name": "Workforce Identity (Entra/SSO)",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_identity, "weight": 1.3},
    {"key": "compliance", "code": "CML", "name": "Compliance Baselines & Secure Score",
     "status": "active", "phase": "C1", "preferred_backends": ["prowler", "embedded"], "run": _engine_compliance, "weight": 0.9},
    {"key": "drift", "code": "DFT", "name": "Configuration Drift & Baseline Guard",
     "status": "active", "phase": "C1", "preferred_backends": ["embedded"], "run": _engine_drift, "weight": 0.8},
]


def _resolve_backend(engine: dict, backends: dict) -> str:
    for name in engine.get("preferred_backends") or ["embedded"]:
        b = backends.get(name) or {}
        if b.get("available"):
            return name
    return "embedded"


def _load_fixture(params: dict) -> tuple[dict | None, str, str | None]:
    mock_file = params.get("mock_file") or params.get("fixture")
    mock_flag = params.get("mock", None)
    target = params.get("target") or "."

    if mock_file:
        path = Path(str(mock_file))
        if not path.is_file():
            alt = Path.cwd() / path.name
            path = alt if alt.is_file() else path
        if not path.is_file():
            # neighbor of this module
            path2 = Path(__file__).resolve().parent / Path(str(mock_file)).name
            path = path2 if path2.is_file() else path
        if not path.is_file():
            return None, "mock", f"mock_file not found: {mock_file}"
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(data, dict):
                return None, "mock", "mock fixture must be a JSON object"
            return data, "mock", None
        except Exception as e:
            return None, "mock", f"invalid mock JSON: {e}"

    tpath = Path(str(target))
    if tpath.is_file() and tpath.suffix.lower() == ".json":
        try:
            data = json.loads(tpath.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and (
                data.get("_cloud_fixture")
                or data.get("aws")
                or data.get("azure")
                or data.get("iam_account_summary")
                or data.get("entra_id_security_defaults")
            ):
                return data, "mock", None
        except Exception:
            pass

    if mock_flag is True:
        for candidate in (
            "mock_cloud_vulnerable.json",
            Path(__file__).resolve().parent / "mock_cloud_vulnerable.json",
        ):
            p = Path(candidate)
            if p.is_file():
                return json.loads(p.read_text(encoding="utf-8-sig")), "mock", None
        return None, "mock", "mock=True but mock_cloud_vulnerable.json not found"

    return None, "live", None


def _risk_score(findings: list[dict]) -> int:
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(str(f.get("severity", "info")).lower(), 0)
    return max(0, 100 - penalty)


def _domain_scores(engine_results: list[dict]) -> dict[str, Any]:
    out = {}
    for er in engine_results:
        key = er["key"]
        findings = er.get("findings") or []
        if er.get("status") == "stub" and not findings:
            out[key] = {
                "score": None,
                "status": "stub",
                "findings": 0,
                "phase": er.get("phase"),
                "backend_used": er.get("backend_used"),
            }
        else:
            out[key] = {
                "score": _risk_score(findings),
                "status": er.get("status"),
                "findings": len(findings),
                "phase": er.get("phase"),
                "backend_used": er.get("backend_used"),
            }
    return out


def _pack_readiness(engine_results: list[dict]) -> dict[str, Any]:
    total = len(engine_results)
    active = sum(1 for e in engine_results if e.get("status") == "active")
    stub = sum(1 for e in engine_results if e.get("status") == "stub")
    pct = round((active / total) * 100) if total else 0
    return {
        "phase": PACK_PHASE,
        "label": PACK_LABEL,
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full multi-engine cloud pack — not 18-check ceiling",
        "next_phase": "FIX_MAP expand for CLOUD-* IDs → Cloud Security Engineer brain",
        "active_engines": sorted(e["key"] for e in engine_results if e.get("status") == "active"),
        "pack_hands_complete": active == total and stub == 0,
        "providers": ["aws", "azure"],
    }


def run(params: dict) -> dict:
    """
    TOOL_STANDARDS entrypoint.

    params:
      target: account label or fixture .json path
      mock_file: optional path to offline fixture
      mock: bool — force mock vulnerable default
      profile: AWS named profile for live collect (default sentinel-demo / AWS_PROFILE)
      region: AWS region for live collect (default us-east-1)
      engines: optional list of engine keys to run
    """
    started = _now()
    params = params or {}
    target = str(params.get("target") or ".")
    engines_filter = params.get("engines")
    if isinstance(engines_filter, str):
        engines_filter = [e.strip() for e in engines_filter.split(",") if e.strip()]

    backends = detect_backends()
    fixture, mode, err = _load_fixture(params)
    if err:
        return {
            "tool_id": TOOL_ID,
            "version": VERSION,
            "execution": {
                "timestamp": _ts(),
                "duration_seconds": 0.0,
                "target": target,
                "status": "failed",
                "mode": mode,
                "error": err,
            },
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "risk_score": 0,
                "checks_run": 0,
                "checks_passed": 0,
            },
            "findings": [],
            "metadata": {
                "domain": DOMAIN,
                "subdomain": SUBDOMAIN,
                "sentinel": SENTINEL,
                "tier": TIER,
                "tags": TAGS,
                "llm_summary": f"Cloud pack failed: {err}",
                "pack_phase": PACK_PHASE,
            },
        }

    # Live without fixture: collect read-only AWS inventory via boto3.
    live_meta: dict[str, Any] = {}
    if mode == "live" and not fixture:
        try:
            from ai_cloud_live_aws import collect_aws_inventory

            profile = params.get("profile") or os.environ.get("AWS_PROFILE") or "sentinel-demo"
            region = params.get("region") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
            fixture = collect_aws_inventory(profile=str(profile), region=str(region))
            mode = "live"
            live_meta = {
                "live_collectors": "aws_boto3",
                "aws_profile": profile,
                "aws_region": region,
                "collector_errors": (fixture or {}).get("_collector_errors") or [],
            }
            if target in (".", "", "live", "aws"):
                acc = (fixture or {}).get("account") or {}
                target = str(acc.get("name") or acc.get("id") or target)
        except Exception as e:
            aws_hint = bool(os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"))
            az_hint = bool(os.environ.get("AZURE_CLIENT_ID") or os.environ.get("ARM_CLIENT_ID"))
            live_findings = [
                {
                    "id": "CLOUD-LIVE-001",
                    "title": "Cloud live AWS collect failed — credentials or boto3 unavailable",
                    "severity": "high",
                    "description": (
                        "Live collectors could not build an AWS inventory. "
                        f"Error: {e}. AWS env/profile hint={aws_hint}; Azure hint={az_hint}. "
                        "Fix: pip install boto3; aws sts get-caller-identity --profile sentinel-demo"
                    ),
                    "evidence": {
                        "check_id": "CLOUD-LIVE-001",
                        "engine": "drift",
                        "aws_creds_present": aws_hint,
                        "azure_creds_present": az_hint,
                        "error": str(e),
                        "passed": False,
                    },
                    "remediation": {
                        "steps": [
                            "pip install boto3",
                            "aws sts get-caller-identity --profile sentinel-demo",
                            "Re-run: python ai_cloud_pack.py live  (no --mock)",
                        ],
                        "effort": "low",
                    },
                }
            ]
            return {
                "tool_id": TOOL_ID,
                "version": VERSION,
                "execution": {
                    "timestamp": _ts(),
                    "duration_seconds": round((_now() - started).total_seconds(), 3),
                    "target": target,
                    "status": "failed",
                    "mode": "live_soft",
                    "error": str(e),
                },
                "summary": {
                    "total_findings": 1,
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "risk_score": 90,
                    "checks_run": 1,
                    "checks_passed": 0,
                    "pack_complete_pct": 100,
                },
                "findings": live_findings,
                "metadata": {
                    "domain": DOMAIN,
                    "subdomain": SUBDOMAIN,
                    "sentinel": SENTINEL,
                    "tier": TIER,
                    "tags": TAGS,
                    "llm_summary": f"Cloud pack live collect failed: {e}",
                    "pack_phase": "C3",
                    "live_collectors": "failed",
                    "backends": {
                        k: {"available": v.get("available"), "version": v.get("version")}
                        for k, v in backends.items()
                    },
                },
            }

    ctx = PackContext(target, fixture, mode, backends, engines_filter)
    engine_results: list[dict] = []
    all_findings: list[dict] = []
    errors: list[str] = []

    for eng in ENGINE_REGISTRY:
        key = eng["key"]
        if engines_filter and key not in engines_filter:
            continue
        backend_used = _resolve_backend(eng, backends)
        entry = {
            "key": key,
            "code": eng["code"],
            "name": eng["name"],
            "status": eng["status"],
            "phase": eng["phase"],
            "backend_used": backend_used,
            "weight": eng.get("weight", 1.0),
            "findings": [],
            "error": None,
        }
        try:
            findings = eng["run"](ctx) or []
            for fi in findings:
                ev = fi.setdefault("evidence", {})
                ev.setdefault("engine", key)
                ev.setdefault("backend", backend_used)
                ev.setdefault("check_id", fi.get("id"))
            entry["findings"] = findings
            if mode == "mock":
                entry["backend_used"] = "embedded"
            all_findings.extend(findings)
        except Exception as e:
            entry["error"] = str(e)
            errors.append(f"{key}: {e}")
        engine_results.append(entry)

    crit = sum(1 for x in all_findings if x.get("severity") == "critical")
    high = sum(1 for x in all_findings if x.get("severity") == "high")
    med = sum(1 for x in all_findings if x.get("severity") == "medium")
    low = sum(1 for x in all_findings if x.get("severity") == "low")
    info = sum(1 for x in all_findings if x.get("severity") == "info")
    total = len(all_findings)
    score = _risk_score(all_findings)
    readiness = _pack_readiness(engine_results)
    domain_scores = _domain_scores(engine_results)

    if errors and not all_findings and readiness["engines_active"] == 0:
        status = "partial" if len(errors) < len(engine_results) else "failed"
    elif crit or high:
        status = "failed" if crit else "partial"
    else:
        status = "success"

    duration = (_now() - started).total_seconds()
    live_tools = [k for k, v in backends.items() if k != "embedded" and v.get("available")]
    providers = []
    if ctx.aws_has():
        providers.append("aws")
    if ctx.az_has():
        providers.append("azure")
    llm = (
        f"Cloud pack {VERSION} ({readiness['label']}) scanned '{ctx.account_label()}' mode={mode}. "
        f"Providers: {', '.join(providers) or 'none'}. "
        f"Engines: {readiness['engines_active']} active / {readiness['engines_stub']} stub "
        f"/ {readiness['engines_total']} total ({readiness['complete_pct']}% pack complete). "
        f"Live backends: {', '.join(live_tools) if live_tools else 'none (embedded only)'}. "
        f"Findings: {total} (C:{crit} H:{high} M:{med} L:{low} I:{info}). "
        f"Risk score {score}/100. Next: {readiness['next_phase']}."
    )

    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {
            "timestamp": _ts(),
            "duration_seconds": round(duration, 3),
            "target": ctx.account_label(),
            "status": status,
            "mode": mode,
            "error": "; ".join(errors) if errors else None,
        },
        "summary": {
            "total_findings": total,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": info,
            "risk_score": score,
            "checks_run": sum(1 for e in engine_results if e["status"] == "active"),
            "checks_passed": sum(
                1 for e in engine_results if e["status"] == "active" and not e.get("findings")
            ),
            "engines_run": len(engine_results),
            "engines_active": readiness["engines_active"],
            "engines_stub": readiness["engines_stub"],
            "pack_complete_pct": readiness["complete_pct"],
            "domain_scores": domain_scores,
            "providers": providers,
        },
        "findings": all_findings,
        "metadata": {
            "domain": DOMAIN,
            "subdomain": SUBDOMAIN,
            "sentinel": SENTINEL,
            "tier": TIER,
            "tags": TAGS,
            "llm_summary": llm,
            "pack_phase": PACK_PHASE,
            "pack_readiness": readiness,
            "engine_registry": [
                {
                    "key": e["key"],
                    "code": e["code"],
                    "name": e["name"],
                    "status": e["status"],
                    "phase": e["phase"],
                    "backend_used": e["backend_used"],
                    "findings": len(e["findings"]),
                    "error": e["error"],
                }
                for e in engine_results
            ],
            "backends": {
                k: {
                    "available": v.get("available"),
                    "version": v.get("version"),
                    "engines": v.get("engines"),
                }
                for k, v in backends.items()
            },
            "id_scheme": "CLOUD-{ENGINE_CODE}-{NNN}",
            "engine_codes": ENGINE_CODES,
            "fixture_profile": (fixture or {}).get("_profile") or (fixture or {}).get("_description"),
            "providers": providers,
            **live_meta,
        },
    }


def scan(target: str = ".", mock_file: str | None = None, **kwargs) -> dict:
    params = {"target": target, **kwargs}
    if mock_file:
        params["mock_file"] = mock_file
    return run(params)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = set(a for a in sys.argv[1:] if a.startswith("--"))
    target = args[0] if args else "."
    mock_file = args[1] if len(args) > 1 else None

    params: dict[str, Any] = {"target": target}
    if mock_file:
        params["mock_file"] = mock_file
    elif "--mock" in flags or target in ("mock", "mock-vuln", "mock-vulnerable"):
        params["mock"] = True
        params["target"] = "mock-cloud"
    elif target in ("mock-clean",):
        params["mock_file"] = "mock_cloud_clean.json"
        params["target"] = "mock-cloud-clean"
    elif target in (".", "live", "aws") or "--live" in flags:
        params["target"] = "live"
        params["profile"] = os.environ.get("AWS_PROFILE") or "sentinel-demo"
        params["region"] = os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

    result = run(params)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("execution", {}).get("status") != "failed" else 1)
