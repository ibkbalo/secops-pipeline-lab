# ai_infra_auditor_azure.py
# Sentinel Stacks — Infrastructure Sentinel Module 2: Azure Auditor
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import os
import sys
import datetime
from collections import defaultdict

TOOL_ID = "scan_infra_auditor_azure"
VERSION = "1.0.0"
DOMAIN = "infrastructure"
SUBDOMAIN = "infrastructure/azure"
SENTINEL = "infrastructure"
TIER = 2
TAGS = ["azure", "entra-id", "storage", "nsg", "key-vault", "defender", "compliance", "nist", "soc2"]

AZURE_CHECKS = [
    # ─── Entra ID (3) ───────────────────────────────────────────────────────
    {
        "id": "AZ-001", "category": "Entra ID",
        "name": "Security Defaults or Conditional Access MFA for All Users",
        "description": "All users must have MFA via Security Defaults or Conditional Access. Without MFA, a stolen password is full tenant access.",
        "severity_if_fail": "critical",
        "frameworks": {"nist": ["AC-2","IA-2","IA-5"], "soc2": ["CC6.1","CC6.2","CC6.3"],
                       "iso": ["A.9.2.1","A.9.4.2","A.9.4.3"], "gdpr": ["Art. 32(1)(b)","Art. 32(1)(d)"]},
        "mock_check": lambda d: (d.get("entra_id_security_defaults", {}).get("enabled", False) or
                                   any(p.get("state") == "enabled" and p.get("grant_controls", {}).get("require_mfa", False)
                                       for p in d.get("conditional_access_policies", [])))
    },
    {
        "id": "AZ-002", "category": "Entra ID",
        "name": "No Legacy Authentication Protocols Enabled",
        "description": "Legacy auth (POP3/IMAP/SMTP Auth) must be blocked — these protocols bypass MFA.",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["IA-2","IA-5","AC-3"], "soc2": ["CC6.1","CC6.3"],
                       "iso": ["A.9.4.2"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: not d.get("entra_id_auth_methods", {}).get("legacy_auth_enabled", False)
    },
    {
        "id": "AZ-003", "category": "Entra ID",
        "name": "Guest User Invites Restricted to Admins",
        "description": "Only admins should invite guests. Open guest invites expand the attack surface.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["AC-2","AC-3"], "soc2": ["CC6.1","CC6.3"],
                       "iso": ["A.9.2.1","A.9.2.2"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: d.get("entra_id_guest_settings", {}).get("guest_invite_restricted_to_admins", False)
    },
    # ─── Storage (3) ────────────────────────────────────────────────────────
    {
        "id": "AZ-004", "category": "Storage Accounts",
        "name": "Storage Accounts: HTTPS-Only (Secure Transfer Required)",
        "description": "All storage accounts must require HTTPS. HTTP exposes data in transit.",
        "severity_if_fail": "critical",
        "frameworks": {"nist": ["SC-8","SC-13"], "soc2": ["CC6.1","CC6.7"],
                       "iso": ["A.10.1.1","A.13.2.1"], "gdpr": ["Art. 32(1)(a)"]},
        "mock_check": lambda d: all(sa.get("secure_transfer_required", False) for sa in d.get("storage_accounts", []))
    },
    {
        "id": "AZ-005", "category": "Storage Accounts",
        "name": "Storage Accounts: No Public Anonymous Blob Access",
        "description": "Public blob access must be disabled. Public containers are a top Azure breach vector.",
        "severity_if_fail": "critical",
        "frameworks": {"nist": ["AC-3","SC-7"], "soc2": ["CC6.1","CC6.6"],
                       "iso": ["A.9.4.1","A.13.1.1"], "gdpr": ["Art. 32(1)(a)","Art. 32(1)(b)"]},
        "mock_check": lambda d: all(not sa.get("allow_blob_public_access", True) for sa in d.get("storage_accounts", []))
    },
    {
        "id": "AZ-006", "category": "Storage Accounts",
        "name": "Storage Accounts: Customer-Managed Key Encryption",
        "description": "Prefer CMK (Microsoft.Keyvault) for encryption key sovereignty.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["SC-13","SC-28"], "soc2": ["CC6.1","CC6.7"],
                       "iso": ["A.10.1.1","A.18.1.3"], "gdpr": ["Art. 32(1)(a)"]},
        "mock_check": lambda d: all(sa.get("encryption_key_source", "") == "Microsoft.Keyvault" for sa in d.get("storage_accounts", []))
    },
    # ─── NSG (2) ────────────────────────────────────────────────────────────
    {
        "id": "AZ-007", "category": "Network Security Groups",
        "name": "No NSG Rules Allowing Internet to Port 22 (SSH)",
        "description": "SSH from Internet must be denied. Use Azure Bastion or VPN instead.",
        "severity_if_fail": "critical",
        "frameworks": {"nist": ["AC-3","SC-7"], "soc2": ["CC6.1","CC6.6"],
                       "iso": ["A.9.4.1","A.13.1.1"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: not any(
            r.get("direction") == "Inbound" and r.get("source") == "Internet" and
            r.get("destination_port") in ("22", "*") and r.get("access") == "Allow"
            for r in d.get("nsg_rules", []))
    },
    {
        "id": "AZ-008", "category": "Network Security Groups",
        "name": "No NSG Rules Allowing Internet to Port 3389 (RDP)",
        "description": "RDP from Internet must be denied. Use Azure Bastion instead.",
        "severity_if_fail": "critical",
        "frameworks": {"nist": ["AC-3","SC-7"], "soc2": ["CC6.1","CC6.6"],
                       "iso": ["A.9.4.1","A.13.1.1"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: not any(
            r.get("direction") == "Inbound" and r.get("source") == "Internet" and
            r.get("destination_port") in ("3389", "*") and r.get("access") == "Allow"
            for r in d.get("nsg_rules", []))
    },
    # ─── Key Vault (2) ──────────────────────────────────────────────────────
    {
        "id": "AZ-009", "category": "Key Vault",
        "name": "Key Vault: Soft Delete + Purge Protection",
        "description": "Soft-delete AND purge protection prevent permanent secret destruction.",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["SC-12","CP-9"], "soc2": ["CC6.1","CC7.5"],
                       "iso": ["A.10.1.1","A.12.3.1"], "gdpr": ["Art. 32(1)(a)","Art. 32(1)(c)"]},
        "mock_check": lambda d: all(v.get("soft_delete_enabled", False) and v.get("purge_protection_enabled", False)
                                      for v in d.get("key_vaults", []))
    },
    {
        "id": "AZ-010", "category": "Key Vault",
        "name": "Key Vault: Network Default Deny",
        "description": "Key Vault network ACLs default_action must be Deny (Private Link / allowed IPs only).",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["AC-3","SC-7"], "soc2": ["CC6.1","CC6.6"],
                       "iso": ["A.9.4.1","A.13.1.1"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: all(v.get("network_acls", {}).get("default_action", "") == "Deny"
                                      for v in d.get("key_vaults", []))
    },
    # ─── Defender (2) ───────────────────────────────────────────────────────
    {
        "id": "AZ-011", "category": "Defender for Cloud",
        "name": "Defender for Cloud: Standard Tier",
        "description": "Standard tier enables threat detection beyond the free security score.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["SI-4","RA-5"], "soc2": ["CC7.1","CC7.2"],
                       "iso": ["A.16.1.5"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: d.get("defender_for_cloud", {}).get("tier", "") == "Standard"
    },
    {
        "id": "AZ-012", "category": "Defender for Cloud",
        "name": "Defender Plans: Servers, SQL, Storage, Key Vault On",
        "description": "Core Defender plans must be On for coverage without monitoring gaps.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["SI-4","RA-5"], "soc2": ["CC7.1","CC7.2"],
                       "iso": ["A.16.1.5"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: all(
            d.get("defender_for_cloud", {}).get("plans", {}).get(plan) == "On"
            for plan in ["Servers", "SqlServers", "StorageAccounts", "KeyVaults"])
    },
    # ─── Monitoring (2) ─────────────────────────────────────────────────────
    {
        "id": "AZ-013", "category": "Monitoring",
        "name": "Activity Log Export to Log Analytics",
        "description": "Activity logs must export to Log Analytics for long-term investigation.",
        "severity_if_fail": "high",
      "frameworks": {"nist": ["AU-2","AU-4","AU-11"], "soc2": ["CC7.2","CC7.3"],
                       "iso": ["A.12.4.1","A.16.1.5"], "gdpr": ["Art. 30","Art. 33"]},
        "mock_check": lambda d: d.get("activity_log_export", {}).get("export_to_log_analytics", False)
    },
    {
        "id": "AZ-014", "category": "Monitoring",
        "name": "Log Analytics Retention >= 365 Days",
        "description": "Retention under 365 days blocks late forensic investigation.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["AU-11","AU-4"], "soc2": ["CC7.2","CC7.3"],
                       "iso": ["A.12.4.1"], "gdpr": ["Art. 30"]},
        "mock_check": lambda d: d.get("log_analytics_workspace", {}).get("retention_days", 0) >= 365
    },
    # ─── SQL (2) ────────────────────────────────────────────────────────────
    {
        "id": "AZ-015", "category": "Azure SQL",
        "name": "Azure SQL: TDE Enabled",
        "description": "Transparent Data Encryption must be on for all SQL databases.",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["SC-13","SC-28"], "soc2": ["CC6.1","CC6.7"],
                       "iso": ["A.10.1.1","A.18.1.3"], "gdpr": ["Art. 32(1)(a)"]},
        "mock_check": lambda d: all(db.get("tde_enabled", False) for db in d.get("sql_databases", []))
    },
    {
        "id": "AZ-016", "category": "Azure SQL",
        "name": "Azure SQL: Auditing Enabled",
        "description": "SQL auditing must write to storage or Log Analytics.",
        "severity_if_fail": "medium",
        "frameworks": {"nist": ["AU-2","AU-6"], "soc2": ["CC7.2","CC7.3"],
                       "iso": ["A.12.4.1"], "gdpr": ["Art. 30"]},
        "mock_check": lambda d: all(db.get("auditing_enabled", False) for db in d.get("sql_databases", []))
    },
    # ─── VMs (2) ────────────────────────────────────────────────────────────
    {
        "id": "AZ-017", "category": "Virtual Machines",
        "name": "VMs: Disk Encryption Enabled",
        "description": "OS and data disks must use ADE or platform encryption.",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["SC-13","SC-28"], "soc2": ["CC6.1","CC6.7"],
                       "iso": ["A.10.1.1","A.18.1.3"], "gdpr": ["Art. 32(1)(a)"]},
        "mock_check": lambda d: all(vm.get("disk_encryption_enabled", False) for vm in d.get("virtual_machines", []))
    },
    {
        "id": "AZ-018", "category": "Virtual Machines",
        "name": "Production VMs: No Public IP",
        "description": "Production VMs should not have direct public IPs. Front with LB/App Gateway/Front Door.",
        "severity_if_fail": "high",
        "frameworks": {"nist": ["AC-3","SC-7"], "soc2": ["CC6.1","CC6.6"],
                       "iso": ["A.9.4.1","A.13.1.1"], "gdpr": ["Art. 32(1)(b)"]},
        "mock_check": lambda d: all(not vm.get("has_public_ip", False) for vm in d.get("virtual_machines", [])
                                      if vm.get("is_production", True))
    },
]

def _ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)

def _load_mock_data(mock_file):
    if not os.path.isfile(mock_file):
        print(f"Mock file not found: {mock_file}", file=sys.stderr)
        return None
    with open(mock_file, "r", encoding="utf-8") as f:
        return json.load(f)

def _empty_report(target, status, error):
    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target, "status": status, "error": error},
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_score": 0,
                    "checks_run": 0, "checks_passed": 0, "compliance_scores": {}},
        "findings": [],
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": f"Azure Auditor failed for {target}: {error}."}
    }

def run(params: dict) -> dict:
    started = _now()
    target = (params or {}).get("target", "").strip()
    mock_file = params.get("mock_file", "mock_azure_vulnerable.json") if params else "mock_azure_vulnerable.json"

    if not target:
        return _empty_report("", "failed", "missing target (Azure subscription ID)")

    mock_data = _load_mock_data(mock_file)
    if not mock_data:
        return _empty_report(target, "failed", f"mock file '{mock_file}' not found")

    findings = []
    fid = 0
    checks_run = 0
    checks_passed = 0

    def add(severity, title, description, evidence, remediation, compliance, notes=""):
        nonlocal fid
        fid += 1
        findings.append({
            "id": f"AZ-{fid:03d}", "title": title, "severity": severity, "confidence": "high",
            "resource": {"type": "azure_subscription", "id": target, "subscription": target},
            "description": description, "evidence": evidence,
            "remediation": {"steps": remediation, "effort": "medium" if _sev_rank(severity) >= 3 else "low",
                            "tier": 2, "reversible": True, "requires_approval": severity == "critical"},
            "compliance": compliance, "notes": notes
        })

    for check in AZURE_CHECKS:
        checks_run += 1
        try:
            passed = check["mock_check"](mock_data)
        except Exception:
            passed = False

        sev = "info" if passed else check["severity_if_fail"]
        check_id = check["id"]
        category = check["category"]

        comp_refs = []
        for fw, controls in check["frameworks"].items():
            fw_label = {"nist": "NIST 800-53", "soc2": "SOC 2", "iso": "ISO 27001", "gdpr": "GDPR"}.get(fw, fw)
            for ctrl in controls:
                comp_refs.append(f"{fw_label} {ctrl}")

        if passed:
            checks_passed += 1
            add("info", f"[{category}] {check['name']} — PASSED",
                check["description"], {"check_id": check_id, "passed": True, "category": category},
                ["No action required."], comp_refs,
                f"Compliant — {len(comp_refs)} controls satisfied.")
        else:
            add(sev, f"[{category}] {check['name']} — FAILED",
                check["description"],
                {"check_id": check_id, "passed": False, "category": category, "frameworks": check["frameworks"]},
                [f"[{check_id}] {check['description']}",
                 f"Improves compliance with: {', '.join(comp_refs)}."],
                comp_refs)

    fw_totals = defaultdict(int)
    fw_passed = defaultdict(int)
    for check in AZURE_CHECKS:
        for fw in check["frameworks"]:
            fw_totals[fw] += 1
            try:
                if check["mock_check"](mock_data):
                    fw_passed[fw] += 1
            except Exception:
                pass

    compliance_scores = {
        "nist_800_53_pct": round((fw_passed.get("nist", 0) / fw_totals["nist"]) * 100) if fw_totals.get("nist") else 0,
        "soc2_pct": round((fw_passed.get("soc2", 0) / fw_totals["soc2"]) * 100) if fw_totals.get("soc2") else 0,
        "iso_27001_pct": round((fw_passed.get("iso", 0) / fw_totals["iso"]) * 100) if fw_totals.get("iso") else 0,
        "gdpr_pct": round((fw_passed.get("gdpr", 0) / fw_totals["gdpr"]) * 100) if fw_totals.get("gdpr") else 0,
    }
    overall_compliance = round(sum(compliance_scores.values()) / 4)

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    info = sum(1 for f in findings if f["severity"] == "info")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))
    duration = (_now() - started).total_seconds()

    if crit > 0:
        verdict = f"CRITICAL: {crit} critical misconfigurations found."
    elif high > 0:
        verdict = f"HIGH: {high} high-severity findings."
    elif med > 0:
        verdict = f"MEDIUM: {med} medium-severity findings."
    else:
        verdict = f"CLEAN: All {checks_run} checks passed."

    llm = (
        f"Azure Auditor scanned subscription {target}. {checks_run} checks, {checks_passed} passed. "
        f"Score {score}/100. Compliance: {overall_compliance}% overall "
        f"(NIST {compliance_scores['nist_800_53_pct']}%, SOC2 {compliance_scores['soc2_pct']}%, "
        f"ISO {compliance_scores['iso_27001_pct']}%, GDPR {compliance_scores['gdpr_pct']}%). "
        + verdict
    )
    status = "success" if crit == 0 and high == 0 else "partial" if crit == 0 else "failed"

    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": round(duration, 2),
                      "target": target, "status": status, "mode": "mock", "error": None},
        "summary": {"total_findings": total, "critical": crit, "high": high,
                    "medium": med, "low": low, "info": info, "risk_score": score,
                    "checks_run": checks_run, "checks_passed": checks_passed,
                    "compliance_scores": compliance_scores,
                    "overall_compliance_pct": overall_compliance},
        "findings": findings,
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": llm}
    }

def scan(target: str, mock_file: str = "mock_azure_vulnerable.json") -> dict:
    return run({"target": target, "mock_file": mock_file})

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "mock-sub-aaaa-bbbb-cccc-dddddddddddd"
    mf = sys.argv[2] if len(sys.argv) > 2 else "mock_azure_vulnerable.json"
    print(json.dumps(scan(target, mf), indent=2))