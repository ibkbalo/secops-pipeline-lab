# ai_data_scout.py
# Sentinel Stacks — Perimeter Sentinel Module 2: Data Scout
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import subprocess
import datetime
from urllib.parse import urlparse

TOOL_ID = "scan_public_url_data_scout"
VERSION = "1.0.1"
DOMAIN = "appsec"
SUBDOMAIN = "perimeter/data-exposure"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["data-exposure", "s3", "azure-blob", "git", "env", "backup", "elasticsearch", "mongodb", "redis"]

SENSITIVE_PATHS = [
    {"path": "/.env", "severity": "critical", "title": "Exposed .env file",
     "match_substrings": ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN", "AWS_", "AZURE_", "PRIVATE_KEY"]},
    {"path": "/.git/HEAD", "severity": "high", "title": "Exposed .git repository",
     "match_substrings": ["ref:", "refs/"]},
    {"path": "/.git/config", "severity": "high", "title": "Exposed .git/config",
     "match_substrings": ["[core]", "repositoryformatversion"]},
    {"path": "/backup.sql", "severity": "critical", "title": "Exposed SQL database dump",
     "match_substrings": ["CREATE TABLE", "INSERT INTO", "MySQL dump"]},
    {"path": "/dump.sql", "severity": "critical", "title": "Exposed SQL database dump",
     "match_substrings": ["CREATE TABLE", "INSERT INTO", "MySQL dump"]},
    {"path": "/db.sql", "severity": "critical", "title": "Exposed SQL database dump",
     "match_substrings": ["CREATE TABLE", "INSERT INTO"]},
    {"path": "/phpinfo.php", "severity": "medium", "title": "Exposed phpinfo() page",
     "match_substrings": ["PHP Version", "phpinfo()"]},
]

DATA_PORT_FINDINGS = {
    9200: {"service": "Elasticsearch", "severity": "high",
           "rationale": "Elasticsearch on the public internet is almost always unpatched or unauthenticated. Shodan lists 30k+ exposed instances."},
    27017: {"service": "MongoDB", "severity": "critical",
            "rationale": "MongoDB on the public internet with default settings = anonymous full read/write. This is the 'MongoDB ransom' breach pattern."},
    6379: {"service": "Redis", "severity": "high",
           "rationale": "Redis on the public internet with default settings = unauthenticated command execution."},
    11211: {"service": "Memcached", "severity": "high",
            "rationale": "Memcached on the public internet = UDP amplification target and unauthenticated read."},
}

KNOWN_GOOD_DOMAINS = {"github.com", "cloudflare.com", "google.com", "microsoft.com", "apple.com",
                      "example.com", "httpbin.org", "s3.amazonaws.com"}

def _ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _resolve(host):
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []

def _check_port(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def _http_get(url, timeout=8, max_bytes=200000):
    try:
        out = subprocess.run(
            ["curl", "-s", "-L", "--max-redirs", "3", "--connect-timeout", "4",
             "--max-time", str(timeout), "--max-filesize", str(max_bytes), url],
            capture_output=True, text=True, timeout=timeout + 3
        )
        return out.stdout, out.returncode
    except Exception as e:
        return f"# error: {e}", 1

def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)

def _empty_report(target_url, status, error):
    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target_url, "status": status, "error": error},
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_score": 0},
        "findings": [],
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": f"Data Scout failed for {target_url}: {error}." if error else "Data Scout did not run."}
    }

def run(params: dict) -> dict:
    started = _now()
    target_url = (params or {}).get("target", "").strip()
    if not target_url:
        return _empty_report("", "failed", "missing target")
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        return _empty_report(target_url, "failed", "invalid hostname")

    ips = _resolve(host)
    if not ips:
        return _empty_report(target_url, "failed", "DNS resolution failed")
    ip = ips[0]
    is_known_good = host.lower() in KNOWN_GOOD_DOMAINS

    findings = []
    fid = 0

    def add(severity, title, description, evidence, remediation, compliance, notes=""):
        nonlocal fid
        fid += 1
        if is_known_good and severity in ("critical", "high"):
            severity = "info"
            notes = (notes + " | " if notes else "") + "Auto-downgraded: target is a known-good site."
        findings.append({
            "id": f"FIND-{fid:03d}",
            "title": title,
            "severity": severity,
            "confidence": "high",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description,
            "evidence": evidence,
            "remediation": {"steps": remediation,
                            "effort": "low" if _sev_rank(severity) <= 2 else "medium",
                            "tier": 1, "reversible": True, "requires_approval": False},
            "compliance": compliance,
            "notes": notes
        })

    base = f"{parsed.scheme}://{parsed.netloc}"
    for entry in SENSITIVE_PATHS:
        url_to_test = base + entry["path"]
        body, rc = _http_get(url_to_test, timeout=6)
        if rc != 0 or not body:
            continue
        if body.startswith("# error"):
            continue
        body_lc = body.lower()
        hits = [s for s in entry["match_substrings"] if s.lower() in body_lc]
        if hits and len(body) > 5:
            sev = entry["severity"]
            add(sev, entry["title"],
                f"{entry['title']} at {url_to_test}. Body contains indicators: {hits}.",
                {"url": url_to_test, "matched_indicators": hits,
                 "body_length_bytes": len(body), "body_preview": body[:300]},
                [f"Immediately remove the file from public access.",
                 f"Block the path at the web server / CDN: deny access to `{entry['path']}`.",
                 "If the file contains credentials, rotate every secret in the file NOW.",
                 "Add the path to the Sentinel Stacks Hardening Kit denylist."],
                ["NIST SC-28", "ISO 27001 A.13.2.1", "PCI DSS 4.0 3.5.1"],
                "Confirms real data exposure. Body content matched the expected pattern.")

    if host.endswith(".s3.amazonaws.com") or host == "s3.amazonaws.com":
        add("high", "S3-style hostname in use — verify bucket is not public",
            f"Host {host} is an S3 endpoint. Public S3 buckets are the #1 cloud breach pattern. The tool could not verify anonymous list access without the specific bucket name.",
            {"host": host, "pattern": "s3.amazonaws.com"},
            ["Run `aws s3api get-public-access-block --bucket <name>` and confirm all 4 flags are true.",
             "Run `aws s3api get-bucket-policy --bucket <name>` and confirm no `Principal: \"*\"` allow rules.",
             "Enable S3 Block Public Access at the account level.",
             "Use the Sentinel Stacks Hardening Kit Terraform to enforce this."],
            ["CIS AWS 2.1.5", "NIST AC-3", "ISO 27001 A.13.1.3"],
            "Manual verification of the specific bucket policy is required.")

    if host.endswith(".blob.core.windows.net") or host.endswith(".azureedge.net"):
        add("high", "Azure Blob / CDN hostname in use — verify container is not public",
            f"Host {host} is an Azure Blob Storage or CDN endpoint. Public containers are the Azure equivalent of public S3.",
            {"host": host, "pattern": "blob.core.windows.net or azureedge.net"},
            ["Set the container's public access level to 'Private'.",
             "Disable anonymous blob access at the storage account level.",
             "Use the Sentinel Stacks Hardening Kit Bicep template to enforce this."],
            ["CIS Azure 3.1", "NIST AC-3", "ISO 27001 A.13.1.3"],
            "Manual verification of the storage account's public access setting is required.")

    if host.endswith(".googleapis.com") or host.endswith(".storage.googleapis.com"):
        add("medium", "Google Cloud Storage hostname in use — verify bucket is not public",
            f"Host {host} is a GCS endpoint. Public buckets are the GCP equivalent of public S3.",
            {"host": host, "pattern": "googleapis.com or storage.googleapis.com"},
            ["Run `gcloud storage buckets describe gs://<bucket> --format=yaml` and verify `iamConfiguration.publicAccessPrevention` is `enforced`.",
             "Use the Sentinel Stacks Hardening Kit Terraform to enforce this."],
            ["CIS GCP 3.1", "NIST AC-3"],
            "Manual verification of the bucket's IAM policy is required.")

    open_data_ports = []
    for port, info in DATA_PORT_FINDINGS.items():
        if _check_port(host, port):
            open_data_ports.append({"port": port, "service": info["service"], "severity": info["severity"]})
    for item in open_data_ports:
        add(item["severity"], f"Data service {item['service']} exposed to the public internet (port {item['port']})",
            f"Port {item['port']} ({item['service']}) is publicly reachable on {host} ({ip}). {DATA_PORT_FINDINGS[item['port']]['rationale']}",
            {"host": host, "ip": ip, "port": item["port"], "service": item["service"]},
            [f"Move {item['service']} behind a firewall or private subnet.",
             f"Require authentication on the {item['service']} instance.",
             "If internet exposure is required, use a Zero-Trust gateway (Cloudflare Access, Tailscale, Twingate).",
             "Use the Sentinel Stacks Hardening Kit Terraform to add a deny rule to the security group."],
            ["CIS Controls 4.4", "CIS Controls 4.5", "NIST SC-7", "ISO 27001 A.13.1.1"],
            "Direct exposure of data services to the internet is the top empirical breach pattern.")

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    info = sum(1 for f in findings if f["severity"] == "info")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))

    duration = (_now() - started).total_seconds()
    parts = []
    if crit >= 1:
        parts.append("Sensitive files or data services are exposed to the public internet.")
    if any("s3.amazonaws.com" in (f.get("evidence", {}).get("host", "") or "") for f in findings):
        parts.append("S3-style endpoint detected; verify the bucket is not public.")
    if any("blob.core.windows.net" in (f.get("evidence", {}).get("host", "") or "") for f in findings):
        parts.append("Azure Blob endpoint detected; verify the container is not public.")
    if not parts and info == 0:
        parts.append("No exposed sensitive data detected.")
    elif not parts:
        parts.append("No critical data exposures, but some checks were inconclusive.")
    llm = (
        f"Data Scout scanned {host} ({ip}) over {target_url}. "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low, {info} info. "
        + " ".join(parts) +
        " Recommend the Sentinel Stacks Hardening Kit ZIP to remediate the top 3 findings."
    )

    status = "success" if total == 0 else "partial" if crit == 0 else "failed"

    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": round(duration, 2),
                      "target": target_url, "status": status, "error": None},
        "summary": {"total_findings": total, "critical": crit, "high": high,
                    "medium": med, "low": low, "info": info, "risk_score": score},
        "findings": findings,
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL,
                     "tier": TIER, "tags": TAGS, "llm_summary": llm}
    }

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run({"target": url}), indent=2))