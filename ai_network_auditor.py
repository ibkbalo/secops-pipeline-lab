# ai_network_auditor.py
# Sentinel Stacks — Perimeter Sentinel Module 1: Network Auditor
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import ssl
import subprocess
import datetime
import re
from urllib.parse import urlparse

TOOL_ID = "scan_public_url_network_auditor"
VERSION = "1.0.0"
DOMAIN = "appsec"
SUBDOMAIN = "perimeter/network"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["network", "tls", "dns", "ports", "public-url"]

RISKY_PORTS = [21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017]

def _ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def _now():
    return datetime.datetime.utcnow()

def _resolve(host):
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []

def _check_tls(host, port=443, timeout=8):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expires = cert.get("notAfter")
                proto = ssock.version()
                return {"ok": True, "expires": expires, "protocol": proto, "subject": dict(x[0] for x in cert.get("subject", []))}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _check_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def _http_headers(url, timeout=8):
    try:
        out = subprocess.run(
            ["curl", "-sI", "-L", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return out.stdout.splitlines()
    except Exception as e:
        return [f"# error: {e}"]

def _missing_security_headers(headers):
    needed = {
        "strict-transport-security": "high",
        "content-security-policy": "high",
        "x-frame-options": "medium",
        "x-content-type-options": "medium",
        "referrer-policy": "low",
    }
    blob = "\n".join(headers).lower()
    return {h: sev for h, sev in needed.items() if h not in blob}

def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)

def run(params: dict) -> dict:
    started = _now()
    target_url = (params or {}).get("target", "").strip()
    if not target_url:
        return {
            "tool_id": TOOL_ID,
            "version": VERSION,
            "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": "", "status": "failed", "error": "missing target"},
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS, "llm_summary": "No target provided."}
        }

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    findings = []

    if not host:
        return {
            "tool_id": TOOL_ID,
            "version": VERSION,
            "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target_url, "status": "failed", "error": "invalid hostname"},
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS, "llm_summary": f"Invalid hostname in {target_url}."}
        }

    ips = _resolve(host)
    if not ips:
        return {
            "tool_id": TOOL_ID,
            "version": VERSION,
            "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target_url, "status": "failed", "error": "DNS resolution failed"},
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS, "llm_summary": f"DNS resolution failed for {host}."}
        }

    ip = ips[0]
    fid = 0
    def add(severity, title, description, evidence, remediation, compliance):
        nonlocal fid
        fid += 1
        findings.append({
            "id": f"FIND-{fid:03d}",
            "title": title,
            "severity": severity,
            "confidence": "high",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description,
            "evidence": evidence,
            "remediation": {
                "steps": remediation,
                "effort": "low" if _sev_rank(severity) <= 2 else "medium",
                "tier": 1,
                "reversible": True,
                "requires_approval": False
            },
            "compliance": compliance
        })

    tls_info = _check_tls(host, 443)
    if not tls_info.get("ok"):
        add("critical", "No valid TLS/SSL on port 443",
            f"Host {host} does not present a valid TLS certificate on port 443.",
            {"host": host, "port": 443, "error": tls_info.get("error")},
            ["Provision a valid TLS certificate (Let's Encrypt or commercial CA).",
             "Force HTTPS via 301 redirect at the load balancer / CDN.",
             "Set HSTS with `includeSubDomains` and `preload`."],
            ["PCI DSS 4.0 4.2.1", "NIST SC-8", "ISO 27001 A.10.1.1"])
    else:
        proto = tls_info.get("protocol", "")
        if proto and proto not in ("TLSv1.3", "TLSv1.2"):
            add("high", f"Outdated TLS protocol: {proto}",
                f"Server negotiated {proto}. Modern browsers and frameworks require TLS 1.2+.",
                {"host": host, "protocol": proto},
                ["Disable TLS 1.0 and TLS 1.1 on the load balancer / web server.",
                 "Enable TLS 1.2 and TLS 1.3 only."],
                ["PCI DSS 4.0 4.2.1", "NIST SC-8", "OWASP A02:2021"])
        expires = tls_info.get("expires", "")
        if expires:
            try:
                exp_dt = datetime.datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_dt - _now()).days
                if days_left < 0:
                    add("critical", "TLS certificate expired",
                        f"Certificate expired {-days_left} days ago.",
                        {"host": host, "notAfter": expires},
                        ["Renew the TLS certificate immediately.",
                         "Automate renewal with Let's Encrypt or your CA's auto-renew flow."],
                        ["NIST SC-8", "ISO 27001 A.10.1.2"])
                elif days_left < 14:
                    add("high", f"TLS certificate expires in {days_left} days",
                        "Certificate expires within 14 days. Outage risk if not renewed.",
                        {"host": host, "notAfter": expires, "days_left": days_left},
                        ["Renew the certificate now.", "Confirm auto-renew is wired and monitored."],
                        ["NIST SC-8", "ISO 27001 A.10.1.2"])
            except Exception:
                pass

    open_risky = [p for p in RISKY_PORTS if _check_port(host, p)]
    if open_risky:
        sev = "critical" if (22 in open_risky or 3389 in open_risky or 445 in open_risky) else "high"
        add(sev, "Risky service ports exposed to the public internet",
            f"Public exposure of {open_risky} on {host} ({ip}).",
            {"host": host, "ip": ip, "open_risky_ports": open_risky},
            ["Restrict SSH (22) to a bastion / VPN.",
             "Replace public RDP (3389) with a Zero-Trust remote-access tool.",
             "Move SMB (445), database ports (1433, 3306, 5432, 27017, 6379, 9200), and management ports behind a firewall or private subnet.",
             "Use the Sentinel Stacks Hardening Kit Terraform to redefine the security group with a deny-by-default posture."],
            ["CIS Controls 4.4", "CIS Controls 4.5", "NIST SC-7", "ISO 27001 A.13.1.1"])

    if parsed.scheme == "http":
        add("high", "Plain HTTP origin in use",
            f"{host} is served over plain HTTP. Credentials and session tokens can be intercepted.",
            {"host": host, "scheme": "http"},
            ["Force HTTPS via 301 redirect at the edge.",
             "Issue a free Let's Encrypt certificate.",
             "Add HSTS with `preload`."],
            ["PCI DSS 4.0 4.2.1", "NIST SC-8", "ISO 27001 A.14.1.2"])

    headers = _http_headers(target_url)
    missing = _missing_security_headers(headers)
    for h, sev in missing.items():
        add(sev, f"Missing security header: {h}",
            f"Response does not include the {h} header. Browsers and frameworks cannot enforce the protection it provides.",
            {"host": host, "header": h},
            [f"Add `{h}` to the web server / CDN response headers.",
             "Use the Sentinel Stacks Hardening Kit YAML for nginx, Apache, CloudFront, Cloudflare, or Vercel."],
            ["OWASP A05:2021", "NIST SI-10", "ISO 27001 A.14.2.5"])

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))

    duration = (_now() - started).total_seconds()
    llm = (
        f"Network Auditor scanned {host} ({ip}) over {target_url}. "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low. "
        f"{'Certificate is expired or missing.' if crit >= 1 else ''}"
        f"{'Risky ports are publicly exposed.' if open_risky else ''}"
        f"{'Several security headers are missing.' if missing else ''}"
        "Recommend the Sentinel Stacks Hardening Kit ZIP to remediate the top 3 findings."
    )

    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {
            "timestamp": _ts(),
            "duration_seconds": round(duration, 2),
            "target": target_url,
            "status": "success" if total == 0 else "partial" if crit == 0 else "failed",
            "error": None
        },
        "summary": {
            "total_findings": total,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": 0
        },
        "findings": findings,
        "metadata": {
            "domain": DOMAIN,
            "subdomain": SUBDOMAIN,
            "sentinel": SENTINEL,
            "tier": TIER,
            "tags": TAGS,
            "llm_summary": llm,
            "risk_score": score
        }
    }

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run({"target": url}), indent=2))
    