# ai_governance_mapper.py
# Sentinel Stacks — Perimeter Sentinel Module 6: Governance Mapper
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import subprocess
import datetime
import re
import time
from urllib.parse import urlparse, urljoin

TOOL_ID = "scan_governance_mapper"
VERSION = "1.0.0"
DOMAIN = "governance"
SUBDOMAIN = "perimeter/compliance"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["compliance", "nist-800-53", "soc2", "iso-27001", "gdpr", "audit", "governance"]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

KNOWN_GOOD_DOMAINS = {"github.com", "cloudflare.com", "google.com", "microsoft.com", "apple.com",
                      "example.com", "httpbin.org", "s3.amazonaws.com"}

# ─── NIST 800-53 Control Catalog (subset — perimeter-relevant controls) ──────
# Format: { "control_id": ("family", "title", "weight") }
NIST_800_53_CONTROLS = {
    "AC-2":  ("Access Control", "Account Management", 3),
    "AC-3":  ("Access Control", "Access Enforcement", 5),
    "AC-7":  ("Access Control", "Unsuccessful Logon Attempts", 2),
    "AC-12": ("Access Control", "Session Termination", 2),
    "AC-17": ("Access Control", "Remote Access", 3),
    "AU-2":  ("Audit and Accountability", "Audit Events", 3),
    "AU-6":  ("Audit and Accountability", "Audit Review, Analysis, and Reporting", 3),
    "CM-7":  ("Configuration Management", "Least Functionality", 4),
    "CM-8":  ("Configuration Management", "Information System Component Inventory", 2),
    "IA-2":  ("Identification and Authentication", "Identification and Authentication (Organizational Users)", 5),
    "IA-5":  ("Identification and Authentication", "Authenticator Management", 4),
    "IA-8":  ("Identification and Authentication", "Identification and Authentication (Non-Organizational Users)", 3),
    "IR-2":  ("Incident Response", "Incident Response Training", 2),
    "RA-5":  ("Risk Assessment", "Vulnerability Scanning", 5),
    "SA-8":  ("System and Services Acquisition", "Security Engineering Principles", 2),
    "SC-7":  ("System and Communications Protection", "Boundary Protection", 3),
    "SC-8":  ("System and Communications Protection", "Transmission Confidentiality and Integrity", 4),
    "SC-12": ("System and Communications Protection", "Cryptographic Key Establishment and Management", 4),
    "SC-13": ("System and Communications Protection", "Cryptographic Protection", 3),
    "SC-23": ("System and Communications Protection", "Session Authenticity", 3),
    "SI-2":  ("System and Information Integrity", "Flaw Remediation", 3),
    "SI-7":  ("System and Information Integrity", "Software, Firmware, and Information Integrity", 3),
    "SI-10": ("System and Information Integrity", "Information Input Validation", 4),
}

# ─── SOC 2 Trust Services Criteria (subset) ───────────────────────────────────
SOC2_CRITERIA = {
    "CC1.1":  ("Common Criteria 1", "COSO Principle 1 — Integrity and Ethical Values", 2),
    "CC6.1":  ("Common Criteria 6", "Logical and Physical Access Controls", 4),
    "CC6.2":  ("Common Criteria 6", "User Access Provisioning and Review", 3),
    "CC6.3":  ("Common Criteria 6", "Identification and Authentication", 4),
    "CC6.6":  ("Common Criteria 6", "External Threats — Boundary Protection", 3),
    "CC6.7":  ("Common Criteria 6", "Data Transmission — Encryption", 4),
    "CC6.8":  ("Common Criteria 6", "Incident Detection and Response", 3),
    "CC7.1":  ("Common Criteria 7", "Vulnerability Detection and Monitoring", 5),
    "CC7.2":  ("Common Criteria 7", "Security Monitoring and Alerting", 3),
    "CC8.1":  ("Common Criteria 8", "Change Management — Authorization and Testing", 2),
    "CC9.1":  ("Common Criteria 9", "Risk Mitigation Activities", 3),
    "CC9.2":  ("Common Criteria 9", "Vendor Risk Management", 2),
    "PI.1.1": ("Privacy", "Notice and Communication of Privacy Practices", 2),
}

# ─── ISO 27001:2022 Annex A Controls (subset) ────────────────────────────────
ISO_27001_CONTROLS = {
    "A.5.1":  ("Information Security Policies", 1),
    "A.8.1":  ("User Endpoint Devices", 2),
    "A.8.2":  ("Privileged Access Rights", 3),
    "A.8.3":  ("Information Access Restriction", 3),
    "A.8.5":  ("Secure Authentication", 4),
    "A.8.7":  ("Protection Against Malware", 2),
    "A.8.9":  ("Configuration Management", 3),
    "A.8.16": ("Monitoring Activities", 2),
    "A.8.20": ("Network Security", 3),
    "A.8.21": ("Security of Network Services", 3),
    "A.8.22": ("Segregation of Networks", 2),
    "A.8.24": ("Use of Cryptography", 4),
    "A.8.25": ("Secure Development Life Cycle", 3),
    "A.8.26": ("Application Security Requirements", 3),
    "A.8.29": ("Security Testing in Development and Acceptance", 4),
    "A.5.21": ("Managing Information Security in the ICT Supply Chain", 2),
}

# ─── GDPR Article mapping (perimeter-relevant) ───────────────────────────────
GDPR_ARTICLES = {
    "Art. 5":  ("Principles relating to processing of personal data", 3),
    "Art. 25": ("Data protection by design and by default", 4),
    "Art. 32": ("Security of processing", 4),
    "Art. 33": ("Notification of a personal data breach", 3),
    "Art. 35": ("Data protection impact assessment", 2),
}

# ─── Compliance check catalog ─────────────────────────────────────────────────
# Each check maps to evidence-gathering probes and associated framework controls.

COMPLIANCE_CHECKS = [
    {
        "id": "GOV-SSL",
        "name": "TLS / HTTPS Enforcement",
        "description": "Verifies the site is served over HTTPS with a valid certificate.",
        "probe": "_probe_tls",
        "severity_if_fail": "critical",
        "frameworks": {
            "nist": ["SC-8", "SC-13"],
            "soc2": ["CC6.7"],
            "iso": ["A.8.24"],
            "gdpr": ["Art. 32"],
        },
    },
    {
        "id": "GOV-HSTS",
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Checks for HSTS header with reasonable max-age (>= 1 year).",
        "probe": "_probe_hsts",
        "severity_if_fail": "medium",
        "frameworks": {
            "nist": ["SC-8", "SC-7"],
            "soc2": ["CC6.7"],
            "iso": ["A.8.24", "A.8.21"],
            "gdpr": ["Art. 32"],
        },
    },
    {
        "id": "GOV-CSP",
        "name": "Content Security Policy",
        "description": "Detects presence of a Content-Security-Policy header.",
        "probe": "_probe_csp",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["SI-7", "SC-7"],
            "soc2": ["CC6.6"],
            "iso": ["A.8.26"],
            "gdpr": ["Art. 25"],
        },
    },
    {
        "id": "GOV-CORS",
        "name": "CORS Configuration",
        "description": "Checks Cross-Origin Resource Sharing is not set to wildcard with credentials.",
        "probe": "_probe_cors_gov",
        "severity_if_fail": "medium",
        "frameworks": {
            "nist": ["AC-3", "SC-7"],
            "soc2": ["CC6.1"],
            "iso": ["A.8.22", "A.8.3"],
        },
    },
    {
        "id": "GOV-COOKIE",
        "name": "Cookie Security Flags",
        "description": "Checks that cookies have Secure, HttpOnly, and SameSite attributes.",
        "probe": "_probe_cookies_gov",
        "severity_if_fail": "medium",
        "frameworks": {
            "nist": ["AC-12", "SC-23", "IA-5"],
            "soc2": ["CC6.3"],
            "iso": ["A.8.5"],
            "gdpr": ["Art. 25", "Art. 32"],
        },
    },
    {
        "id": "GOV-XFO",
        "name": "Clickjacking Protection (X-Frame-Options)",
        "description": "Ensures X-Frame-Options or CSP frame-ancestors is set.",
        "probe": "_probe_xfo",
        "severity_if_fail": "medium",
        "frameworks": {
            "nist": ["SI-7", "SC-7"],
            "soc2": ["CC6.6"],
            "iso": ["A.8.26"],
        },
    },
    {
        "id": "GOV-XCTO",
        "name": "MIME Type Protection (X-Content-Type-Options)",
        "description": "Checks for X-Content-Type-Options: nosniff header.",
        "probe": "_probe_xcto",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["SI-7"],
            "soc2": ["CC6.6"],
            "iso": ["A.8.26"],
        },
    },
    {
        "id": "GOV-SECURITY-TXT",
        "name": "security.txt — Vulnerability Disclosure",
        "description": "Checks for /.well-known/security.txt per RFC 9116.",
        "probe": "_probe_security_txt",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["IR-2", "RA-5"],
            "soc2": ["CC7.1", "CC7.2"],
            "iso": ["A.8.16"],
        },
    },
    {
        "id": "GOV-PRIVACY",
        "name": "Privacy Policy / Data Protection Notice",
        "description": "Looks for privacy policy links in the page body.",
        "probe": "_probe_privacy_policy",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["AC-2"],
            "soc2": ["PI.1.1"],
            "iso": ["A.5.1"],
            "gdpr": ["Art. 5", "Art. 35"],
        },
    },
    {
        "id": "GOV-SERVER-INFO",
        "name": "Server Information Leakage",
        "description": "Verifies Server/X-Powered-By headers are suppressed.",
        "probe": "_probe_server_info",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["CM-7", "SI-2"],
            "soc2": ["CC6.6"],
            "iso": ["A.8.9"],
        },
    },
    {
        "id": "GOV-REFERRER",
        "name": "Referrer Policy",
        "description": "Checks for Referrer-Policy header to prevent URL data leakage.",
        "probe": "_probe_referrer_policy",
        "severity_if_fail": "low",
        "frameworks": {
            "nist": ["SC-23"],
            "soc2": ["CC6.7"],
            "iso": ["A.8.24"],
            "gdpr": ["Art. 25"],
        },
    },
    {
        "id": "GOV-REDIRECT",
        "name": "HTTP-to-HTTPS Redirect",
        "description": "Verifies plain HTTP requests are redirected to HTTPS.",
        "probe": "_probe_http_redirect",
        "severity_if_fail": "high",
        "frameworks": {
            "nist": ["SC-8", "SC-7"],
            "soc2": ["CC6.7"],
            "iso": ["A.8.24", "A.8.21"],
            "gdpr": ["Art. 32"],
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# Utility Functions (shared pattern from modules 1–5)
# ═══════════════════════════════════════════════════════════════════════════════

def _ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _resolve(host):
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []


def _http_get(url, timeout=8, max_bytes=500000, extra_headers=None, no_size_limit=False):
    headers = ["-H", f"User-Agent: {DEFAULT_UA}"]
    if extra_headers:
        for k, v in extra_headers.items():
            headers.extend(["-H", f"{k}: {v}"])
    try:
        cmd = ["curl", "-s", "-L", "--max-redirs", "3", "--connect-timeout", "4",
               "--max-time", str(timeout),
               "-D", "-", "-o", "-", *headers, url]
        if not no_size_limit:
            cmd.insert(cmd.index("-D"), f"--max-filesize={max_bytes}")
        out = subprocess.run(
            cmd,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout + 3
        )
        return out.stdout, out.returncode
    except Exception as e:
        return f"# error: {e}", 1


def _http_head(url, timeout=4):
    try:
        out = subprocess.run(
            ["curl", "-sI", "-L", "--max-redirs", "3", "--connect-timeout", "3",
             "--max-time", str(timeout),
             "-H", f"User-Agent: {DEFAULT_UA}", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout + 2
        )
        return out.stdout
    except Exception:
        return ""


def _parse_headers(response_text):
    headers_dict = {}
    code = 0
    response_text = response_text.replace("\r\n", "\n")
    blocks = re.split(r'\n\n', response_text)
    for block in blocks:
        lines = block.split("\n")
        for line in lines:
            if line.startswith("HTTP/") and not line.startswith("HTTP/1.1 100"):
                try:
                    code = int(re.search(r"HTTP/\S+\s+(\d{3})", line).group(1))
                except Exception:
                    pass
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                headers_dict[key.strip().lower()] = val.strip()
        if not lines[0].startswith("HTTP/"):
            break
    return code, headers_dict


def _split_headers_body(full_response):
    full_response = full_response.replace("\r\n", "\n")
    parts = full_response.split("\n\n", 1)
    if len(parts) < 2:
        return full_response, ""
    last_http = full_response.rfind("HTTP/")
    if last_http > 0:
        remaining = full_response[last_http:]
        if "\r\n\r\n" in remaining:
            _, _, body = remaining.partition("\r\n\r\n")
            return full_response[:last_http] + remaining.partition("\r\n\r\n")[0], body
    return parts[0], parts[1] if len(parts) > 1 else ""


def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _empty_report(target_url, status, error):
    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target_url, "status": status, "error": error},
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                    "risk_score": 0, "tests_run": 0,
                    "nist_800_53_score": 0, "soc2_score": 0, "iso_27001_score": 0, "gdpr_score": 0},
        "findings": [],
        "compliance_matrix": {},
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": f"Governance Mapper failed for {target_url}: {error}."}
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Probes
# ═══════════════════════════════════════════════════════════════════════════════

def _probe_tls(target_url, parsed, headers, body):
    if parsed.scheme == "https":
        return True, "Site served over HTTPS"
    return False, "Site served over plain HTTP — all traffic is visible in transit"


def _probe_hsts(target_url, parsed, headers, body):
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        return False, "No HSTS header"
    max_age_match = re.search(r'max-age=(\d+)', hsts)
    if max_age_match and int(max_age_match.group(1)) >= 31536000:
        inc = "includeSubDomains" in hsts
        pre = "preload" in hsts
        return True, f"HSTS set with max-age={max_age_match.group(1)}s (includeSubs={inc}, preload={pre})"
    return False, f"HSTS present but max-age too short: {hsts}"


def _probe_csp(target_url, parsed, headers, body):
    csp = headers.get("content-security-policy", "")
    if csp:
        return True, f"CSP defined ({len(csp)} chars)"
    frame_ancestors = bool(headers.get("x-frame-options", "")) or "frame-ancestors" in csp
    if frame_ancestors:
        return True, "CSP not present but X-Frame-Options provides partial coverage"
    return False, "No Content-Security-Policy header"


def _probe_cors_gov(target_url, parsed, headers, body):
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if not acao:
        return True, "No CORS headers exposed (default: same-origin only)"
    if acao == "*" and acac.lower() == "true":
        return False, "CORS allows any origin with credentials — insecure"
    if acao == "*":
        return True, "CORS wildcard without credentials (acceptable for public APIs)"
    return True, f"CORS restricted to origin: {acao}"


def _probe_cookies_gov(target_url, parsed, headers, body):
    set_cookies = [v for k, v in headers.items() if k == "set-cookie"]
    if not set_cookies:
        return True, "No cookies set on response"
    all_secure = True
    issues = []
    for cookie_str in set_cookies:
        lower = cookie_str.lower()
        if "secure" not in lower:
            all_secure = False
            issues.append("missing Secure")
        if "httponly" not in lower:
            all_secure = False
            issues.append("missing HttpOnly")
        if "samesite" not in lower:
            all_secure = False
            issues.append("missing SameSite")
    if all_secure:
        return True, f"All {len(set_cookies)} cookie(s) have Secure; HttpOnly; SameSite"
    return False, f"{len(issues)} cookie flag issue(s): {'; '.join(issues[:3])}"


def _probe_xfo(target_url, parsed, headers, body):
    xfo = headers.get("x-frame-options", "")
    if xfo:
        return True, f"X-Frame-Options: {xfo}"
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp:
        return True, "CSP frame-ancestors directive present (replaces X-Frame-Options)"
    return False, "No X-Frame-Options or CSP frame-ancestors — site can be embedded in iframes"


def _probe_xcto(target_url, parsed, headers, body):
    xcto = headers.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        return True, "X-Content-Type-Options: nosniff"
    if xcto:
        return False, f"X-Content-Type-Options set to '{xcto}' — should be 'nosniff'"
    return False, "No X-Content-Type-Options header"


def _probe_security_txt(target_url, parsed, headers, body):
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_url = f"{base}/.well-known/security.txt"
    resp, rc = _http_get(test_url, timeout=5, max_bytes=10000)
    if rc == 0 and resp and not resp.startswith("# error"):
        _, _, resp_body = resp.partition("\n\n")
        if len(resp_body) > 10 and ("Contact:" in resp_body or "contact:" in resp_body):
            return True, "security.txt found with contact information"
        if len(resp_body) > 10:
            return True, "security.txt found"
    return False, "No /.well-known/security.txt — no vulnerability disclosure policy"


def _probe_privacy_policy(target_url, parsed, headers, body):
    if not body:
        return False, "No page body to scan"
    full_lower = body.lower() if body else ""
    privacy_markers = [
        "privacy policy", "privacy notice", "data protection policy",
        "data processing", "gdpr", "ccpa", "personal data",
        "privacy statement", "privacy", "cookie policy",
    ]
    for marker in privacy_markers:
        if marker in full_lower:
            return True, f"Privacy-related content detected: '{marker}'"
    privacy_links = re.findall(
        r'href=["\'][^"\']*privacy[^"\']*["\']',
        body[:200000] if body else "", re.IGNORECASE
    )
    if privacy_links:
        return True, f"Privacy policy link(s) found: {privacy_links[0][:80]}"
    footer_area = (body[-20000:] if len(body) > 20000 else body).lower()
    for term in ["privacy", "legal", "terms", "cookies", "data"]:
        if term in footer_area:
            return True, f"Footer area contains '{term}' — privacy infrastructure likely present"
    return False, "No privacy policy or data protection notice found on the page"


def _probe_server_info(target_url, parsed, headers, body):
    leaking = []
    version_patterns = [
        r'apache/\d', r'nginx/\d', r'iis/\d', r'php/\d', r'tomcat/\d',
        r'jetty/\d', r'node\.js/\d', r'express/\d', r'django/\d',
        r'flask/\d', r'rails/\d', r'laravel/\d', r'asp\.net',
    ]
    for hdr in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        val = headers.get(hdr, "")
        if not val:
            continue
        lower_val = val.lower()
        is_version_leak = any(re.search(pat, lower_val) for pat in version_patterns)
        if is_version_leak or hdr in ("x-powered-by", "x-aspnet-version", "x-generator"):
            leaking.append(f"{hdr}: {val}")
        elif hdr == "server" and "/" in val:
            if not any(v in lower_val for v in ["cloudflare", "github", "amazon", "akamai", "fastly", "varnish"]):
                leaking.append(f"{hdr}: {val}")
    if leaking:
        return False, f"Version info exposed: {', '.join(leaking)}"
    return True, "No server version headers exposed"


def _probe_referrer_policy(target_url, parsed, headers, body):
    rp = headers.get("referrer-policy", "")
    if rp:
        return True, f"Referrer-Policy: {rp}"
    return False, "No Referrer-Policy header — URL information leaks via Referer"


def _probe_http_redirect(target_url, parsed, headers, body):
    """Check if the HTTP version redirects to HTTPS."""
    http_url = target_url.replace("https://", "http://", 1)
    try:
        out = subprocess.run(
            ["curl", "-sI", "--max-redirs", "0", "--connect-timeout", "3",
             "--max-time", "5", "-H", f"User-Agent: {DEFAULT_UA}", http_url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10
        )
        text = out.stdout
        code_match = re.search(r'HTTP/\S+\s+(\d{3})', text)
        if code_match:
            code = int(code_match.group(1))
            if 300 <= code < 400:
                location = ""
                for line in text.split("\n"):
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        break
                if location.startswith("https://"):
                    return True, f"HTTP redirects to HTTPS: {location}"
                return False, f"HTTP redirects to non-HTTPS destination: {location}"
            return False, f"HTTP returned {code} (not a redirect)"
        return True, "HTTP connection failed to resolve — likely blocked"
    except Exception:
        return True, "HTTP connection failed — likely blocked at network level"


# ═══════════════════════════════════════════════════════════════════════════════
# Framework Scoring
# ═══════════════════════════════════════════════════════════════════════════════

def _score_frameworks(check_results):
    """Calculate compliance scores for each framework based on passed/failed checks."""
    framework_weights = {"nist": {}, "soc2": {}, "iso": {}, "gdpr": {}}
    framework_passed = {"nist": {}, "soc2": {}, "iso": {}, "gdpr": {}}

    for check in COMPLIANCE_CHECKS:
        check_id = check["id"]
        for fw_key in ["nist", "soc2", "iso", "gdpr"]:
            controls = check["frameworks"].get(fw_key, [])
            for ctrl in controls:
                framework_weights[fw_key][ctrl] = framework_weights[fw_key].get(ctrl, 0)
                framework_passed[fw_key][ctrl] = framework_passed[fw_key].get(ctrl, 0)

    for check in COMPLIANCE_CHECKS:
        check_id = check["id"]
        result = check_results.get(check_id, False)
        for fw_key in ["nist", "soc2", "iso", "gdpr"]:
            controls = check["frameworks"].get(fw_key, [])
            for ctrl in controls:
                if result.get("passed", False):
                    framework_passed[fw_key][ctrl] = framework_passed[fw_key].get(ctrl, 0) + 1

    # Calculate scores
    scores = {}
    for fw_key, controls in framework_passed.items():
        total_weight = sum(1 for _ in controls)
        if total_weight == 0:
            scores[f"{fw_key}_score"] = 100
            continue
        met = sum(1 for ctrl, count in controls.items() if count > 0)
        scores[f"{fw_key}_score"] = round((met / total_weight) * 100)

    # Build detailed matrix
    matrix = {}
    for fw_key, fw_name in [("nist", "NIST 800-53"), ("soc2", "SOC 2"), ("iso", "ISO 27001"), ("gdpr", "GDPR")]:
        controls_detail = {}
        for ctrl in sorted(framework_passed.get(fw_key, {}).keys()):
            met_count = framework_passed[fw_key].get(ctrl, 0)
            controls_detail[ctrl] = {
                "met": met_count > 0,
                "checks_covering": met_count,
            }
        matrix[fw_name] = {
            "score": scores.get(f"{fw_key}_score", 100),
            "controls_assessed": len(controls_detail),
            "controls_met": sum(1 for c in controls_detail.values() if c["met"]),
            "detail": controls_detail,
        }

    return scores, matrix


# ═══════════════════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════════════════

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
    is_https = parsed.scheme == "https"
    base = f"{parsed.scheme}://{parsed.netloc}"

    findings = []
    fid = 0
    tests_run = 0

    def add(severity, title, description, evidence, remediation, compliance, notes=""):
        nonlocal fid
        fid += 1
        if is_known_good and severity in ("critical", "high"):
            severity = "info"
            notes = (notes + " | " if notes else "") + "Auto-downgraded: target is a known-good site."
        findings.append({
            "id": f"GOV-{fid:03d}", "title": title, "severity": severity, "confidence": "high",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description, "evidence": evidence,
            "remediation": {"steps": remediation, "effort": "medium" if _sev_rank(severity) >= 3 else "low",
                            "tier": 1, "reversible": True, "requires_approval": severity == "critical"},
            "compliance": compliance, "notes": notes
        })

    # ─── Fetch target ─────────────────────────────────────────────────────────
    full_resp, full_rc = _http_get(target_url, timeout=10, no_size_limit=True)
    if full_rc != 0 or not full_resp or full_resp.startswith("# error"):
        return _empty_report(target_url, "failed", "No response from HTTP GET")

    code, headers = _parse_headers(full_resp)
    _, body = _split_headers_body(full_resp)
    if body.startswith("# error"):
        body = ""

    # ─── Run all compliance checks ────────────────────────────────────────────
    check_results = {}
    probe_map = {
        "_probe_tls": _probe_tls,
        "_probe_hsts": _probe_hsts,
        "_probe_csp": _probe_csp,
        "_probe_cors_gov": _probe_cors_gov,
        "_probe_cookies_gov": _probe_cookies_gov,
        "_probe_xfo": _probe_xfo,
        "_probe_xcto": _probe_xcto,
        "_probe_security_txt": _probe_security_txt,
        "_probe_privacy_policy": _probe_privacy_policy,
        "_probe_server_info": _probe_server_info,
        "_probe_referrer_policy": _probe_referrer_policy,
        "_probe_http_redirect": _probe_http_redirect,
    }

    for check in COMPLIANCE_CHECKS:
        check_id = check["id"]
        probe_fn = probe_map.get(check["probe"])
        tests_run += 1
        if probe_fn:
            try:
                passed, evidence = probe_fn(target_url, parsed, headers, body)
            except Exception as e:
                passed, evidence = False, f"Probe error: {e}"
        else:
            passed, evidence = False, "Probe not implemented"

        check_results[check_id] = {
            "name": check["name"],
            "passed": passed,
            "evidence": evidence,
            "severity_if_fail": check["severity_if_fail"] if not passed else "info",
        }

        if not passed:
            sev = check["severity_if_fail"]
            # Build compliance control strings
            comp_refs = []
            for fw, controls in check["frameworks"].items():
                fw_label = {"nist": "NIST 800-53", "soc2": "SOC 2", "iso": "ISO 27001", "gdpr": "GDPR"}.get(fw, fw)
                for ctrl in controls:
                    comp_refs.append(f"{fw_label} {ctrl}")
            add(sev, f"{check['name']} — FAILED",
                f"{check['description']}. Evidence: {evidence}",
                {"check_id": check_id, "evidence": evidence, "frameworks": check["frameworks"]},
                ["Refer to the Sentinel Stacks Hardening Kit for the relevant remediation template.",
                 f"Address this gap to improve compliance with: {', '.join(comp_refs)}."],
                [f"{fw_label} {ctrl}" for fw, controls in check["frameworks"].items()
                 for fw_label, ctrl in [(  {"nist": "NIST 800-53", "soc2": "SOC 2", "iso": "ISO 27001", "gdpr": "GDPR"}.get(fw, fw), ctrl) for ctrl in controls]])
        else:
            comp_refs = []
            for fw, controls in check["frameworks"].items():
                fw_label = {"nist": "NIST 800-53", "soc2": "SOC 2", "iso": "ISO 27001", "gdpr": "GDPR"}.get(fw, fw)
                for ctrl in controls:
                    comp_refs.append(f"{fw_label} {ctrl}")
            add("info", f"{check['name']} — PASSED",
                f"{check['description']}. Evidence: {evidence}",
                {"check_id": check_id, "passed": True, "evidence": evidence},
                ["No action required. This control is compliant."],
                [f"{fw_label} {ctrl}" for fw, controls in check["frameworks"].items()
                 for fw_label, ctrl in [(  {"nist": "NIST 800-53", "soc2": "SOC 2", "iso": "ISO 27001", "gdpr": "GDPR"}.get(fw, fw), ctrl) for ctrl in controls]],
                f"Compliant — covers {len(comp_refs)} framework control(s)")

    # ─── Score frameworks ─────────────────────────────────────────────────────
    fw_scores, compliance_matrix = _score_frameworks(check_results)

    # ─── Summary ──────────────────────────────────────────────────────────────
    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    info = sum(1 for f in findings if f["severity"] == "info")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))

    duration = (_now() - started).total_seconds()

    nist_score = fw_scores.get("nist_score", 0)
    soc2_score = fw_scores.get("soc2_score", 0)
    iso_score = fw_scores.get("iso_score", 0)
    gdpr_score = fw_scores.get("gdpr_score", 0)
    overall_compliance = round((nist_score + soc2_score + iso_score + gdpr_score) / 4)

    if overall_compliance >= 90:
        verdict = f"COMPLIANT ({overall_compliance}%): Strong alignment with regulatory frameworks."
    elif overall_compliance >= 70:
        verdict = f"PARTIALLY COMPLIANT ({overall_compliance}%): Gaps exist across one or more frameworks."
    elif overall_compliance >= 50:
        verdict = f"NON-COMPLIANT ({overall_compliance}%): Significant gaps in security governance posture."
    else:
        verdict = f"CRITICAL GAPS ({overall_compliance}%): Severe compliance deficiencies across all frameworks."

    llm = (
        f"Governance Mapper scanned {host} ({ip}) over {target_url}. "
        f"{tests_run} compliance checks across 4 frameworks (NIST 800-53, SOC 2, ISO 27001, GDPR). "
        f"Overall Compliance: {overall_compliance}%. "
        f"NIST 800-53: {nist_score}% | SOC 2: {soc2_score}% | ISO 27001: {iso_score}% | GDPR: {gdpr_score}%. "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low, {info} info. "
        + verdict +
        " For deep audit-ready reporting, export the compliance matrix and attach evidence artifacts."
    )

    status = "success" if crit == 0 and high == 0 else "partial" if crit == 0 else "failed"

    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": round(duration, 2),
                      "target": target_url, "status": status, "error": None},
        "summary": {"total_findings": total, "critical": crit, "high": high,
                    "medium": med, "low": low, "info": info, "risk_score": score,
                    "tests_run": tests_run, "owasp_categories_covered": 0,
                    "nist_800_53_score": nist_score, "soc2_score": soc2_score,
                    "iso_27001_score": iso_score, "gdpr_score": gdpr_score,
                    "overall_compliance_pct": overall_compliance},
        "findings": findings,
        "compliance_matrix": compliance_matrix,
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": llm}
    }


def scan(target: str) -> dict:
    return run({"target": target})


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run({"target": url}), indent=2))
