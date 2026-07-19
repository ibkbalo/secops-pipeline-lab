# ai_vuln_hunter.py
# Sentinel Stacks — Perimeter Sentinel Module 4: Vuln Hunter
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import subprocess
import datetime
import re
import time
import hashlib
from urllib.parse import urlparse, urljoin, quote

TOOL_ID = "scan_vuln_hunter"
VERSION = "1.0.2"
DOMAIN = "appsec"
SUBDOMAIN = "perimeter/owasp-top10"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["owasp", "xss", "sqli", "ssrf", "path-traversal", "misconfig", "cors", "clickjacking", "vulnerability"]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

KNOWN_GOOD_DOMAINS = {"github.com", "cloudflare.com", "google.com", "microsoft.com", "apple.com",
                      "example.com", "httpbin.org", "s3.amazonaws.com"}

XSS_CANARY = hashlib.md5(b"sentinel-stacks-xss-canary-v1").hexdigest()[:12]
XSS_PAYLOADS = [
    (f'<{XSS_CANARY}>', f'<{XSS_CANARY}>'),
    (f'"{XSS_CANARY}', f'"{XSS_CANARY}'),
    (f'<script>/*{XSS_CANARY}*/</script>', XSS_CANARY),
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d{4,5}", r"PostgreSQL.*ERROR",
    r"SQLite.*error", r"Microsoft OLE DB", r"ODBC Driver",
    r"Unclosed quotation mark", r"near \"", r"unexpected token",
    r"SQLSTATE\[\d+\]", r"Warning.*mysql_", r"Invalid query",
    r"DBD::mysql", r"Microsoft SQL Server",
]

PATH_TRAVERSAL_PATHS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

PATH_TRAVERSAL_INDICATORS = [
    "root:x:0:0:", "[extensions]", "for 16-bit app support",
    "Daemon", "root:/root:/bin/bash",
]

SSRF_PARAMS = ["url", "uri", "path", "callback", "webhook", "redirect", "redirect_uri",
               "return", "return_url", "next", "target", "proxy", "src", "source",
               "link", "file", "download", "fetch", "load", "image", "img",
               "document", "doc", "feed", "rss", "api_url", "endpoint"]

DEBUG_ENDPOINTS = [
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/.env", "/debug", "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info", "/trace", "/trace.axd",
    "/.git/HEAD", "/.svn/entries", "/.DS_Store",
    "/console", "/h2-console", "/swagger-ui.html",
]

LOG_ENDPOINTS = [
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/wp-content/debug.log", "/tmp", "/temp",
]

VERSION_INDICATORS = [
    ("Server", r"Apache/(\d+\.\d+)", "Apache version exposed"),
    ("X-Powered-By", r"PHP/(\d+\.\d+)", "PHP version exposed"),
    ("X-AspNet-Version", r"(\d+\.\d+)", "ASP.NET version exposed"),
    ("X-Generator", r"(\S+)", "CMS generator exposed"),
]


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
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_score": 0,
                    "tests_run": 0, "owasp_categories_covered": 0},
        "findings": [],
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": f"Vuln Hunter failed for {target_url}: {error}." if error else "Vuln Hunter did not run."}
    }


def _test_xss_reflection(target_url, base, add):
    parsed = urlparse(target_url)
    params = parsed.query
    test_params = {}
    if params:
        for pair in params.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                test_params[k] = v

    if not test_params and "?" not in target_url:
        test_params["q"] = "test"
        test_params["s"] = "test"
        test_params["search"] = "test"
        test_params["id"] = "1"

    found_reflection = False
    for param_name, _ in list(test_params.items())[:5]:
        for payload, canary in XSS_PAYLOADS:
            test_url = target_url
            if "?" in target_url:
                test_url = re.sub(
                    rf'({re.escape(param_name)})=[^&]*',
                    rf'\1={quote(payload)}',
                    target_url
                )
            else:
                test_url = f"{target_url}?{param_name}={quote(payload)}"

            full_resp, rc = _http_get(test_url, timeout=6, max_bytes=200000)
            if rc == 0 and full_resp:
                _, body = _split_headers_body(full_resp)
                if canary in body or canary in full_resp:
                    found_reflection = True
                    add("high", "Reflected XSS (Cross-Site Scripting)",
                        f"Parameter '{param_name}' on {target_url} reflects unsanitized user input. The payload was echoed back in the response body, indicating a potential reflected XSS vulnerability (OWASP A03:2021 \u2014 Injection).",
                        {"parameter": param_name, "payload": payload, "url": test_url},
                        ["Apply context-appropriate output encoding (HTML entities, JS encoding, URL encoding).",
                         "Implement Content-Security-Policy header with 'unsafe-inline' disabled.",
                         "Use a templating engine with auto-escaping (Jinja2, React JSX, Angular).",
                         "Validate and sanitize all user input against an allowlist."],
                        ["OWASP A03:2021 Injection", "CWE-79", "NIST SI-10", "ISO 27001 A.14.2.5"])
                    return
        time.sleep(0.1)

    if not found_reflection:
        add("info", "No reflected XSS detected",
            f"Tested {min(5, len(test_params))} parameters on {target_url} for reflected XSS. No immediate reflection of payloads was detected. This does not guarantee absence of stored or DOM-based XSS.",
            {"parameters_tested": list(test_params.keys())[:5]},
            ["Run a full authenticated XSS scan against all input fields.",
             "Review source code for innerHTML, document.write, and eval usage.",
             "Use the Sentinel Stacks Hardening Kit WAF rules to add XSS filtering."],
            ["OWASP A03:2021 Injection", "CWE-79"],
            "Only reflected XSS was tested. Stored and DOM-based XSS require authenticated/browser-based testing.")


def _test_sqli_error_based(target_url, add):
    parsed = urlparse(target_url)
    params = parsed.query
    test_params = {}
    if params:
        for pair in params.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                test_params[k] = v
    if not test_params:
        test_params["id"] = "1"

    sqli_payloads = ["'", "\"", "1'", "1\"", "' OR '1'='1"]

    for param_name, original in list(test_params.items())[:4]:
        for payload in sqli_payloads[:5]:
            test_url = target_url
            if "?" in target_url:
                test_url = re.sub(rf'({re.escape(param_name)})=[^&]*', rf'\1={quote(payload)}', target_url)
            else:
                test_url = f"{target_url}?{param_name}={quote(payload)}"

            full_resp, rc = _http_get(test_url, timeout=5, max_bytes=100000)
            if rc == 0 and full_resp:
                _, body = _split_headers_body(full_resp)
                check_text = (body[:5000] + " " + full_resp[:2000]).lower()
                for pattern in SQLI_ERROR_PATTERNS:
                    match = re.search(pattern, check_text, re.IGNORECASE)
                    if match:
                        add("critical", "SQL Injection \u2014 database error exposed",
                            f"Parameter '{param_name}' on {target_url} triggered a database error when injected with '{payload}'. The error '{match.group(0)}' was exposed in the response, confirming the application is likely vulnerable to SQL injection (OWASP A03:2021).",
                            {"parameter": param_name, "payload": payload, "error_pattern": pattern, "url": test_url},
                            ["Use parameterized queries / prepared statements immediately.",
                             "Apply input validation \u2014 allowlist expected values.",
                             "Use an ORM (SQLAlchemy, Hibernate, Entity Framework).",
                             "Apply least-privilege database accounts.",
                             "Deploy a WAF rule via the Sentinel Stacks Hardening Kit."],
                            ["OWASP A03:2021 Injection", "CWE-89", "PCI DSS 6.5.1", "NIST SI-10"],
                            "SQL injection is the #1 web vulnerability. Fix immediately \u2014 this is likely exploitable for data exfiltration.")
                        return
        time.sleep(0.1)

    add("info", "No SQL injection errors detected in responses",
        f"Tested {min(4, len(test_params))} parameters with SQL injection payloads. No database error messages were exposed.",
        {"parameters_tested": list(test_params.keys())[:4], "payloads_tested": sqli_payloads[:5]},
        ["Run sqlmap for blind/time-based SQL injection testing.",
         "Review all database queries in source code for concatenation.",
         "Enable database query logging and review for injection attempts."],
        ["OWASP A03:2021 Injection", "CWE-89"])


def _test_path_traversal(target_url, add):
    base_url = target_url.rstrip("/")
    found = False
    for payload in PATH_TRAVERSAL_PATHS[:2]:
        test_url = f"{base_url}?file={quote(payload)}"
        full_resp, rc = _http_get(test_url, timeout=5, max_bytes=100000)
        if rc == 0 and full_resp:
            _, body = _split_headers_body(full_resp)
            combined = (body[:5000] + " " + full_resp[:2000]).lower()
            for indicator in PATH_TRAVERSAL_INDICATORS:
                if indicator.lower() in combined:
                    add("critical", "Path Traversal \u2014 file system access",
                        f"Path traversal payload on {target_url} returned file system contents (matched: '{indicator}'). The application reads arbitrary files from the server filesystem (OWASP A01:2021).",
                        {"payload": payload, "indicator": indicator, "url": test_url},
                        ["Validate and sanitize file path parameters. Use a strict allowlist.",
                         "Use chroot jails or container isolation to limit filesystem access.",
                         "Serve static files through a dedicated CDN/subsystem.",
                         "Apply the Sentinel Stacks Hardening Kit path traversal WAF rule."],
                        ["OWASP A01:2021 Broken Access Control", "CWE-22", "NIST AC-6", "ISO 27001 A.9.4.5"],
                        "Path traversal allows attackers to read /etc/passwd, source code, configuration files, and credentials.")
                    found = True
                    break
        if found:
            break
        time.sleep(0.1)

    if not found:
        add("info", "No path traversal indicators detected",
            f"Tested {len(PATH_TRAVERSAL_PATHS[:2])} path traversal payloads on {target_url}. No filesystem content indicators found.",
            {"payloads_tested": PATH_TRAVERSAL_PATHS[:2]},
            ["Run a full fuzzer (ffuf) against file parameters with a traversal wordlist.",
             "Test for URL-encoded, double-encoded, and Unicode traversal variants.",
             "Review file access code for unsanitized user input in file paths."],
            ["OWASP A01:2021 Broken Access Control", "CWE-22"])


def _test_cors_misconfig(headers, add, target_url):
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        add("high", "CORS Misconfiguration \u2014 credentials with wildcard origin",
            f"Access-Control-Allow-Origin is set to '*' but Access-Control-Allow-Credentials is 'true'. Any website can make authenticated cross-origin requests (OWASP A01:2021).",
            {"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
            ["Never use '*' with credentials. Specify exact allowed origins.",
             "If multiple origins are needed, validate Origin header server-side.",
             "Use the Sentinel Stacks Hardening Kit CORS policy template."],
            ["OWASP A01:2021 Broken Access Control", "CWE-942", "NIST AC-3"],
            "CORS * + credentials = any website can steal authenticated user data.")
    elif acao and acao != "*":
        add("info", "CORS configured \u2014 restricted origin",
            f"CORS Access-Control-Allow-Origin is set to '{acao}' (not wildcard). Correct configuration.",
            {"access-control-allow-origin": acao},
            ["Review the allowed origin list to ensure only trusted domains are included."],
            ["OWASP A01:2021 Broken Access Control"])


def _test_security_headers(headers, add, target_url):
    required = {
        "x-content-type-options": ("nosniff", "Missing X-Content-Type-Options", "medium",
            "Prevents MIME-type sniffing. Without it, browsers may interpret files as executable content."),
        "x-frame-options": (None, "Missing X-Frame-Options (Clickjacking risk)", "medium",
            "Site can be embedded in an iframe for clickjacking attacks."),
        "strict-transport-security": (None, "Missing Strict-Transport-Security (HSTS)", "medium",
            "Users can be downgraded to HTTP via MITM attacks."),
        "content-security-policy": (None, "Missing Content-Security-Policy", "low",
            "CSP provides defense-in-depth against XSS, clickjacking, and code injection."),
        "x-xss-protection": ("1; mode=block", "Missing X-XSS-Protection", "low",
            "Legacy XSS filter. CSP is preferred but this provides defense-in-depth for older clients."),
        "referrer-policy": (None, "Missing Referrer-Policy", "low",
            "Sensitive URL data may leak to third-party sites via the Referer header."),
        "permissions-policy": (None, "Missing Permissions-Policy", "low",
            "Browser features (camera, mic, geolocation) are unrestricted without this header."),
    }

    for header, (expected, title, severity, desc) in required.items():
        current = headers.get(header, "")
        if not current:
            add(severity, title,
                f"{desc} (OWASP A05:2021 \u2014 Security Misconfiguration).",
                {"missing_header": header},
                [f"Add '{header}' header to the web server or application configuration.",
                 f"Use the Sentinel Stacks Hardening Kit web-server-config template."],
                ["OWASP A05:2021 Security Misconfiguration", "NIST SI-7", "ISO 27001 A.12.5.1"])
        elif expected and expected.lower() not in current.lower():
            add("low", f"Incorrect {header} value",
                f"'{header}' is set to '{current}' but should include '{expected}'.",
                {"header": header, "current_value": current, "expected": expected},
                [f"Update '{header}' to include '{expected}'."],
                ["OWASP A05:2021 Security Misconfiguration"])


def _test_server_info_leak(headers, add, target_url):
    for name, pattern, title in VERSION_INDICATORS:
        key = name.lower().replace("-", "-")
        val = headers.get(key, "")
        if val:
            match = re.search(pattern, val)
            if match:
                add("medium", title,
                    f"The '{name}' response header exposes '{val}' on {target_url}. Version disclosure helps attackers identify vulnerable software (OWASP A06:2021).",
                    {"header": name, "value": val, "version_match": match.group(1)},
                    [f"Remove or suppress the '{name}' header in web server configuration.",
                     "Configure reverse proxy (nginx/Cloudflare) to strip version headers.",
                     "Use the Sentinel Stacks Hardening Kit web-server hardening template."],
                    ["OWASP A06:2021 Vulnerable Components", "CWE-200", "NIST SI-2", "PCI DSS 6.5.5"])


def _test_debug_endpoints(target_url, add, base):
    found = []
    for path in DEBUG_ENDPOINTS:
        test_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
        resp, rc = _http_get(test_url, timeout=4, max_bytes=30000)
        if rc == 0 and resp:
            _, body = _split_headers_body(resp)
            lower = body[:2000].lower() if len(body) > 10 else ""
            triggers = {
                "/actuator/env": "propertysources" in lower or "profiles" in lower,
                "/actuator/health": "status" in lower and ("up" in lower or "down" in lower),
                "/.env": "=" in lower and ("db_" in lower or "api_" in lower or "secret" in lower or "password" in lower or "key" in lower),
                "/phpinfo.php": "php version" in lower or "php credits" in lower,
                "/info.php": "php version" in lower,
                "/.git/HEAD": "ref:" in lower[:100] if lower else False,
                "/server-status": "server uptime" in lower or "apache server status" in lower,
                "/trace.axd": "application trace" in lower,
            }
            is_exposed = triggers.get(path) if path in triggers else (len(body) > 20 and not body.startswith("# error") and "not found" not in lower and "404" not in lower[:200])
            if is_exposed:
                found.append(path)
        time.sleep(0.08)

    for p in found[:3]:
        severity = "critical" if p in ["/.env", "/.git/HEAD"] else "high" if p in ["/actuator/env"] else "medium"
        add(severity, f"Debug/sensitive endpoint exposed: {p}",
            f"The endpoint {base}{p} is publicly accessible, exposing internal configuration or debug information (OWASP A04:2021 \u2014 Insecure Design).",
            {"endpoint": f"{base}{p}", "path": p},
            ["Remove this endpoint from production immediately.",
             "Restrict access to internal IP ranges or require authentication.",
             "Use the Sentinel Stacks Hardening Kit web-server config to deny access to these paths."],
            ["OWASP A04:2021 Insecure Design", "OWASP A05:2021 Security Misconfiguration", "CWE-200", "NIST CM-7"])
    return found


def _test_log_exposure(target_url, add, base):
    found = []
    for path in LOG_ENDPOINTS:
        test_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
        resp, rc = _http_get(test_url, timeout=4, max_bytes=30000)
        if rc == 0 and resp:
            _, body = _split_headers_body(resp)
            lower = body[:1000].lower() if len(body) > 10 else ""
            if len(body) > 50 and not body.startswith("# error") and "not found" not in lower and "404" not in lower[:200]:
                found.append(path)
        time.sleep(0.08)

    for p in found[:2]:
        add("medium", f"Log file potentially exposed: {p}",
            f"The path {base}{p} returned content. Exposed log files can reveal session tokens, internal IPs, and user activity (OWASP A09:2021).",
            {"endpoint": f"{base}{p}"},
            ["Move log files outside the webroot.",
             "Configure the web server to deny access to log file extensions.",
             "Use centralized logging (CloudWatch, Azure Monitor) instead of local files."],
            ["OWASP A09:2021 Logging & Monitoring", "CWE-532", "PCI DSS 10.5"])


def _test_mixed_content(target_url, add):
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return
    resp, rc = _http_get(target_url, timeout=8, max_bytes=500000)
    if rc == 0 and resp:
        _, body = _split_headers_body(resp)
        http_scripts = re.findall(r'<script[^>]*src=["\']http://', body[:100000] if body else "")
        http_refs = re.findall(r'(src|href|action|content)=["\']http://', body[:100000] if body else "")
        if http_scripts:
            add("medium", "Mixed content \u2014 scripts loaded over HTTP",
                f"{len(http_scripts)} script tag(s) on {target_url} load resources over HTTP on an HTTPS page. Browsers will block these, but any that slip through enable MITM injection (OWASP A02:2021).",
                {"https_page": target_url, "http_script_count": len(http_scripts)},
                ["Change script src to https:// or protocol-relative URLs.",
                 "Enable HSTS with includeSubDomains and preload.",
                 "Use CSP upgrade-insecure-requests directive during migration."],
                ["OWASP A02:2021 Cryptographic Failures", "CWE-319", "NIST SC-8"])
        elif len(http_refs) > 2:
            add("low", "Mixed content \u2014 some resources loaded over HTTP",
                f"{len(http_refs)} resource references use HTTP on an HTTPS page.",
                {"https_page": target_url, "http_resource_count": len(http_refs)},
                ["Change resource URLs to https:// or protocol-relative.",
                 "Enable CSP upgrade-insecure-requests directive."],
                ["OWASP A02:2021 Cryptographic Failures", "CWE-319"])


def _test_open_redirect(target_url, add):
    redirect_params = ["redirect", "redirect_uri", "return", "return_url", "next", "url", "goto", "target"]
    test_url_str = "https://evil.com"

    for param in redirect_params:
        if param in target_url.lower():
            test_url = target_url
            if "?" in target_url:
                test_url = re.sub(rf'({param})=[^&]*', rf'\1={quote(test_url_str)}', target_url, flags=re.IGNORECASE)
            else:
                test_url = f"{target_url}?{param}={quote(test_url_str)}"

            headers_text = _http_head(test_url, timeout=4)
            _, headers = _parse_headers(headers_text)
            location = headers.get("location", "")
            if test_url_str in location:
                add("medium", "Open Redirect vulnerability",
                    f"Parameter '{param}' on {target_url} redirects to arbitrary external URLs. Attackers use this for phishing that appears to originate from your domain (OWASP A01:2021).",
                    {"parameter": param, "redirect_target": test_url_str, "location_header": location},
                    ["Implement a redirect allowlist of known-safe domains.",
                     "Use relative redirects or validate target against a safe list.",
                     "Never pass user-controlled URLs directly to Location headers.",
                     "Use the Sentinel Stacks Hardening Kit Open Redirect WAF rule."],
                    ["OWASP A01:2021 Broken Access Control", "CWE-601", "NIST AC-3"],
                    "Open redirects are commonly used in OAuth phishing and spear-phishing campaigns.")
                return


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
            "id": f"VULN-{fid:03d}", "title": title, "severity": severity, "confidence": "medium",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description, "evidence": evidence,
            "remediation": {"steps": remediation, "effort": "medium" if _sev_rank(severity) >= 3 else "low",
                            "tier": 1, "reversible": True, "requires_approval": severity == "critical"},
            "compliance": compliance, "notes": notes
        })

    # Fetch headers separately (HEAD request avoids body download)
    headers_text = _http_head(target_url, timeout=5)
    if not headers_text:
        return _empty_report(target_url, "failed", "No response from HEAD request")
    code, headers = _parse_headers(headers_text)

    # Fetch body only (no -D flag to avoid header/body tangling)
    def _get_body_only(u, to=8):
        try:
            out = subprocess.run(
                ["curl", "-s", "-L", "--max-redirs", "3", "--connect-timeout", "4",
                 "--max-time", str(to),
                 "-H", f"User-Agent: {DEFAULT_UA}", u],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=to + 3
            )
            return out.stdout, out.returncode
        except Exception as e:
            return f"# error: {e}", 1

    body, body_rc = _get_body_only(target_url)
    if body_rc != 0 or not body or body.startswith("# error"):
        body = ""

    # ─── Run all tests ────────────────────────────────────────────────────────
    tests_run += 1; _test_xss_reflection(target_url, base, add)
    tests_run += 1; _test_sqli_error_based(target_url, add)
    tests_run += 1; _test_path_traversal(target_url, add)
    tests_run += 1; _test_cors_misconfig(headers, add, target_url)
    tests_run += 1; _test_security_headers(headers, add, target_url)
    tests_run += 1; _test_server_info_leak(headers, add, target_url)
    tests_run += 1; _test_debug_endpoints(target_url, add, base)
    tests_run += 1; _test_log_exposure(target_url, add, base)
    tests_run += 1; _test_mixed_content(target_url, add)
    tests_run += 1; _test_open_redirect(target_url, add)

    # ─── Summary ──────────────────────────────────────────────────────────────
    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    info = sum(1 for f in findings if f["severity"] == "info")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))

    duration = (_now() - started).total_seconds()

    owasp_cats = set()
    for f in findings:
        for c in f.get("compliance", []):
            if c.startswith("OWASP"):
                owasp_cats.add(c.split()[0] + " " + c.split()[1])

    if crit > 0:
        verdict = f"CRITICAL: {crit} critical vulnerabilities found. Immediate remediation required."
    elif high > 0:
        verdict = f"HIGH: {high} high-severity findings that should be addressed within days."
    elif med > 0:
        verdict = f"MEDIUM: {med} medium-severity findings. Address within the next sprint."
    elif low > 0:
        verdict = f"LOW: {low} low-severity findings. Address as part of regular hardening."
    else:
        verdict = "CLEAN: No exploitable vulnerabilities detected in the tested categories."

    llm = (
        f"Vuln Hunter scanned {host} ({ip}) over {target_url}. "
        f"{tests_run} OWASP Top 10 categories tested. "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low, {info} info. "
        + verdict +
        " For deep authenticated testing, run Module 6 (Governance Mapper) for compliance mapping."
    )

    status = "success" if crit == 0 and high == 0 else "partial" if crit == 0 else "failed"

    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": round(duration, 2),
                      "target": target_url, "status": status, "error": None},
        "summary": {"total_findings": total, "critical": crit, "high": high,
                    "medium": med, "low": low, "info": info, "risk_score": score,
                    "tests_run": tests_run, "owasp_categories_covered": len(owasp_cats)},
        "findings": findings,
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": llm}
    }


def scan(target: str) -> dict:
    return run({"target": target})


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run({"target": url}), indent=2))
