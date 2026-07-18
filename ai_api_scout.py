# ai_api_scout.py
# Sentinel Stacks — Perimeter Sentinel Module 3: API Scout
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import subprocess
import datetime
import re
import time
from urllib.parse import urlparse, urljoin

TOOL_ID = "scan_public_url_api_scout"
VERSION = "1.0.5"
DOMAIN = "appsec"
SUBDOMAIN = "perimeter/api-discovery"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["api-discovery", "crawl", "admin-panel", "endpoints", "graphql", "swagger"]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

MAX_LIVE_URLS = 60
MAX_LINK_EXTRACT = 50
MAX_GET_PAGES = 5
ADMIN_BODY_MAX_BYTES = 15000
ADMIN_BODY_TIMEOUT = 3

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/login", "/signup", "/register",
    "/api", "/api/", "/api/v1", "/api/v2", "/v1", "/v2",
    "/graphql", "/gql", "/query",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api-docs",
    "/admin", "/wp-admin", "/administrator", "/console", "/manage", "/dashboard",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/health", "/status", "/ping", "/version", "/info",
    "/backup", "/backups", "/old", "/staging", "/test", "/dev",
    "/uploads", "/static", "/assets", "/media",
    "/config", "/configuration", "/settings", "/setup", "/install",
]

SENSITIVE_ENDPOINT_PATTERNS = [
    {"regex": r"/api/v\d+/users?", "severity": "high", "title": "API user endpoint exposed"},
    {"regex": r"/api/v\d+/admin", "severity": "high", "title": "API admin endpoint exposed"},
    {"regex": r"/graphql$", "severity": "medium", "title": "GraphQL endpoint exposed"},
    {"regex": r"/swagger\.(json|yaml)", "severity": "medium", "title": "Swagger/OpenAPI spec exposed"},
    {"regex": r"/openapi\.(json|yaml)", "severity": "medium", "title": "OpenAPI spec exposed"},
    {"regex": r"/actuator", "severity": "high", "title": "Spring Boot Actuator endpoint exposed"},
    {"regex": r"/wp-json/wp/v2/users", "severity": "high", "title": "WordPress user enumeration endpoint exposed"},
    {"regex": r"/\.env$", "severity": "critical", "title": "Environment file exposed via API path"},
]

ADMIN_PATH_PATTERNS = [
    r"/wp-admin", r"/wp-login\.php", r"/administrator",
    r"/admin/login", r"/console/login", r"/manage/login",
    r"/dashboard/login", r"/cpanel", r"/phpmyadmin",
    r"/django-admin", r"/rails/admin", r"/laravel/admin",
]

KNOWN_GOOD_DOMAINS = {"github.com", "cloudflare.com", "google.com", "microsoft.com", "apple.com",
                      "example.com", "httpbin.org", "s3.amazonaws.com"}

NOT_FOUND_STRINGS = [
    "page not found", "not found", "the page you were looking for doesn't exist",
    "no such page", "nothing here", "couldn't find this page",
    "there isn't a github pages site here", "this is not the web page you are looking for",
    "the requested url was not found", "error 404", "404 error",
    "file not found", "url was not found", "doesn't exist",
]

TITLE_NOT_FOUND = ["404", "not found", "page not found", "error 404"]


def _ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _resolve(host):
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []


def _http_head(url, timeout=3):
    try:
        out = subprocess.run(
            ["curl", "-sI", "-L", "--max-redirs", "2", "--connect-timeout", "2",
             "--max-time", str(timeout),
             "-H", f"User-Agent: {DEFAULT_UA}", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout + 2
        )
        code_match = re.search(r"HTTP/\S+\s+(\d{3})", out.stdout)
        return int(code_match.group(1)) if code_match else 0
    except Exception:
        return 0


def _http_get(url, timeout=6, max_bytes=200000):
    try:
        out = subprocess.run(
            ["curl", "-s", "-L", "--max-redirs", "3", "--connect-timeout", "3",
             "--max-time", str(timeout), "--max-filesize", str(max_bytes),
             "-H", f"User-Agent: {DEFAULT_UA}", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout + 3
        )
        return out.stdout, out.returncode
    except Exception as e:
        return f"# error: {e}", 1


def _fetch_admin_body(url):
    try:
        out = subprocess.run(
            ["curl", "-s", "-L", "--max-redirs", "2", "--connect-timeout", "2",
             "--max-time", str(ADMIN_BODY_TIMEOUT),
             "-H", f"User-Agent: {DEFAULT_UA}", url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=ADMIN_BODY_TIMEOUT + 2
        )
        if out.returncode == 0 and out.stdout and not out.stdout.startswith("# error"):
            return out.stdout[:ADMIN_BODY_MAX_BYTES].lower()
    except Exception:
        pass
    return ""


def _is_soft_404(html_sample):
    if not html_sample:
        return False
    # 1. Check <title> for 404 indicators
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_sample, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip().lower()
        for indicator in TITLE_NOT_FOUND:
            if indicator in title:
                return True
    # 2. Strip HTML tags and check visible text for not-found phrases
    text = re.sub(r"<[^>]+>", " ", html_sample)
    text = re.sub(r"\s+", " ", text).strip()
    for indicator in NOT_FOUND_STRINGS:
        if indicator in text:
            return True
    # 3. Positive check: does this look like a REAL admin login panel?
    #    Real admin panels have password fields. No password = not an admin panel.
    if 'type="password"' not in html_sample and "type='password'" not in html_sample:
        if "type=password" not in html_sample:
            return True
    return False


def _extract_links(html, base_url):
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
    srcs = re.findall(r'src=["\']([^"\']+)["\']', html)
    actions = re.findall(r'action=["\']([^"\']+)["\']', html)
    all_links = hrefs + srcs + actions
    found = set()
    base_parsed = urlparse(base_url)
    for link in all_links:
        if link.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full = urljoin(base_url, link)
        parsed = urlparse(full)
        if parsed.netloc == base_parsed.netloc:
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
            if clean:
                found.add(clean)
    return list(found)


def _path_has_admin_indicator(url):
    parsed = urlparse(url)
    path = parsed.path.lower().rstrip("/")
    for pattern in ADMIN_PATH_PATTERNS:
        if re.search(pattern, path):
            return True
    return False


def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _empty_report(target_url, status, error):
    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": 0.0, "target": target_url, "status": status, "error": error},
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_score": 0,
                    "discovered_urls": 0, "live_urls": 0, "api_endpoints": 0, "admin_panels": 0},
        "findings": [],
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL, "tier": TIER, "tags": TAGS,
                     "llm_summary": f"API Scout failed for {target_url}: {error}." if error else "API Scout did not run."}
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
            "id": f"FIND-{fid:03d}", "title": title, "severity": severity, "confidence": "high",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description, "evidence": evidence,
            "remediation": {"steps": remediation, "effort": "low" if _sev_rank(severity) <= 2 else "medium",
                            "tier": 1, "reversible": True, "requires_approval": False},
            "compliance": compliance, "notes": notes
        })

    discovered_urls = set()
    live_urls = []
    base = f"{parsed.scheme}://{parsed.netloc}"
    crawl_queue = [base]
    for path in COMMON_PATHS:
        crawl_queue.append(f"{base}{path}")

    crawled = set()

    # Phase 1: HEAD all common paths + base
    for i, url_to_check in enumerate(crawl_queue):
        if len(live_urls) >= MAX_LIVE_URLS:
            break
        url_norm = url_to_check.rstrip("/")
        if url_norm in crawled:
            continue
        crawled.add(url_norm)

        status = _http_head(url_to_check, timeout=3)
        if 200 <= status < 400:
            live_urls.append({"url": url_norm, "code": status})
            discovered_urls.add(url_norm)
        elif status in (401, 403):
            discovered_urls.add(url_norm)

        if i > 0 and i % 10 == 0:
            time.sleep(0.2)
        else:
            time.sleep(0.05)

    # Phase 2: GET first few live pages for link extraction
    for url_info in live_urls[:MAX_GET_PAGES]:
        if len(live_urls) >= MAX_LIVE_URLS:
            break
        body, rc = _http_get(url_info["url"], timeout=6)
        if rc == 0 and body and not body.startswith("# error"):
            new_links = _extract_links(body, url_info["url"])
            for link in new_links[:MAX_LINK_EXTRACT]:
                if len(live_urls) >= MAX_LIVE_URLS:
                    break
                if link in crawled:
                    continue
                crawled.add(link)
                status = _http_head(link, timeout=2)
                if 200 <= status < 400:
                    live_urls.append({"url": link, "code": status})
                    discovered_urls.add(link)
                time.sleep(0.03)

    # Phase 3: Analyse API endpoints
    api_endpoints = []
    for url_info in live_urls:
        url = url_info["url"]
        for entry in SENSITIVE_ENDPOINT_PATTERNS:
            if re.search(entry["regex"], url, re.IGNORECASE):
                api_endpoints.append({"url": url, "title": entry["title"], "severity": entry["severity"]})
                break

    # Phase 4: Analyse admin panels — with body verification to kill soft 404s
    admin_panels = []
    for url_info in live_urls:
        url = url_info["url"]
        if _path_has_admin_indicator(url):
            body_sample = _fetch_admin_body(url)
            if _is_soft_404(body_sample):
                continue
            admin_panels.append({"url": url})

    # Phase 5: Build findings
    for ep in api_endpoints:
        add(ep["severity"], ep["title"],
            f"{ep['title']} at {ep['url']}. This endpoint may expose sensitive operations, data, or configuration.",
            {"url": ep["url"], "pattern_matched": ep["title"]},
            [f"Require authentication on {ep['url']}.",
             f"If this endpoint is not needed, remove it or move it to an internal network.",
             "Add rate limiting and IP allowlisting to the endpoint.",
             "Use the Sentinel Stacks Hardening Kit API Gateway config to lock down the endpoint."],
            ["OWASP API1:2023", "OWASP API2:2023", "NIST AC-3", "ISO 27001 A.9.4.1"],
            "API endpoints without authentication are a top breach vector per OWASP API Top 10.")

    for panel in admin_panels[:5]:
        already = any(
            f["title"] == "Admin panel publicly accessible" and panel["url"] in str(f.get("evidence", {}).get("url", ""))
            for f in findings
        )
        if not already:
            add("high", "Admin panel publicly accessible",
                f"Admin login panel detected at {panel['url']}. Admin panels should not be reachable from the public internet.",
                {"url": panel["url"]},
                ["Move the admin panel behind a VPN or Zero-Trust gateway.",
                 "Require MFA on all admin accounts.",
                 "Add IP allowlisting to restrict access to known office IPs.",
                 "Use the Sentinel Stacks Hardening Kit to add a WAF rule blocking public access to admin paths."],
                ["CIS Controls 4.4", "NIST AC-3", "ISO 27001 A.9.4.2"],
                "Admin panels on the public internet are the #1 brute-force target.")

    discovered_count = len(discovered_urls)
    live_count = len(live_urls)
    api_count = len(api_endpoints)
    admin_count = len(admin_panels)

    if discovered_count < 3 and live_count < 3:
        add("low", "Limited URL discovery — possible lightweight site or crawl block",
            f"Only {discovered_count} URLs discovered on {host}. The site may be a single-page application, have aggressive crawl blocking, or have a very small footprint.",
            {"host": host, "discovered_urls": discovered_count, "live_urls": live_count},
            ["If the site is an SPA, use the full browser-based scanner for deeper discovery.",
             "Check robots.txt and sitemap.xml for disallowed paths.",
             "Increase crawl depth in the agent configuration."],
            ["OWASP API1:2023"],
            "Not a vulnerability — informational only. The API Scout works best on traditional multi-page sites.")

    if live_count > 20:
        add("info", f"High URL count: {live_count} live endpoints discovered",
            f"{live_count} URLs returned a 2xx/3xx status code on {host}. A large number of publicly reachable endpoints increases the attack surface.",
            {"host": host, "live_url_count": live_count, "discovered_url_count": discovered_count},
            ["Review the full URL list and remove any endpoints not intentionally public.",
             "Ensure every endpoint has a clear authentication and authorization policy.",
             "Run Module 4 (Vuln Hunter) against the top 10 endpoints."],
            ["OWASP API1:2023", "NIST CM-8"],
            "Informational. Large attack surfaces are harder to secure — prioritize reduction.")

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    info = sum(1 for f in findings if f["severity"] == "info")
    total = len(findings)
    score = max(0, 100 - (crit * 25) - (high * 10) - (med * 4) - (low * 1))

    duration = (_now() - started).total_seconds()
    parts = []
    if api_count >= 1:
        parts.append(f"{api_count} sensitive API endpoints discovered.")
    if admin_count >= 1:
        parts.append(f"{admin_count} admin panels publicly accessible.")
    if not parts and info == 0:
        parts.append("No sensitive API endpoints or admin panels detected.")
    elif not parts:
        parts.append("No critical API exposures, but informational findings exist.")
    llm = (
        f"API Scout scanned {host} ({ip}) over {target_url}. "
        f"Discovered {discovered_count} URLs ({live_count} live). "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low, {info} info. "
        + " ".join(parts) +
        " Recommend Module 4 (Vuln Hunter) on the top API endpoints for deeper analysis."
    )

    status = "success" if total == 0 else "partial" if crit == 0 else "failed"

    return {
        "tool_id": TOOL_ID, "version": VERSION,
        "execution": {"timestamp": _ts(), "duration_seconds": round(duration, 2),
                      "target": target_url, "status": status, "error": None},
        "summary": {"total_findings": total, "critical": crit, "high": high,
                    "medium": med, "low": low, "info": info, "risk_score": score,
                    "discovered_urls": discovered_count, "live_urls": live_count,
                    "api_endpoints": api_count, "admin_panels": admin_count},
        "findings": findings,
        "metadata": {"domain": DOMAIN, "subdomain": SUBDOMAIN, "sentinel": SENTINEL,
                     "tier": TIER, "tags": TAGS, "llm_summary": llm}
    }


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run({"target": url}), indent=2))