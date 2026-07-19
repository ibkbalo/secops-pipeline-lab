# ai_identity_guard.py
# Sentinel Stacks — Perimeter Sentinel Module 5: Identity Guard
# Compliance: TOOL_STANDARDS.md v1.0
# Sovereign: runs locally, on customer's Otto device, or in the cloud.

import json
import socket
import subprocess
import datetime
import re
import time
import base64
import hashlib
from urllib.parse import urlparse, urljoin, quote

TOOL_ID = "scan_identity_guard"
VERSION = "1.0.0"
DOMAIN = "iam"
SUBDOMAIN = "perimeter/zero-trust"
SENTINEL = "perimeter"
TIER = 1
TAGS = ["identity", "jwt", "session", "cookies", "authentication", "zero-trust", "oauth", "csrf"]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

KNOWN_GOOD_DOMAINS = {"github.com", "cloudflare.com", "google.com", "microsoft.com", "apple.com",
                      "example.com", "httpbin.org", "s3.amazonaws.com"}

SENSITIVE_PATHS = ["/admin", "/dashboard", "/account", "/settings", "/profile",
                   "/api/admin", "/api/users", "/api/me", "/user", "/users",
                   "/manage", "/console", "/panel", "/cp", "/cms"]

LOGIN_PATHS = ["/login", "/signin", "/auth", "/sign-in", "/logon",
               "/oauth/authorize", "/sso", "/idp", "/saml"]

COMMON_AUTH_COOKIES = [
    "session", "token", "jwt", "auth", "sid", "JSESSIONID", "PHPSESSID",
    "ASP.NET_SessionId", "connect.sid", "laravel_session", "auth_token",
    "access_token", "id_token", "refresh_token", "__session", "cf authorization",
    "Authorization", "Bearer",
]

COMMON_CSRF_COOKIES = [
    "csrf", "xsrf", "_csrf", "XSRF-TOKEN", "csrf_token", "X-CSRF",
    "x-csrf-token", "__RequestVerificationToken",
]

COMMON_CSRF_FIELDS = [
    "csrf", "_csrf", "xsrf", "_token", "csrf_token", "authenticity_token",
    "__RequestVerificationToken", "csrfmiddlewaretoken", "nonce",
]

SENSITIVE_JWT_CLAIMS = [
    "password", "secret", "key", "api_key", "token", "passwd", "pin",
    "credit_card", "ssn", "social_security", "bank", "routing",
]

OAUTH_PARAMS = [
    "client_id", "redirect_uri", "response_type", "scope", "state",
    "code", "grant_type", "code_challenge", "code_challenge_method",
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


def _parse_set_cookies(full_response):
    """Parse all Set-Cookie headers from a full HTTP response (multi-block aware)."""
    cookies = []
    text = full_response.replace("\r\n", "\n")
    for line in text.split("\n"):
        if line.lower().startswith("set-cookie:"):
            cookie_str = line[len("set-cookie:"):].strip()
            cookies.append(_parse_single_cookie(cookie_str))
    return cookies


def _parse_single_cookie(cookie_str):
    parts = cookie_str.split(";")
    result = {"raw": cookie_str}
    for i, part in enumerate(parts):
        part = part.strip()
        if i == 0:
            if "=" in part:
                k, _, v = part.partition("=")
                result["name"] = k.strip()
                result["value"] = v.strip()
            else:
                result["name"] = part
                result["value"] = ""
        else:
            attr = part.lower()
            if attr == "httponly":
                result["httponly"] = True
            elif attr == "secure":
                result["secure"] = True
            elif attr.startswith("samesite"):
                val = attr.split("=", 1)[1].strip() if "=" in attr else "lax"
                result["samesite"] = val
            elif attr.startswith("max-age"):
                try:
                    result["max_age"] = int(attr.split("=", 1)[1].strip())
                except Exception:
                    pass
            elif attr.startswith("expires"):
                result["expires"] = part[7:].strip()
            elif attr.startswith("domain"):
                result["domain"] = attr.split("=", 1)[1].strip() if "=" in attr else ""
            elif attr.startswith("path"):
                result["path"] = attr.split("=", 1)[1].strip() if "=" in attr else ""
    return result


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
                     "llm_summary": f"Identity Guard failed for {target_url}: {error}." if error else "Identity Guard did not run."}
    }


# ═══════════════════════════════════════════════════════════════════════════════
# JWT DECODING
# ═══════════════════════════════════════════════════════════════════════════════

def _b64url_decode(data):
    """Decode base64url-encoded string, with padding fix."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return json.loads(base64.b64decode(data).decode("utf-8"))
    except Exception:
        return None


def _detect_jwts(text):
    """Find JWT-like tokens in text. Returns list of (token, header, payload)."""
    jwt_re = re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)?)')
    tokens = []
    seen = set()
    for match in jwt_re.finditer(text):
        token = match.group(1)
        token_hash = token[:40]
        if token_hash in seen:
            continue
        seen.add(token_hash)
        parts = token.split(".")
        if len(parts) < 2:
            continue
        header = _b64url_decode(parts[0])
        payload = _b64url_decode(parts[1])
        tokens.append((token, header, payload, len(parts) >= 3 and bool(parts[2])))
    return tokens


def _analyze_jwt(token, header, payload, has_signature):
    issues = []
    if header is None:
        return [("invalid", "JWT with unparseable header")]
    alg = header.get("alg", "").lower()

    # alg: none
    if alg == "none":
        issues.append(("critical", "JWT uses 'alg: none' — accepts unsigned tokens"))
    # alg: HS256 with potential weak secret
    if alg == "hs256":
        issues.append(("low", "JWT uses HS256 (symmetric) — ensure secret is not guessable"))
    # No algorithm specified
    if not alg:
        issues.append(("medium", "JWT missing 'alg' claim — implementation may default unsafely"))

    if payload is None:
        issues.append(("invalid", "JWT with unparseable payload"))
        return issues

    # Check expiry
    exp = payload.get("exp")
    if exp:
        try:
            exp_ts = int(exp)
            now_ts = int(time.time())
            if exp_ts < now_ts:
                issues.append(("low", f"JWT expired at {datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).isoformat()}"))
            elif exp_ts - now_ts > 315360000:
                issues.append(("low", "JWT expiry exceeds 10 years — tokens should have short lifetimes"))
        except (ValueError, TypeError):
            pass
    else:
        issues.append(("medium", "JWT has no 'exp' claim — token never expires"))

    # Check issued-at
    iat = payload.get("iat")
    if iat:
        try:
            if int(iat) > int(time.time()) + 300:
                issues.append(("low", "JWT 'iat' claim is in the future — possible clock skew or misconfiguration"))
        except (ValueError, TypeError):
            pass

    # Check not-before
    nbf = payload.get("nbf")
    if nbf:
        try:
            if int(nbf) > int(time.time()) + 300:
                issues.append(("low", "JWT 'nbf' claim is in the future — token not yet valid"))
        except (ValueError, TypeError):
            pass

    # Missing signature
    if not has_signature:
        issues.append(("high", "JWT has no signature — anyone can forge this token"))

    # Sensitive claims
    for claim in SENSITIVE_JWT_CLAIMS:
        if claim in payload:
            issues.append(("high", f"JWT payload contains sensitive claim '{claim}'"))

    # Missing issuer
    if not payload.get("iss"):
        issues.append(("low", "JWT missing 'iss' (issuer) — token accepted from any issuer"))

    # Missing audience
    if not payload.get("aud"):
        issues.append(("low", "JWT missing 'aud' (audience) — token accepted by any service"))

    # Missing subject
    if not payload.get("sub"):
        issues.append(("low", "JWT missing 'sub' (subject) — identity not explicitly declared"))

    return issues


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def _test_cookie_security(full_response, add, target_url, is_https):
    cookies = _parse_set_cookies(full_response)
    for c in cookies:
        name = c.get("name", "unknown")
        name_lower = name.lower()

        # Only flag auth/session cookies (skip analytics, tracking, prefs)
        is_auth_cookie = any(ac in name_lower for ac in COMMON_AUTH_COOKIES)
        is_auth_cookie = is_auth_cookie or any(kw in name_lower for kw in ["session", "sess", "auth", "token", "login", "jwt"])
        if not is_auth_cookie:
            continue

        issues = []
        if not c.get("secure") and is_https:
            issues.append("missing 'Secure' flag")
        if not c.get("httponly"):
            issues.append("missing 'HttpOnly' flag")
        if not c.get("samesite"):
            issues.append("missing 'SameSite' attribute")
        elif c.get("samesite", "").lower() == "none" and not c.get("secure"):
            issues.append("SameSite=None requires Secure flag")

        if issues:
            add("medium", f"Insecure session cookie: {name}",
                f"Cookie '{name}' set by {target_url} has: {', '.join(issues)}. "
                "Without these protections, cookies are vulnerable to XSS exfiltration (HttpOnly), MITM interception (Secure), and cross-site request forgery (SameSite).",
                {"cookie_name": name, "issues": issues, "cookie_props": {k: v for k, v in c.items() if k != "raw"}},
                ["Set HttpOnly; Secure; SameSite=Lax on all session cookies.",
                 "Configure the framework's session middleware (Express: cookie.secure, Django: SESSION_COOKIE_SECURE).",
                 "Use the Sentinel Stacks Hardening Kit cookie security template."],
                ["OWASP A07:2021 Identification Failures", "CWE-614", "CWE-1004", "NIST AC-12", "PCI DSS 6.5.10"])
            break


def _test_jwt_detection(full_response, body, add, target_url, headers):
    all_text = full_response + body + json.dumps({k: headers.get(k, "") for k in ["authorization", "cookie", "set-cookie"]})
    jwts = _detect_jwts(all_text)

    if not jwts:
        add("info", "No JWT tokens detected in response",
            f"No JSON Web Tokens found in headers, cookies, or response body of {target_url}.",
            {"source": "full_response_scan"},
            ["If the application uses JWTs, ensure they are not leaked in URLs or error messages.",
             "Tokens should only appear in Authorization headers or HttpOnly cookies."],
            ["OWASP A07:2021 Identification Failures", "CWE-312", "NIST IA-5"])
        return None

    for token, header, payload, has_sig in jwts:
        issues = _analyze_jwt(token, header, payload, has_sig)
        if not issues:
            continue
        worst_sev = "low"
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "invalid": "info"}
        for sev, _ in issues:
            if sev_map.get(sev, "info") == "critical":
                worst_sev = "critical"
                break
            elif sev_map.get(sev, "info") == "high" and worst_sev not in ("critical",):
                worst_sev = "high"
            elif sev_map.get(sev, "info") == "medium" and worst_sev not in ("critical", "high"):
                worst_sev = "medium"

        issue_descs = [f"[{s}] {d}" for s, d in issues]
        add(worst_sev, f"JWT security issues detected",
            f"A JWT found in {target_url} has {len(issues)} security concern(s): {'; '.join(issue_descs)}.",
            {"jwt_preview": token[:20] + "..." if len(token) > 20 else token[:20],
             "header": header, "payload_keys": list(payload.keys()) if payload else [],
             "issues": issues},
            ["Use RS256 (asymmetric) instead of HS256 for distributed systems.",
             "Set short expiry times (15 min access, 1 hour refresh).",
             "Never store sensitive data (passwords, keys) in JWT payloads.",
             "Validate iss, aud, and exp on every request.",
             "Use the Sentinel Stacks JWT Gateway Hardened template."],
            ["OWASP A07:2021 Identification Failures", "OWASP A01:2021 Broken Access Control",
             "CWE-347", "CWE-613", "NIST IA-5"])

    return jwts


def _test_auth_header_audit(headers, add, target_url, is_https):
    auth = headers.get("authorization", "")
    www_auth = headers.get("www-authenticate", "")

    if www_auth:
        www_lower = www_auth.lower()
        if "basic" in www_lower and not is_https:
            add("high", "Basic Authentication offered without HTTPS",
                f"{target_url} returns WWW-Authenticate: {www_auth}. Basic Auth sends credentials in base64 (not encrypted) — "
                "over plain HTTP this is plaintext credential leakage (OWASP A02:2021).",
                {"header": "WWW-Authenticate", "value": www_auth},
                ["Redirect all HTTP traffic to HTTPS immediately.",
                 "Enable HSTS with preload to prevent downgrade attacks.",
                 "Replace Basic Auth with token-based authentication (JWT/OAuth)."],
                ["OWASP A02:2021 Cryptographic Failures", "CWE-319", "NIST SC-8", "PCI DSS 4.1"])

    if not auth and not www_auth:
        add("info", "No authentication header detected on main page",
            f"The homepage of {target_url} returns no Authorization or WWW-Authenticate header. "
            "This is expected for public pages, but ensure authenticated endpoints enforce auth.",
            {"checked_headers": ["authorization", "www-authenticate"]},
            ["Verify that all authenticated endpoints require valid Authorization headers.",
             "Enforce authentication via a gateway/reverse proxy for all /api and /admin paths."],
            ["OWASP A01:2021 Broken Access Control", "NIST AC-3"])


def _test_session_in_url(target_url, full_response, body, add, headers):
    parsed = urlparse(target_url)
    query = parsed.query
    suspicious = []
    sensitive_names = ["token", "session", "jwt", "auth", "key", "secret", "password", "passwd",
                       "access_token", "id_token", "refresh_token", "api_key", "apikey", "bearer"]

    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.lower() in sensitive_names and len(v) > 8:
                suspicious.append((k, v[:20] + "..." if len(v) > 20 else v))

    # Also check body for links with tokens in URL
    if body:
        for sn in sensitive_names:
            pattern = rf'href=["\'][^"\']*\b{sn}=([^&\s"\']+)'
            for match in re.finditer(pattern, body[:50000], re.IGNORECASE):
                suspicious.append((sn, match.group(1)[:20]))

    if suspicious:
        for param, val in suspicious[:3]:
            add("high", f"Session token leaked in URL: {param}",
                f"The parameter '{param}' in {target_url} carries what appears to be a session token: {val}. "
                "Tokens in URLs are logged by proxies, servers, and browsers, and leak via Referer headers to third parties (OWASP A04:2021).",
                {"parameter": param, "token_preview": val},
                ["Move authentication tokens to HttpOnly Secure cookies or Authorization headers.",
                 "Use POST for authentication requests instead of GET with query parameters.",
                 "Configure the web server to strip sensitive query parameters from access logs."],
                ["OWASP A04:2021 Insecure Design", "CWE-598", "NIST IA-5", "PCI DSS 3.4"])
            break


def _test_cors_credentials(headers, add, target_url):
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acac.lower() == "true":
        if acao == "*":
            add("high", "CORS: Allow-Credentials with wildcard origin",
                f"{target_url} returns Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *. "
                "Browsers will reject this combination, but any intermediary that doesn't will expose credentialed requests to any origin (OWASP A05:2021).",
                {"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                ["Never use wildcard origin with credentials.",
                 "Whitelist specific trusted origins.",
                 "Validate Origin header server-side against an allowlist."],
                ["OWASP A05:2021 Security Misconfiguration", "CWE-942", "NIST SC-8"])
        elif acao and not acao.startswith(target_url.split("/")[2].split(":")[0]):
            add("medium", "CORS: Credentials allowed for external origin",
                f"{target_url} allows credentialed requests from '{acao}', which differs from the target origin. "
                "This may be intentional for multi-domain setups, but verify the origin is trusted.",
                {"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                ["Review the CORS origin allowlist to ensure only trusted origins are permitted.",
                 "Never allow credentials for origins you don't fully control."],
                ["OWASP A05:2021 Security Misconfiguration", "CWE-942"])


def _test_csrf_protection(body, full_response, add, target_url, headers):
    if not body or len(body) < 100:
        return

    # Find forms
    forms = re.findall(r'<form[^>]*>', body[:100000], re.IGNORECASE)
    login_forms = [f for f in forms if re.search(r'(login|signin|auth|password)', f, re.IGNORECASE)]

    if not login_forms:
        return

    # Check Set-Cookie headers for CSRF cookies
    cookies = _parse_set_cookies(full_response)
    cookie_names = {c.get("name", "").lower() for c in cookies}
    has_csrf_cookie = any(csrf in cookie_names for csrf in COMMON_CSRF_COOKIES)

    # Check for CSRF hidden fields in forms
    has_csrf_field = False
    for form in login_forms[:3]:
        form_end = body.find("</form>", body.find(form) + len(form))
        if form_end == -1:
            form_end = body.find("</form>", body.find(form) + len(form))
        form_content = body[body.find(form):form_end] if form_end > 0 else form
        for csrf_field in COMMON_CSRF_FIELDS:
            if re.search(rf'name=["\']{csrf_field}["\']', form_content, re.IGNORECASE):
                has_csrf_field = True
                break
        if re.search(r'<meta[^>]+name=["\']csrf', form_content, re.IGNORECASE):
            has_csrf_field = True

    if not has_csrf_cookie and not has_csrf_field and login_forms:
        add("medium", "Login form without CSRF protection detected",
            f"A login form on {target_url} was found without a CSRF token (hidden field or cookie). "
            "Without CSRF protection, attackers can forge login requests from malicious sites, potentially logging users into attacker-controlled accounts (OWASP A01:2021).",
            {"form_count": len(login_forms), "form_previews": [f[:120] for f in login_forms[:2]]},
            ["Add CSRF tokens to all state-changing forms (login, logout, account changes).",
             "Use the framework's built-in CSRF protection (Django middleware, Express csurf, Laravel VerifyCsrfToken).",
             "Implement SameSite=Lax or Strict on session cookies as defense-in-depth."],
            ["OWASP A01:2021 Broken Access Control", "CWE-352", "NIST AC-3"])


def _test_login_over_https(target_url, body, is_https, add):
    if is_https:
        return
    if not body or len(body) < 100:
        return
    forms = re.findall(r'<form[^>]*>', body[:100000], re.IGNORECASE)
    login_forms = [f for f in forms if re.search(r'(login|signin|auth|password)', f, re.IGNORECASE)]
    if login_forms:
        action = ""
        for f in login_forms:
            m = re.search(r'action=["\']([^"\']+)', f)
            if m:
                action = m.group(1)
                break
        action_url = urljoin(target_url, action) if action else target_url
        if action_url.startswith("http://"):
            add("critical", "Login form submits credentials over plain HTTP",
                f"A login form on {target_url} posts to {action_url} over HTTP. "
                "Credentials are transmitted in plaintext, visible to anyone on the network path (OWASP A02:2021).",
                {"form_action": action_url, "form_preview": login_forms[0][:150]},
                ["Serve the login page exclusively over HTTPS.",
                 "Set the form action to https://.",
                 "Enable HSTS with includeSubDomains and preload.",
                 "Redirect all HTTP traffic to HTTPS at the web server level."],
                ["OWASP A02:2021 Cryptographic Failures", "CWE-319", "NIST SC-8", "PCI DSS 4.1"])


def _test_bearer_exposure(body, add, target_url):
    if not body:
        return
    bearer_re = re.compile(r'(?:Bearer|bearer)\s+([A-Za-z0-9_\-\.]{20,})')
    matches = bearer_re.findall(body[:100000])
    if matches:
        token_preview = matches[0][:20] + "..." if len(matches[0]) > 20 else matches[0]
        add("high", f"Bearer token exposed in response body",
            f"A Bearer token ({token_preview}) was found in the HTML/JS body of {target_url}. "
            "Tokens embedded in page content can be extracted by XSS, browser extensions, or third-party scripts (OWASP A07:2021).",
            {"token_preview": token_preview, "match_count": len(matches)},
            ["Store tokens exclusively in HttpOnly Secure cookies or in-memory (closure variable, not localStorage).",
             "Never embed access tokens in HTML templates or inline JavaScript.",
             "Use the Token Handler pattern (BFF — Backend For Frontend) to keep tokens server-side."],
            ["OWASP A07:2021 Identification Failures", "CWE-312", "NIST IA-5"])


def _test_cache_auth_pages(headers, add, target_url, has_auth_cookie):
    if not has_auth_cookie:
        return
    cc = headers.get("cache-control", "").lower()
    pragma = headers.get("pragma", "").lower()
    if "private" not in cc and "no-store" not in cc and "no-cache" not in cc and "no-cache" not in pragma:
        add("medium", "Authenticated page missing Cache-Control restrictions",
            f"Response from {target_url} (which sets authentication cookies) lacks Cache-Control: no-store/private. "
            "Authenticated pages may be cached by browsers or intermediate proxies, exposing user data to others on shared machines (OWASP A04:2021).",
            {"cache-control": headers.get("cache-control", "(missing)"),
             "auth_cookies_detected": True},
            ["Add 'Cache-Control: no-store, no-cache, must-revalidate, private' to all authenticated responses.",
             "Set 'Pragma: no-cache' for legacy browser support.",
             "Configure this at the framework middleware level for consistent enforcement."],
            ["OWASP A04:2021 Insecure Design", "CWE-525", "NIST SC-8"])


def _test_oauth_endpoint_security(target_url, add, base):
    oauth_paths = [
        "/.well-known/openid-configuration",
        "/oauth2/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/openid-configuration",
    ]
    for path in oauth_paths:
        test_url = f"{base}{path}"
        resp, rc = _http_get(test_url, timeout=5, max_bytes=100000)
        if rc != 0 or not resp or resp.startswith("# error"):
            continue
        _, resp_headers = _parse_headers(resp)
        _, body = _split_headers_body(resp)
        if not body or len(body) < 20:
            continue
        try:
            oidc_config = json.loads(body)
        except Exception:
            continue

        issuer = oidc_config.get("issuer", "")
        if issuer and not issuer.startswith("https://"):
            add("medium", "OIDC issuer uses HTTP",
                f"The OpenID Connect issuer at {test_url} declares '{issuer}' (non-HTTPS). "
                "Tokens and authorization codes may be transmitted in plaintext.",
                {"oidc_endpoint": test_url, "issuer": issuer},
                ["Configure the OIDC provider to use HTTPS for the issuer URL.",
                 "Ensure all OAuth/OIDC endpoints (authorization, token, userinfo) use HTTPS."],
                ["OWASP A02:2021 Cryptographic Failures", "CWE-319"])

        # Check response_types_supported for implicit flow
        rts = oidc_config.get("response_types_supported", [])
        if "token" in str(rts) or "id_token token" in str(rts):
            add("low", "OIDC provider supports implicit flow",
                f"The OIDC provider at {test_url} supports response types that return tokens in the URL fragment: {rts}. "
                "The implicit flow is deprecated in OAuth 2.1 due to token leakage risks.",
                {"oidc_endpoint": test_url, "response_types_supported": rts},
                ["Migrate to Authorization Code flow with PKCE.",
                 "Disable implicit grant type in the OIDC provider configuration."],
                ["OWASP A07:2021 Identification Failures", "CWE-312"])

        # Check grant_types
        gts = oidc_config.get("grant_types_supported", [])
        if "password" in str(gts):
            add("medium", "OIDC provider supports Resource Owner Password grant",
                f"The OIDC provider supports the 'password' grant type (ROPC). This requires the client to handle user credentials directly — deprecated in OAuth 2.1.",
                {"oidc_endpoint": test_url, "grant_types_supported": gts},
                ["Disable the password grant type.",
                 "Use Authorization Code + PKCE for all user-facing flows."],
                ["OWASP A07:2021 Identification Failures", "CWE-287"])
        break


def _test_rate_limiting_indicators(target_url, headers, add):
    """Check for presence of rate-limiting headers (or lack thereof)."""
    rl_headers = [
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
        "retry-after",
    ]
    found = any(headers.get(h, "") for h in rl_headers)
    if not found:
        # Quick test: make 3 rapid requests and see if we get 429
        blocked = False
        for _ in range(3):
            _, rc = _http_get(target_url, timeout=4, max_bytes=10000)
            if rc != 0:
                blocked = True
                break
            time.sleep(0.3)

        add("low" if not blocked else "info", "No rate-limiting headers detected",
            f"{target_url} does not expose rate-limit headers (X-RateLimit-*, Retry-After). "
            "Without rate limiting, the application is susceptible to credential stuffing, brute force, and API scraping (OWASP A04:2021)."
            + (f" | Rapid request test did not trigger 429." if not blocked else " | Rapid request test triggered blocking."),
            {"rate_limit_headers_found": False, "rapid_test_blocked": blocked},
            ["Implement rate limiting at the API gateway or web server (nginx limit_req, Cloudflare Rate Limiting).",
             "Add X-RateLimit-* headers so consumers can self-throttle.",
             "Set account-specific rate limits on login endpoints to prevent credential stuffing."],
            ["OWASP A04:2021 Insecure Design", "OWASP A07:2021 Identification Failures", "NIST AC-7"])


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
            "id": f"IDENT-{fid:03d}", "title": title, "severity": severity, "confidence": "medium",
            "resource": {"type": "public_url", "id": target_url, "region": "global", "host": host, "ip": ip},
            "description": description, "evidence": evidence,
            "remediation": {"steps": remediation, "effort": "medium" if _sev_rank(severity) >= 3 else "low",
                            "tier": 1, "reversible": True, "requires_approval": severity == "critical"},
            "compliance": compliance, "notes": notes
        })

    # ─── Fetch full response (headers + body) for cookie/JWT analysis ─────────
    full_resp, full_rc = _http_get(target_url, timeout=10, no_size_limit=True)
    if full_rc != 0 or not full_resp or full_resp.startswith("# error"):
        return _empty_report(target_url, "failed", "No response from HTTP GET")

    code, headers = _parse_headers(full_resp)
    _, body = _split_headers_body(full_resp)
    if body.startswith("# error"):
        body = ""

    # ─── Run all tests ────────────────────────────────────────────────────────
    tests_run += 1; has_jwts = _test_jwt_detection(full_resp, body, add, target_url, headers)
    tests_run += 1; _test_cookie_security(full_resp, add, target_url, is_https)
    tests_run += 1; _test_auth_header_audit(headers, add, target_url, is_https)
    tests_run += 1; _test_session_in_url(target_url, full_resp, body, add, headers)
    tests_run += 1; _test_cors_credentials(headers, add, target_url)
    tests_run += 1; _test_csrf_protection(body, full_resp, add, target_url, headers)

    has_auth_cookie = any(
        ac.lower() in c.get("name", "").lower()
        for c in _parse_set_cookies(full_resp)
        for ac in COMMON_AUTH_COOKIES
    )
    tests_run += 1; _test_cache_auth_pages(headers, add, target_url, has_auth_cookie)
    tests_run += 1; _test_login_over_https(target_url, body, is_https, add)
    tests_run += 1; _test_bearer_exposure(body, add, target_url)
    tests_run += 1; _test_oauth_endpoint_security(target_url, add, base)
    tests_run += 1; _test_rate_limiting_indicators(target_url, headers, add)

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
        verdict = f"CRITICAL: {crit} critical identity vulnerabilities found. Immediate remediation required."
    elif high > 0:
        verdict = f"HIGH: {high} high-severity identity findings that should be addressed within days."
    elif med > 0:
        verdict = f"MEDIUM: {med} medium-severity identity findings. Address within the next sprint."
    elif low > 0:
        verdict = f"LOW: {low} low-severity identity findings. Address as part of regular hardening."
    else:
        verdict = "CLEAN: No exploitable identity vulnerabilities detected."

    llm = (
        f"Identity Guard scanned {host} ({ip}) over {target_url}. "
        f"{tests_run} identity and zero-trust tests run. "
        f"Risk Score {score}/100. {crit} critical, {high} high, {med} medium, {low} low, {info} info. "
        + verdict +
        " For deep authenticated identity testing, run Module 6 (Governance Mapper) for compliance mapping."
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
