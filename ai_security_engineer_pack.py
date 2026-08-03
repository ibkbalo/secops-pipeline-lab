# ai_security_engineer_pack.py
# Sentinel Stacks — Security Engineer Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase P1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase P3: Network (NET) + Data exposure (DATA) engines ACTIVE — embedded
#            fixture + optional live wrap of ai_network_auditor / ai_data_scout.
# Phase P4: API (API) + Vuln (VULN) engines ACTIVE — embedded fixture +
#            optional live wrap of ai_api_scout / ai_vuln_hunter.
# Enterprise bar: full senior Security Engineer coverage — not a single-scanner toy.

from __future__ import annotations

import json
import re
import os
import shutil
import subprocess
import sys
import datetime
from pathlib import Path
from typing import Any, Callable

TOOL_ID = "scan_security_engineer_pack"
VERSION = "0.4.0-p4"
DOMAIN = "appsec"
SUBDOMAIN = "security-engineer/pack"
SENTINEL = "perimeter"
TIER = 1
TAGS = [
    "security-engineer",
    "perimeter",
    "multi-engine",
    "network",
    "api",
    "owasp",
    "phishing",
    "email",
    "appsec",
    "enterprise",
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# Ports that should not be internet-facing (aligned with ai_network_auditor.py)
RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
    8080: "HTTP-Alt",
}

PATH_SEVERITY: dict[str, str] = {
    "/.env": "critical",
    "/.git/config": "high",
    "/.git/HEAD": "high",
    "/backup/": "critical",
    "/debug/": "medium",
}

# ── Finding ID scheme (locked) ───────────────────────────────────────────────
# PERIM-{ENGINE}-{NNN}
# ENGINE codes are stable forever; NNN grows without artificial ceilings.
ENGINE_CODES = {
    "network": "NET",
    "data_exposure": "DATA",
    "api": "API",
    "vuln": "VULN",
    "identity": "IDENT",
    "governance": "GOV",
    "phishing": "PHISH",
    "traffic": "TRF",
    "protocol": "PRT",
    "asset": "AST",
}

# ── Backend probes (live tools when installed) ───────────────────────────────


def _which(name: str) -> str | None:
    return shutil.which(name)


def _tool_version(cmd: list[str]) -> str | None:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        out = (p.stdout or p.stderr or "").strip().splitlines()
        return out[0][:200] if out else "present"
    except Exception:
        return None


def detect_backends() -> dict[str, dict[str, Any]]:
    """Discover optional live scanners on PATH. Embedded fixtures always work offline."""
    backends: dict[str, dict[str, Any]] = {}

    for name, eng in (
        ("nuclei", ["vuln", "api"]),
        ("httpx", ["network", "api", "data_exposure"]),
        ("nmap", ["network", "protocol"]),
        ("openssl", ["network"]),
        ("dig", ["network", "phishing"]),
    ):
        p = _which(name)
        backends[name] = {
            "available": bool(p),
            "path": p,
            "version": _tool_version([p, "--version"]) if p else None,
            "engines": eng,
        }

    backends["embedded"] = {
        "available": True,
        "path": "builtin",
        "version": VERSION,
        "engines": list(ENGINE_CODES.keys()),
        "note": "Deterministic offline engine — always on. Live backends extend depth when installed.",
    }
    return backends


# ── Context passed into every engine ─────────────────────────────────────────


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
        self.mode = mode  # mock | live | hybrid
        self.backends = backends
        self.engines_filter = engines_filter
        self._counters: dict[str, int] = {k: 0 for k in ENGINE_CODES}

    def next_id(self, engine_key: str) -> str:
        code = ENGINE_CODES[engine_key]
        self._counters[engine_key] += 1
        return f"PERIM-{code}-{self._counters[engine_key]:03d}"

    def section(self, key: str, default: Any = None) -> Any:
        return self.fixture.get(key, default if default is not None else {})


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _ts() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(
    fid: str,
    title: str,
    severity: str,
    description: str,
    *,
    confidence: str = "high",
    resource: dict | None = None,
    evidence: dict | None = None,
    remediation: dict | None = None,
    compliance: list | None = None,
    engine: str,
    backend: str = "embedded",
) -> dict:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "resource": resource
        or {"type": "perimeter", "id": fid, "engine": engine},
        "description": description,
        "evidence": {
            **(evidence or {}),
            "engine": engine,
            "backend": backend,
            "check_id": fid,
        },
        "remediation": remediation
        or {
            "steps": [
                "Review evidence and suppress only with documented risk acceptance.",
                "Apply the matching hardening kit artifact when available.",
                "Re-run scan_security_engineer_pack to verify the control passes.",
            ],
            "effort": "medium",
        },
        "compliance": compliance
        or [
            "NIST 800-53 SI-2",
            "NIST 800-53 SC-7",
            "SOC 2 CC6.1",
            "ISO 27001 A.14.2.1",
        ],
    }


# ── Engine protocol ──────────────────────────────────────────────────────────
# status:
#   active  — emits real findings this release
#   stub    — registered, executes, returns [] until filled (P2+)
# backend preference: live tool if available else embedded

EngineFn = Callable[[PackContext], list[dict]]


def _engine_network(ctx: PackContext) -> list[dict]:
    """Network perimeter — TLS/DNS/ports; embedded fixture + optional live auditor wrap."""
    findings: list[dict] = []
    net = ctx.section("network") if ctx.fixture else {}

    if net:
        tls_ver = (net.get("tls_version") or "").upper()
        if tls_ver in ("TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2"):
            findings.append(
                _finding(
                    ctx.next_id("network"),
                    f"Deprecated TLS protocol: {tls_ver}",
                    "high",
                    f"Endpoint negotiates {tls_ver}. PCI and modern browsers deprecate TLS 1.0/1.1.",
                    resource={"type": "tls", "id": tls_ver, "engine": "network"},
                    evidence={"tls_version": net.get("tls_version"), "source": "fixture.network.tls_version"},
                    remediation={
                        "steps": [
                            "Disable TLS 1.0/1.1 at load balancer and origin.",
                            "Enable TLS 1.2+ only; test with SSL Labs.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["NIST 800-53 SC-8", "PCI DSS 4.0"],
                    engine="network",
                    backend="embedded",
                )
            )

        if net.get("cert_expired") is True:
            findings.append(
                _finding(
                    ctx.next_id("network"),
                    "TLS certificate expired",
                    "critical",
                    "The presented certificate is expired. Clients will warn or refuse connections.",
                    resource={"type": "tls", "id": "cert_expired", "engine": "network"},
                    evidence={"cert_expired": True, "source": "fixture.network.cert_expired"},
                    remediation={
                        "steps": [
                            "Renew certificate immediately (ACME or CA reissue).",
                            "Automate renewal; alert 30 days before expiry.",
                        ],
                        "effort": "low",
                    },
                    compliance=["NIST 800-53 SC-8"],
                    engine="network",
                    backend="embedded",
                )
            )

        for port in net.get("open_ports") or []:
            try:
                pnum = int(port)
            except (TypeError, ValueError):
                continue
            if pnum not in RISKY_PORTS:
                continue
            svc = RISKY_PORTS[pnum]
            sev = "critical" if pnum in (22, 3306, 3389, 445, 27017, 6379, 1433) else "high"
            if pnum == 8080:
                sev = "medium"
            findings.append(
                _finding(
                    ctx.next_id("network"),
                    f"Risky port open to internet: {pnum}/{svc}",
                    sev,
                    f"Port {pnum} ({svc}) is reachable on the public attack surface.",
                    resource={"type": "port", "id": str(pnum), "engine": "network", "service": svc},
                    evidence={"port": pnum, "service": svc, "source": "fixture.network.open_ports"},
                    remediation={
                        "steps": [
                            f"Close or firewall port {pnum}; restrict to bastion/VPN CIDRs only.",
                            "Move admin services off the public internet.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["NIST 800-53 SC-7", "CIS Network"],
                    engine="network",
                    backend="embedded",
                )
            )

        if net.get("cdn_waf") is False:
            findings.append(
                _finding(
                    ctx.next_id("network"),
                    "No CDN/WAF in front of public endpoint",
                    "medium",
                    "Traffic hits origin directly without edge WAF/CDN DDoS protection.",
                    resource={"type": "edge", "id": "cdn_waf", "engine": "network"},
                    evidence={"cdn_waf": False, "source": "fixture.network.cdn_waf"},
                    remediation={
                        "steps": [
                            "Place a WAF/CDN (Cloudflare, AWS CloudFront+WAF, Azure Front Door) in front.",
                            "Enable bot management and rate limiting.",
                        ],
                        "effort": "medium",
                    },
                    engine="network",
                    backend="embedded",
                )
            )

        return findings

    if ctx.mode == "live" and str(ctx.target).startswith(("http://", "https://")):
        try:
            import ai_network_auditor as na

            rep = na.run({"target": ctx.target, "timeout": 60})
            for f in rep.get("findings") or []:
                findings.append(
                    _finding(
                        ctx.next_id("network"),
                        f.get("title") or "Network finding",
                        _norm_sev(f.get("severity"), "medium"),
                        f.get("description") or "",
                        resource=f.get("resource") or {"type": "network", "engine": "network"},
                        evidence={**(f.get("evidence") or {}), "source": "live.ai_network_auditor"},
                        remediation=f.get("remediation"),
                        compliance=f.get("compliance"),
                        engine="network",
                        backend="live",
                    )
                )
        except Exception:
            pass
    return findings


def _engine_data_exposure(ctx: PackContext) -> list[dict]:
    """Data exposure scout — sensitive paths, public buckets; fixture + live data_scout wrap."""
    findings: list[dict] = []
    data = ctx.section("data_exposure") if ctx.fixture else {}

    if data:
        for path in data.get("paths_found") or []:
            sev = "medium"
            for prefix, psev in PATH_SEVERITY.items():
                if path.startswith(prefix) or prefix.rstrip("/") in path:
                    sev = psev
                    break
            if ".env" in path:
                sev = "critical"
            elif ".git" in path:
                sev = "high"
            elif "backup" in path or ".sql" in path:
                sev = "critical"
            findings.append(
                _finding(
                    ctx.next_id("data_exposure"),
                    f"Sensitive path exposed: {path}",
                    sev,
                    f"Public URL path '{path}' matches data-leak patterns (configs, VCS, backups, debug).",
                    resource={"type": "url_path", "id": path, "engine": "data_exposure"},
                    evidence={"path": path, "source": "fixture.data_exposure.paths_found"},
                    remediation={
                        "steps": [
                            f"Remove or deny public access to '{path}'.",
                            "Rotate any secrets that may have been exposed.",
                            "Add WAF rule blocking sensitive path probes.",
                        ],
                        "effort": "high" if sev == "critical" else "medium",
                    },
                    compliance=["NIST 800-53 SC-28", "OWASP A02", "SOC 2 CC6.1"],
                    engine="data_exposure",
                    backend="embedded",
                )
            )

        for bucket in data.get("s3_public_buckets") or []:
            findings.append(
                _finding(
                    ctx.next_id("data_exposure"),
                    f"Public object storage bucket: {bucket}",
                    "critical",
                    f"Bucket/storage account '{bucket}' allows anonymous or public read.",
                    resource={"type": "storage_bucket", "id": bucket, "engine": "data_exposure"},
                    evidence={"bucket": bucket, "source": "fixture.data_exposure.s3_public_buckets"},
                    remediation={
                        "steps": [
                            "Enable account/block public access settings.",
                            "Audit bucket ACLs and policies; remove public principals.",
                            "Enable access logging and alert on public policy changes.",
                        ],
                        "effort": "high",
                    },
                    compliance=["NIST 800-53 AC-3", "CIS AWS 2.1"],
                    engine="data_exposure",
                    backend="embedded",
                )
            )

        if data.get("robots_disallow_sensitive") is False:
            findings.append(
                _finding(
                    ctx.next_id("data_exposure"),
                    "robots.txt does not disallow sensitive paths",
                    "low",
                    "Crawlers may index admin/backup/debug paths; defense-in-depth gap.",
                    resource={"type": "url_path", "id": "/robots.txt", "engine": "data_exposure"},
                    evidence={
                        "robots_disallow_sensitive": False,
                        "source": "fixture.data_exposure.robots_disallow_sensitive",
                    },
                    remediation={
                        "steps": [
                            "Disallow /admin, /backup, /.git in robots.txt (not a security control alone).",
                            "Ensure sensitive paths require authentication regardless of robots.",
                        ],
                        "effort": "low",
                    },
                    engine="data_exposure",
                    backend="embedded",
                )
            )

        return findings

    if ctx.mode == "live" and str(ctx.target).startswith(("http://", "https://")):
        try:
            import ai_data_scout as ds

            rep = ds.run({"target": ctx.target, "timeout": 60})
            for f in rep.get("findings") or []:
                findings.append(
                    _finding(
                        ctx.next_id("data_exposure"),
                        f.get("title") or "Data exposure finding",
                        _norm_sev(f.get("severity"), "medium"),
                        f.get("description") or "",
                        resource=f.get("resource") or {"type": "data_exposure", "engine": "data_exposure"},
                        evidence={**(f.get("evidence") or {}), "source": "live.ai_data_scout"},
                        remediation=f.get("remediation"),
                        compliance=f.get("compliance"),
                        engine="data_exposure",
                        backend="live",
                    )
                )
        except Exception:
            pass
    return findings


def _engine_api(ctx: PackContext) -> list[dict]:
    """API surface / OpenAPI / admin paths — embedded fixture + optional live api_scout wrap."""
    findings: list[dict] = []
    api = ctx.section("api") if ctx.fixture else {}

    if api:
        if api.get("openapi_exposed") is True:
            findings.append(
                _finding(
                    ctx.next_id("api"),
                    "OpenAPI/Swagger specification exposed",
                    "medium",
                    "Public OpenAPI or Swagger documentation reveals API structure, endpoints, and schemas to attackers.",
                    resource={"type": "api_spec", "id": "openapi", "engine": "api"},
                    evidence={"openapi_exposed": True, "source": "fixture.api.openapi_exposed"},
                    remediation={
                        "steps": [
                            "Remove public Swagger/OpenAPI from production or require authentication.",
                            "Publish API docs on an internal portal or VPN-only route.",
                        ],
                        "effort": "low",
                    },
                    compliance=["OWASP API1:2023", "OWASP API2:2023", "NIST AC-3"],
                    engine="api",
                    backend="embedded",
                )
            )

        for path in api.get("admin_paths") or []:
            sev = "critical" if path.rstrip("/").endswith((".env", "/.env")) else "high"
            findings.append(
                _finding(
                    ctx.next_id("api"),
                    f"Sensitive API/admin path exposed: {path}",
                    sev,
                    f"Path '{path}' is reachable on the public attack surface (admin panel, internal API, or API docs).",
                    resource={"type": "url_path", "id": path, "engine": "api"},
                    evidence={"path": path, "source": "fixture.api.admin_paths"},
                    remediation={
                        "steps": [
                            f"Restrict or remove public access to '{path}'.",
                            "Move admin and internal APIs behind VPN, Zero Trust, or IP allowlisting.",
                            "Require MFA for all admin authentication paths.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP API1:2023", "CIS Controls 4.4", "NIST AC-3"],
                    engine="api",
                    backend="embedded",
                )
            )

        for endpoint in api.get("unauthenticated_endpoints") or []:
            findings.append(
                _finding(
                    ctx.next_id("api"),
                    f"Unauthenticated API endpoint: {endpoint}",
                    "high",
                    f"Endpoint '{endpoint}' may expose data or operations without authentication.",
                    resource={"type": "api_endpoint", "id": endpoint, "engine": "api"},
                    evidence={"endpoint": endpoint, "source": "fixture.api.unauthenticated_endpoints"},
                    remediation={
                        "steps": [
                            f"Require authentication and authorization on '{endpoint}'.",
                            "Add rate limiting and audit logging for sensitive exports.",
                            "Review API gateway policies for anonymous access.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP API1:2023", "OWASP API2:2023", "SOC 2 CC6.1"],
                    engine="api",
                    backend="embedded",
                )
            )

        if api.get("rate_limiting") is False:
            findings.append(
                _finding(
                    ctx.next_id("api"),
                    "No API rate limiting detected",
                    "medium",
                    "Public API endpoints lack rate limiting — brute-force, scraping, and abuse risk.",
                    resource={"type": "api_policy", "id": "rate_limiting", "engine": "api"},
                    evidence={"rate_limiting": False, "source": "fixture.api.rate_limiting"},
                    remediation={
                        "steps": [
                            "Enable rate limiting at API gateway or WAF (per-IP and per-token).",
                            "Add exponential backoff and lockout for auth endpoints.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP API4:2023", "NIST SC-5"],
                    engine="api",
                    backend="embedded",
                )
            )

        return findings

    if ctx.mode == "live" and str(ctx.target).startswith(("http://", "https://")):
        try:
            import ai_api_scout as ap

            rep = ap.run({"target": ctx.target, "timeout": 60})
            for f in rep.get("findings") or []:
                sev = _norm_sev(f.get("severity"), "medium")
                if sev == "info":
                    continue
                findings.append(
                    _finding(
                        ctx.next_id("api"),
                        f.get("title") or "API surface finding",
                        sev,
                        f.get("description") or "",
                        resource=f.get("resource") or {"type": "api", "engine": "api"},
                        evidence={**(f.get("evidence") or {}), "source": "live.ai_api_scout"},
                        remediation=f.get("remediation"),
                        compliance=f.get("compliance"),
                        engine="api",
                        backend="live",
                    )
                )
        except Exception:
            pass
    return findings


_VULN_HEADER_SEVERITY: dict[str, str] = {
    "content-security-policy": "low",
    "x-frame-options": "medium",
    "strict-transport-security": "medium",
    "x-content-type-options": "medium",
    "referrer-policy": "low",
    "permissions-policy": "low",
    "x-xss-protection": "low",
}


def _engine_vuln(ctx: PackContext) -> list[dict]:
    """OWASP Top 10 — embedded fixture + optional live vuln_hunter wrap."""
    findings: list[dict] = []
    vuln = ctx.section("vuln") if ctx.fixture else {}

    if vuln:
        for header in vuln.get("missing_headers") or []:
            hkey = header.strip().lower()
            sev = _VULN_HEADER_SEVERITY.get(hkey, "medium")
            findings.append(
                _finding(
                    ctx.next_id("vuln"),
                    f"Missing security header: {header}",
                    sev,
                    f"Response lacks '{header}' — increases risk of XSS, clickjacking, or transport downgrade (OWASP A05).",
                    resource={"type": "http_header", "id": header, "engine": "vuln"},
                    evidence={"missing_header": header, "source": "fixture.vuln.missing_headers"},
                    remediation={
                        "steps": [
                            f"Add '{header}' to web server or application response headers.",
                            "Use Sentinel Stacks hardening kit web-server templates.",
                        ],
                        "effort": "low",
                    },
                    compliance=["OWASP A05:2021 Security Misconfiguration", "NIST SI-7"],
                    engine="vuln",
                    backend="embedded",
                )
            )

        if vuln.get("xss_reflected") is True:
            findings.append(
                _finding(
                    ctx.next_id("vuln"),
                    "Reflected XSS (Cross-Site Scripting)",
                    "high",
                    "User input is reflected unsanitized in HTTP responses (OWASP A03:2021 Injection).",
                    resource={"type": "web_vuln", "id": "xss_reflected", "engine": "vuln"},
                    evidence={"xss_reflected": True, "source": "fixture.vuln.xss_reflected"},
                    remediation={
                        "steps": [
                            "Apply context-appropriate output encoding on all user-controlled output.",
                            "Deploy Content-Security-Policy with unsafe-inline disabled.",
                            "Use framework auto-escaping (React, Angular, templating engines).",
                        ],
                        "effort": "high",
                    },
                    compliance=["OWASP A03:2021 Injection", "CWE-79", "NIST SI-10"],
                    engine="vuln",
                    backend="embedded",
                )
            )

        if vuln.get("open_redirect") is True:
            findings.append(
                _finding(
                    ctx.next_id("vuln"),
                    "Open Redirect vulnerability",
                    "medium",
                    "Application redirects to arbitrary external URLs — phishing and OAuth abuse vector (OWASP A01).",
                    resource={"type": "web_vuln", "id": "open_redirect", "engine": "vuln"},
                    evidence={"open_redirect": True, "source": "fixture.vuln.open_redirect"},
                    remediation={
                        "steps": [
                            "Validate redirect targets against an allowlist of trusted domains.",
                            "Use relative redirects or signed redirect tokens.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP A01:2021 Broken Access Control", "CWE-601"],
                    engine="vuln",
                    backend="embedded",
                )
            )

        missing_flags = vuln.get("cookie_flags_missing") or []
        if missing_flags:
            findings.append(
                _finding(
                    ctx.next_id("vuln"),
                    "Session cookies missing security flags",
                    "high",
                    f"Cookies lack required flags: {', '.join(missing_flags)}. Session hijacking and CSRF risk.",
                    resource={"type": "cookie", "id": "session_flags", "engine": "vuln"},
                    evidence={
                        "cookie_flags_missing": missing_flags,
                        "source": "fixture.vuln.cookie_flags_missing",
                    },
                    remediation={
                        "steps": [
                            "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on session cookies.",
                            "Rotate session identifiers after login.",
                        ],
                        "effort": "low",
                    },
                    compliance=["OWASP A07:2021 Identification and Authentication Failures", "CWE-614"],
                    engine="vuln",
                    backend="embedded",
                )
            )

        return findings

    if ctx.mode == "live" and str(ctx.target).startswith(("http://", "https://")):
        try:
            import ai_vuln_hunter as vh

            rep = vh.run({"target": ctx.target, "timeout": 90})
            for f in rep.get("findings") or []:
                sev = _norm_sev(f.get("severity"), "medium")
                if sev == "info":
                    continue
                findings.append(
                    _finding(
                        ctx.next_id("vuln"),
                        f.get("title") or "Vulnerability finding",
                        sev,
                        f.get("description") or "",
                        resource=f.get("resource") or {"type": "vuln", "engine": "vuln"},
                        evidence={**(f.get("evidence") or {}), "source": "live.ai_vuln_hunter"},
                        remediation=f.get("remediation"),
                        compliance=f.get("compliance"),
                        engine="vuln",
                        backend="live",
                    )
                )
        except Exception:
            pass
    return findings


def _engine_identity(ctx: PackContext) -> list[dict]:
    """P5: session/JWT/OAuth — wraps ai_identity_guard. P1 stub."""
    _ = ctx
    return []


def _engine_governance(ctx: PackContext) -> list[dict]:
    """P5: headers / compliance mapping — wraps ai_governance_mapper. P1 stub."""
    _ = ctx
    return []


def _norm_sev(sev: str | None, default: str = "high") -> str:
    s = (sev or default).strip().lower()
    if s in ("critical", "crit", "4"):
        return "critical"
    if s in ("high", "3"):
        return "high"
    if s in ("medium", "med", "moderate", "2"):
        return "medium"
    if s in ("low", "1"):
        return "low"
    return "info" if s == "info" else default


def _auth_result_sev(result: str | None) -> str:
    r = (result or "").lower()
    if r in ("fail", "hardfail", "reject"):
        return "critical"
    if r in ("softfail", "neutral", "none", "missing"):
        return "high"
    if r in ("pass", "bestguesspass"):
        return "info"
    return "medium"


def _parse_eml_headers(path: Path) -> dict[str, Any]:
    """Lightweight RFC822 header parse for live .eml analysis (no body HTML render)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    headers: dict[str, list[str]] = {}
    block: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            break
        if line.startswith((" ", "\t")) and block:
            block[-1] += " " + line.strip()
        else:
            block.append(line)
    for h in block:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        headers.setdefault(k.strip().lower(), []).append(v.strip())
    return {
        "from": (headers.get("from") or [""])[0],
        "reply_to": (headers.get("reply-to") or headers.get("reply_to") or [""])[0],
        "return_path": (headers.get("return-path") or headers.get("return_path") or [""])[0],
        "subject": (headers.get("subject") or [""])[0],
        "authentication_results": " ".join(headers.get("authentication-results") or headers.get("authentication_results") or []),
        "path": str(path),
    }


def _engine_phishing(ctx: PackContext) -> list[dict]:
    """Phishing & email security — embedded fixture + optional .eml live parse."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "phishing"),
        ctx.backends,
    )
    phish = ctx.section("phishing") if ctx.fixture else {}

    if phish:
        policy = (phish.get("domain_dmarc_policy") or "").lower()
        if policy in ("none", "", "missing"):
            findings.append(
                _finding(
                    ctx.next_id("phishing"),
                    "Domain DMARC policy not enforced (p=none or missing)",
                    "high",
                    f"Organizational DMARC is '{policy or 'missing'}'. "
                    "Spoofed messages can deliver without aggregate/reject enforcement.",
                    resource={"type": "dns_record", "id": "dmarc", "engine": "phishing"},
                    evidence={
                        "domain_dmarc_policy": phish.get("domain_dmarc_policy"),
                        "source": "fixture.phishing.domain_dmarc_policy",
                    },
                    remediation={
                        "steps": [
                            "Publish DMARC TXT at _dmarc with p=quarantine or p=reject after monitoring.",
                            "Enable rua/ruf reporting; review aggregate reports weekly.",
                            "Align SPF and DKIM before moving to reject.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["NIST 800-53 SI-8", "CIS Email Security", "SOC 2 CC6.7"],
                    engine="phishing",
                    backend="embedded",
                )
            )

        if phish.get("spf_record_present") is False:
            findings.append(
                _finding(
                    ctx.next_id("phishing"),
                    "SPF record not published for sending domain",
                    "high",
                    "No SPF TXT record detected for the domain. Unauthorized senders may pass implicit trust.",
                    resource={"type": "dns_record", "id": "spf", "engine": "phishing"},
                    evidence={"spf_record_present": False, "source": "fixture.phishing.spf_record_present"},
                    remediation={
                        "steps": [
                            "Publish v=spf1 with explicit includes and -all or ~all after validation.",
                            "Inventory all legitimate outbound mail sources (M365, SES, marketing).",
                            "Re-test with scan_security_engineer_pack phishing engine.",
                        ],
                        "effort": "low",
                    },
                    compliance=["NIST 800-53 SI-8", "CIS Email Security"],
                    engine="phishing",
                    backend="embedded",
                )
            )

        if phish.get("dkim_selectors_configured") is False:
            findings.append(
                _finding(
                    ctx.next_id("phishing"),
                    "DKIM selectors not configured",
                    "medium",
                    "DKIM signing appears absent. Recipients cannot cryptographically verify message integrity.",
                    resource={"type": "dns_record", "id": "dkim", "engine": "phishing"},
                    evidence={
                        "dkim_selectors_configured": False,
                        "source": "fixture.phishing.dkim_selectors_configured",
                    },
                    remediation={
                        "steps": [
                            "Enable DKIM signing on the mail platform (M365/Google/SES).",
                            "Publish selector CNAME/TXT records; rotate keys per vendor guidance.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["NIST 800-53 SI-8"],
                    engine="phishing",
                    backend="embedded",
                )
            )

        for sample in phish.get("samples") or []:
            sid = sample.get("fixture_id") or "email-sample"
            display = sample.get("from_display") or ""
            envelope = sample.get("from_envelope") or ""
            reply_to = sample.get("reply_to") or ""
            spf = sample.get("spf_result")
            dkim = sample.get("dkim_result")
            dmarc = sample.get("dmarc_result")
            links = sample.get("suspicious_links") or []

            auth_bad = any(
                str(x).lower() in ("fail", "softfail", "none", "missing", "neutral")
                for x in (spf, dkim, dmarc)
            )
            if auth_bad:
                findings.append(
                    _finding(
                        ctx.next_id("phishing"),
                        f"Email authentication failure: {sid}",
                        "critical" if str(dmarc).lower() in ("fail", "reject") else "high",
                        f"Sample '{sid}' failed auth checks (SPF={spf}, DKIM={dkim}, DMARC={dmarc}). "
                        "Message may be spoofed or forwarded without alignment.",
                        resource={"type": "email_message", "id": sid, "engine": "phishing"},
                        evidence={
                            "fixture_id": sid,
                            "spf_result": spf,
                            "dkim_result": dkim,
                            "dmarc_result": dmarc,
                            "source": "fixture.phishing.samples",
                        },
                        remediation={
                            "steps": [
                                "Quarantine the message; do not click links or open HTML attachments.",
                                "Verify sender via out-of-band channel before acting on financial requests.",
                                "Report to security operations / phishing mailbox.",
                            ],
                            "effort": "low",
                        },
                        compliance=["NIST 800-53 SI-8", "SOC 2 CC6.1"],
                        engine="phishing",
                        backend="embedded",
                    )
                )

            if display and envelope and display.lower() not in envelope.lower():
                findings.append(
                    _finding(
                        ctx.next_id("phishing"),
                        f"Display name / envelope mismatch (possible BEC): {sid}",
                        "critical",
                        f"Friendly From '{display}' does not align with envelope '{envelope}'. "
                        "Classic business-email-compromise impersonation pattern.",
                        resource={"type": "email_message", "id": sid, "engine": "phishing"},
                        evidence={
                            "from_display": display,
                            "from_envelope": envelope,
                            "source": "fixture.phishing.samples",
                        },
                        remediation={
                            "steps": [
                                "Block similar display-name spoofing at the mail gateway.",
                                "Enable external sender banners and anti-BEC policies.",
                                "Train finance/payroll on callback verification for wire requests.",
                            ],
                            "effort": "medium",
                        },
                        compliance=["NIST 800-53 SI-8", "ISO 27001 A.8.23"],
                        engine="phishing",
                        backend="embedded",
                    )
                )

            if sample.get("return_path_mismatch") or (
                reply_to and envelope and reply_to.split("@")[-1] != envelope.split("@")[-1]
            ):
                findings.append(
                    _finding(
                        ctx.next_id("phishing"),
                        f"Reply-To / Return-Path mismatch: {sid}",
                        "high",
                        f"Reply-To '{reply_to}' diverges from envelope domain for '{sid}'. "
                        "Replies may route to an attacker-controlled mailbox.",
                        resource={"type": "email_message", "id": sid, "engine": "phishing"},
                        evidence={
                            "reply_to": reply_to,
                            "from_envelope": envelope,
                            "return_path_mismatch": sample.get("return_path_mismatch"),
                            "source": "fixture.phishing.samples",
                        },
                        remediation={
                            "steps": [
                                "Block or flag messages where Reply-To domain ≠ From domain.",
                                "Review mail flow rules for auto-forward abuse.",
                            ],
                            "effort": "low",
                        },
                        engine="phishing",
                        backend="embedded",
                    )
                )

            for link in links:
                if re.search(r"micros0ft|login-|secure-|verify-|account-", link, re.I) or link.startswith("http://"):
                    findings.append(
                        _finding(
                            ctx.next_id("phishing"),
                            f"Suspicious link in message: {sid}",
                            "critical" if "micros0ft" in link.lower() or link.startswith("http://") else "high",
                            f"Sample '{sid}' contains suspicious URL '{link}' "
                            "(lookalike domain, cleartext HTTP, or credential-harvest pattern).",
                            resource={"type": "url", "id": link, "engine": "phishing"},
                            evidence={"url": link, "fixture_id": sid, "source": "fixture.phishing.samples"},
                            remediation={
                                "steps": [
                                    "Do not visit the URL; submit to URL sandbox if required.",
                                    "Add domain to blocklist; hunt for other recipients.",
                                ],
                                "effort": "low",
                            },
                            engine="phishing",
                            backend="embedded",
                        )
                    )

            if sample.get("urgency_language"):
                findings.append(
                    _finding(
                        ctx.next_id("phishing"),
                        f"Social-engineering urgency language: {sid}",
                        "medium",
                        f"Sample '{sid}' uses urgency cues common in phishing/BEC lures.",
                        resource={"type": "email_message", "id": sid, "engine": "phishing"},
                        evidence={"urgency_language": True, "source": "fixture.phishing.samples"},
                        remediation={
                            "steps": [
                                "Include urgency keywords in mail-gateway phish heuristics.",
                                "Run targeted awareness for finance and exec assistants.",
                            ],
                            "effort": "low",
                        },
                        engine="phishing",
                        backend="embedded",
                    )
                )

            if (sample.get("attachment_type") or "").lower() == "html":
                findings.append(
                    _finding(
                        ctx.next_id("phishing"),
                        f"HTML attachment risk: {sid}",
                        "high",
                        "HTML attachments can host credential forms offline and evade link scanners.",
                        resource={"type": "email_attachment", "id": sid, "engine": "phishing"},
                        evidence={"attachment_type": "html", "source": "fixture.phishing.samples"},
                        remediation={
                            "steps": [
                                "Strip or sandbox HTML attachments at the gateway.",
                                "Block .html/.htm attachments from external senders by default.",
                            ],
                            "effort": "low",
                        },
                        engine="phishing",
                        backend="embedded",
                    )
                )

        return findings

    # Live: optional .eml file analysis
    if ctx.mode == "live":
        eml_path = Path(ctx.target)
        if eml_path.is_file() and eml_path.suffix.lower() in (".eml", ".txt"):
            try:
                hdr = _parse_eml_headers(eml_path)
                auth = hdr.get("authentication_results") or ""
                if re.search(r"spf=fail|dkim=fail|dmarc=fail", auth, re.I):
                    findings.append(
                        _finding(
                            ctx.next_id("phishing"),
                            "Live .eml authentication failure",
                            "critical",
                            f"Authentication-Results on '{eml_path.name}' indicate SPF/DKIM/DMARC failure.",
                            resource={"type": "email_message", "id": str(eml_path), "engine": "phishing"},
                            evidence={"authentication_results": auth, "source": "live.eml"},
                            engine="phishing",
                            backend="embedded",
                        )
                    )
                from_hdr = hdr.get("from") or ""
                reply = hdr.get("reply_to") or ""
                if reply and from_hdr and reply.lower() not in from_hdr.lower():
                    findings.append(
                        _finding(
                            ctx.next_id("phishing"),
                            "Live .eml Reply-To mismatch",
                            "high",
                            f"Reply-To '{reply}' differs from From '{from_hdr}'.",
                            resource={"type": "email_message", "id": str(eml_path), "engine": "phishing"},
                            evidence={"from": from_hdr, "reply_to": reply, "source": "live.eml"},
                            engine="phishing",
                            backend="embedded",
                        )
                    )
            except Exception:
                pass
    return findings


def _engine_traffic(ctx: PackContext) -> list[dict]:
    """P6: traffic anomaly / log patterns — upgrade legacy traffic scout. P1 stub."""
    _ = ctx
    return []


def _engine_protocol(ctx: PackContext) -> list[dict]:
    """P6: protocol fingerprint — upgrade legacy protocol scout. P1 stub."""
    _ = ctx
    return []


def _engine_asset(ctx: PackContext) -> list[dict]:
    """P6: external attack surface / asset discovery. P1 stub."""
    _ = ctx
    return []


# Single source of truth — grow without rebuilding the facade
ENGINE_REGISTRY: list[dict[str, Any]] = [
    {
        "key": "network",
        "code": "NET",
        "name": "Network Perimeter (TLS/DNS/Ports)",
        "status": "active",  # P3
        "phase": "P3",
        "preferred_backends": ["httpx", "nmap", "openssl", "embedded"],
        "run": _engine_network,
        "weight": 1.2,
        "wraps": "ai_network_auditor.py",
    },
    {
        "key": "data_exposure",
        "code": "DATA",
        "name": "Data Exposure & Leak Scout",
        "status": "active",  # P3
        "phase": "P3",
        "preferred_backends": ["httpx", "embedded"],
        "run": _engine_data_exposure,
        "weight": 1.2,
        "wraps": "ai_data_scout.py",
    },
    {
        "key": "api",
        "code": "API",
        "name": "API Surface & Admin Discovery",
        "status": "active",  # P4
        "phase": "P4",
        "preferred_backends": ["httpx", "nuclei", "embedded"],
        "run": _engine_api,
        "weight": 1.1,
        "wraps": "ai_api_scout.py",
    },
    {
        "key": "vuln",
        "code": "VULN",
        "name": "Application Vulnerabilities (OWASP)",
        "status": "active",  # P4
        "phase": "P4",
        "preferred_backends": ["nuclei", "embedded"],
        "run": _engine_vuln,
        "weight": 1.2,
        "wraps": "ai_vuln_hunter.py",
    },
    {
        "key": "identity",
        "code": "IDENT",
        "name": "Identity & Session Security",
        "status": "stub",
        "phase": "P5",
        "preferred_backends": ["embedded"],
        "run": _engine_identity,
        "weight": 1.1,
        "wraps": "ai_identity_guard.py",
    },
    {
        "key": "governance",
        "code": "GOV",
        "name": "Governance & Security Headers",
        "status": "stub",
        "phase": "P5",
        "preferred_backends": ["embedded"],
        "run": _engine_governance,
        "weight": 1.0,
        "wraps": "ai_governance_mapper.py",
    },
    {
        "key": "phishing",
        "code": "PHISH",
        "name": "Phishing & Email Security Detective",
        "status": "active",  # P2
        "phase": "P2",
        "preferred_backends": ["dig", "embedded"],
        "run": _engine_phishing,
        "weight": 1.3,
        "wraps": "embedded phishing detective (P2)",
    },
    {
        "key": "traffic",
        "code": "TRF",
        "name": "Traffic Anomaly Detection",
        "status": "stub",
        "phase": "P6",
        "preferred_backends": ["embedded"],
        "run": _engine_traffic,
        "weight": 0.9,
        "wraps": "ai_traffic_scout.py (legacy upgrade)",
    },
    {
        "key": "protocol",
        "code": "PRT",
        "name": "Protocol Fingerprint & Service ID",
        "status": "stub",
        "phase": "P6",
        "preferred_backends": ["nmap", "embedded"],
        "run": _engine_protocol,
        "weight": 0.9,
        "wraps": "ai_protocol_scout.py (legacy upgrade)",
    },
    {
        "key": "asset",
        "code": "AST",
        "name": "External Attack Surface & Assets",
        "status": "stub",
        "phase": "P6",
        "preferred_backends": ["httpx", "embedded"],
        "run": _engine_asset,
        "weight": 0.9,
        "wraps": "ai_asset_scout.py (legacy upgrade)",
    },
]


def _resolve_backend(engine: dict, backends: dict) -> str:
    for name in engine.get("preferred_backends") or ["embedded"]:
        b = backends.get(name) or {}
        if b.get("available"):
            return name
    return "embedded"


def _load_fixture(params: dict) -> tuple[dict | None, str, str | None]:
    """Load mock fixture JSON. Returns (data, mode, error)."""
    mock_file = params.get("mock_file") or params.get("fixture")
    mock_flag = params.get("mock", None)
    target = params.get("target") or "."

    if mock_file:
        path = Path(str(mock_file))
        if not path.is_file():
            alt = Path.cwd() / path.name
            path = alt if alt.is_file() else path
        if not path.is_file():
            return None, "mock", f"mock_file not found: {mock_file}"
        try:
            text = path.read_text(encoding="utf-8-sig")
            data = json.loads(text)
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
                data.get("_security_engineer_fixture")
                or data.get("_perimeter_fixture")
                or data.get("target")
            ):
                return data, "mock", None
        except Exception:
            pass

    if mock_flag is True:
        for candidate in (
            "mock_security_engineer_vulnerable.json",
            Path(__file__).resolve().parent / "mock_security_engineer_vulnerable.json",
        ):
            p = Path(candidate)
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8-sig"))
                return data, "mock", None
        return None, "mock", "mock=True but mock_security_engineer_vulnerable.json not found"

    return None, "live", None


def _risk_score(findings: list[dict]) -> int:
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(str(f.get("severity", "info")).lower(), 0)
    return max(0, 100 - penalty)


def _domain_scores(engine_results: list[dict]) -> dict[str, Any]:
    """Per-engine score shell. 100 when stub/no findings; drops when findings exist."""
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
        "phase": "P4",
        "label": "phishing_network_data_api_vuln_active",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full Security Engineer multi-engine pack — not single-scanner ceiling",
        "next_phase": "P5 identity + governance engines",
        "active_engines": sorted(e["key"] for e in engine_results if e.get("status") == "active"),
        "pack_hands_complete": False,
    }


def run(params: dict) -> dict:
    """
    TOOL_STANDARDS entrypoint.

    params:
      target: public URL, label, or fixture .json path
      mock_file: optional path to offline fixture
      mock: bool — force mock vulnerable default
      engines: optional list of engine keys to run (default: all)
      timeout: reserved for live backends
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
                "llm_summary": f"Security Engineer pack failed: {err}",
                "pack_phase": "P4",
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
            for f in findings:
                ev = f.setdefault("evidence", {})
                ev.setdefault("engine", key)
                ev.setdefault("backend", backend_used)
                ev.setdefault("check_id", f.get("id"))
            entry["findings"] = findings
            all_findings.extend(findings)
        except Exception as e:
            entry["error"] = str(e)
            errors.append(f"{key}: {e}")
        engine_results.append(entry)

    crit = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    med = sum(1 for f in all_findings if f.get("severity") == "medium")
    low = sum(1 for f in all_findings if f.get("severity") == "low")
    info = sum(1 for f in all_findings if f.get("severity") == "info")
    total = len(all_findings)
    score = _risk_score(all_findings)
    readiness = _pack_readiness(engine_results)
    domain_scores = _domain_scores(engine_results)

    target_label = target
    if mode == "mock" and fixture:
        target_label = (fixture.get("target") or {}).get("url") or fixture.get("target") or target

    if errors and not all_findings and readiness["engines_active"] == 0:
        status = "partial" if len(errors) < len(engine_results) else "failed"
    elif crit or high:
        status = "failed" if crit else "partial"
    else:
        status = "success"

    duration = (_now() - started).total_seconds()
    live_tools = [k for k, v in backends.items() if k != "embedded" and v.get("available")]
    llm = (
        f"Security Engineer pack {VERSION} ({readiness['label']}) scanned '{target_label}' mode={mode}. "
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
            "target": target_label,
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
                1
                for e in engine_results
                if e["status"] == "active" and not e.get("findings")
            ),
            "engines_run": len(engine_results),
            "engines_active": readiness["engines_active"],
            "engines_stub": readiness["engines_stub"],
            "pack_complete_pct": readiness["complete_pct"],
            "domain_scores": domain_scores,
        },
        "findings": all_findings,
        "metadata": {
            "domain": DOMAIN,
            "subdomain": SUBDOMAIN,
            "sentinel": SENTINEL,
            "tier": TIER,
            "tags": TAGS,
            "llm_summary": llm,
            "pack_phase": "P4",
            "pack_readiness": readiness,
            "pack_hands_complete": readiness.get("pack_hands_complete", False),
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
            "id_scheme": "PERIM-{ENGINE_CODE}-{NNN}",
            "engine_codes": ENGINE_CODES,
            "fixture_profile": (fixture or {}).get("_profile") or (fixture or {}).get("_description"),
        },
    }


def scan(target: str = ".", mock_file: str | None = None, **kwargs) -> dict:
    params = {"target": target, **kwargs}
    if mock_file:
        params["mock_file"] = mock_file
    return run(params)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    target = args[0] if args else "."
    mock_file = args[1] if len(args) > 1 else None

    params: dict[str, Any] = {"target": target}
    if mock_file:
        params["mock_file"] = mock_file
    elif "--mock" in flags or target in ("mock", "mock-vuln", "mock-vulnerable"):
        params["mock"] = True
        params["target"] = "mock-security-engineer"
    elif target in ("mock-clean",):
        params["mock_file"] = "mock_security_engineer_clean.json"
        params["target"] = "mock-security-engineer-clean"

    result = run(params)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("execution", {}).get("status") != "failed" else 1)
