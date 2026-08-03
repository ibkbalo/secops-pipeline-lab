# ai_security_engineer_pack.py
# Sentinel Stacks — Security Engineer Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase P1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase P2: Phishing (PHISH) engine ACTIVE — embedded fixture + optional
#            .eml header analysis; SPF/DKIM/DMARC, BEC, link signals.
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
VERSION = "0.2.0-p2"
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
    """P3: TLS/DNS/ports — wraps ai_network_auditor. P1 stub."""
    _ = ctx
    return []


def _engine_data_exposure(ctx: PackContext) -> list[dict]:
    """P3: data leaks / exposed buckets / .env — wraps ai_data_scout. P1 stub."""
    _ = ctx
    return []


def _engine_api(ctx: PackContext) -> list[dict]:
    """P4: API surface / OpenAPI / admin paths — wraps ai_api_scout. P1 stub."""
    _ = ctx
    return []


def _engine_vuln(ctx: PackContext) -> list[dict]:
    """P4: OWASP Top 10 — wraps ai_vuln_hunter. P1 stub."""
    _ = ctx
    return []


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
        "status": "stub",
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
        "status": "stub",
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
        "status": "stub",
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
        "status": "stub",
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
        "phase": "P2",
        "label": "phishing_active",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full Security Engineer multi-engine pack — not single-scanner ceiling",
        "next_phase": "P3 network + data exposure engines",
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
                "pack_phase": "P2",
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
            "pack_phase": "P2",
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
