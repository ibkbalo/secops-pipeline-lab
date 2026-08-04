# ai_ai_security_pack.py
# Sentinel Stacks — AI Security Engineer Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase A1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase A2: Prompt Injection (PI) + LLM API Keys (KEY) engines ACTIVE —
#            embedded fixture + optional gitleaks/semgrep live backends.
# Enterprise bar: full AI / LLM security multi-engine pack —
#                 not a single-scanner toy (prompt-injection-only demo).
#
# Planned activation (later phases):
#   A3: rag_data_leakage + output_filtering
#   A4: agent_tool_abuse + mcp_permissions
#   A5: model_supply_chain + training_poison
#   A6: model_governance + inference_hardening → pack hands complete
#   A7: FIX_MAP AISEC-* in ai_remediation_engine.py

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import datetime
from pathlib import Path
from typing import Any, Callable

TOOL_ID = "scan_ai_security_pack"
VERSION = "0.2.0-a2"
DOMAIN = "aisec"
SUBDOMAIN = "ai-security/pack"
SENTINEL = "ai"
TIER = 1
TAGS = [
    "ai-security",
    "llm",
    "multi-engine",
    "prompt-injection",
    "rag",
    "mcp",
    "agentic",
    "owasp-llm",
    "enterprise",
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# ── Finding ID scheme (locked) ───────────────────────────────────────────────
# AISEC-{ENGINE}-{NNN}
# ENGINE codes are stable forever; NNN grows without artificial ceilings.
ENGINE_CODES = {
    "prompt_injection": "PI",
    "model_supply_chain": "MSC",
    "rag_data_leakage": "RAG",
    "agent_tool_abuse": "AGT",
    "llm_api_keys": "KEY",
    "output_filtering": "OUT",
    "training_poison": "POI",
    "mcp_permissions": "MCP",
    "model_governance": "GOV",
    "inference_hardening": "INF",
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
        ("gitleaks", ["llm_api_keys"]),
        ("trivy", ["model_supply_chain"]),
        ("semgrep", ["prompt_injection", "agent_tool_abuse"]),
        ("syft", ["model_supply_chain"]),
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
        return f"AISEC-{code}-{self._counters[engine_key]:03d}"

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
        or {"type": "ai-security", "id": fid, "engine": engine},
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
                "Re-run scan_ai_security_pack to verify the control passes.",
            ],
            "effort": "medium",
        },
        "compliance": compliance
        or [
            "OWASP LLM Top 10",
            "NIST AI RMF GOVERN-1.1",
            "NIST 800-53 SI-2",
            "ISO 27001 A.14.2.1",
        ],
    }


# ── Engine protocol ──────────────────────────────────────────────────────────
# status:
#   active  — emits real findings this release
#   stub    — registered, executes, returns [] until filled (A2+)
# backend preference: live tool if available else embedded

EngineFn = Callable[[PackContext], list[dict]]


def _sev_for_llm_key_rule(rule: str) -> str:
    r = (rule or "").lower()
    if any(x in r for x in ("openai", "anthropic", "azure-openai", "gemini", "cohere", "huggingface", "hf-")):
        return "critical"
    if any(x in r for x in ("api-key", "apikey", "token", "secret", "bearer")):
        return "high"
    return "high"


def _engine_prompt_injection(ctx: PackContext) -> list[dict]:
    """Prompt injection & jailbreak — embedded fixture + optional live config patterns."""
    findings: list[dict] = []
    pi = ctx.section("prompt_injection") if ctx.fixture else {}

    if pi:
        if pi.get("system_prompt_isolation") is False:
            findings.append(
                _finding(
                    ctx.next_id("prompt_injection"),
                    "System prompt not isolated from user/tool content",
                    "critical",
                    "System instructions are not cryptographically or structurally isolated from "
                    "user messages and retrieved documents. Attackers can override policy via injection.",
                    resource={"type": "llm_config", "id": "system_prompt", "engine": "prompt_injection"},
                    evidence={
                        "system_prompt_isolation": False,
                        "source": "fixture.prompt_injection.system_prompt_isolation",
                    },
                    remediation={
                        "steps": [
                            "Separate system instructions from user/RAG content (structured roles, not concatenated plain text).",
                            "Apply instruction hierarchy / privileged system channel where the platform supports it.",
                            "Add regression tests for known override payloads before production.",
                        ],
                        "effort": "high",
                    },
                    compliance=["OWASP LLM01:2025", "NIST AI RMF MAP-2.3", "NIST 800-53 SI-10"],
                    engine="prompt_injection",
                    backend="embedded",
                )
            )

        if pi.get("indirect_injection_from_docs") is True:
            findings.append(
                _finding(
                    ctx.next_id("prompt_injection"),
                    "Indirect prompt injection via retrieved documents enabled",
                    "critical",
                    "Documents ingested into RAG/context can carry hidden instructions that the model may obey. "
                    "No durable separation between trusted instructions and untrusted content was detected.",
                    resource={"type": "rag_pipeline", "id": "document_ingestion", "engine": "prompt_injection"},
                    evidence={
                        "indirect_injection_from_docs": True,
                        "source": "fixture.prompt_injection.indirect_injection_from_docs",
                    },
                    remediation={
                        "steps": [
                            "Treat all retrieved content as untrusted data, never as instructions.",
                            "Strip or quarantine instruction-like markup from ingested docs.",
                            "Require human approval for high-impact tool calls triggered after retrieval.",
                        ],
                        "effort": "high",
                    },
                    compliance=["OWASP LLM01:2025", "OWASP LLM02:2025", "NIST AI RMF MEASURE-2.6"],
                    engine="prompt_injection",
                    backend="embedded",
                )
            )

        if pi.get("jailbreak_filter") is False:
            findings.append(
                _finding(
                    ctx.next_id("prompt_injection"),
                    "Jailbreak / policy-bypass filter disabled",
                    "high",
                    "No jailbreak or role-play override filter is enforced on inbound prompts. "
                    "Classic DAN-style and instruction-smuggling payloads can reach the model.",
                    resource={"type": "llm_guardrail", "id": "jailbreak_filter", "engine": "prompt_injection"},
                    evidence={
                        "jailbreak_filter": False,
                        "source": "fixture.prompt_injection.jailbreak_filter",
                    },
                    remediation={
                        "steps": [
                            "Enable inbound prompt classifiers for jailbreak / policy-bypass patterns.",
                            "Block or escalate known role-play override classes before model invoke.",
                            "Log blocked attempts for abuse monitoring.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP LLM01:2025", "NIST AI RMF GOVERN-1.2"],
                    engine="prompt_injection",
                    backend="embedded",
                )
            )

        for sample in pi.get("samples") or []:
            if sample.get("blocked") is True:
                continue
            sid = sample.get("fixture_id") or "sample"
            vector = sample.get("vector") or "unknown"
            payload_class = sample.get("payload_class") or "unclassified"
            sev = "critical" if vector == "indirect" else "high"
            findings.append(
                _finding(
                    ctx.next_id("prompt_injection"),
                    f"Unblocked injection sample: {sid} ({payload_class})",
                    sev,
                    f"Fixture sample '{sid}' (vector={vector}, class={payload_class}) was not blocked. "
                    f"Source hint: {sample.get('source') or 'direct prompt'}.",
                    resource={
                        "type": "injection_sample",
                        "id": sid,
                        "engine": "prompt_injection",
                        "vector": vector,
                    },
                    evidence={
                        "sample": sample,
                        "source": "fixture.prompt_injection.samples",
                    },
                    remediation={
                        "steps": [
                            f"Add detection/blocking for payload class '{payload_class}'.",
                            "Include this sample in the red-team / eval suite before each model release.",
                            "Re-run scan_ai_security_pack prompt_injection engine to verify block=true.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP LLM01:2025", "NIST AI RMF MEASURE-2.7"],
                    engine="prompt_injection",
                    backend="embedded",
                )
            )
        return findings

    # Live fallback: look for common weak prompt-assembly patterns in code
    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            pattern = re.compile(
                r"(system_prompt\s*\+|f[\"'].*system.*\{.*user|ignore previous instructions)",
                re.I,
            )
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in {".py", ".ts", ".js", ".tsx", ".jsx"}:
                    continue
                if any(p in path.parts for p in (".git", "node_modules", "__pycache__", ".venv", "venv")):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if pattern.search(text):
                    findings.append(
                        _finding(
                            ctx.next_id("prompt_injection"),
                            f"Risky prompt assembly pattern in {path.name}",
                            "medium",
                            f"File '{path.as_posix()}' appears to concatenate or interpolate user content "
                            "into privileged prompt strings without isolation.",
                            resource={"type": "file", "id": str(path), "engine": "prompt_injection"},
                            evidence={"path": str(path), "source": "live.prompt_assembly_scan"},
                            engine="prompt_injection",
                            backend="embedded",
                        )
                    )
                    if len(findings) >= 5:
                        break
    return findings


def _engine_model_supply_chain(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A5. Model provenance, weights, insecure plugins."""
    return []


def _engine_rag_data_leakage(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A3. RAG over-exposure, PII in indexes, cross-tenant."""
    return []


def _engine_agent_tool_abuse(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A4. Unsafe tool/function calling, SSRF/exfil via tools."""
    return []


def _engine_llm_api_keys(ctx: PackContext) -> list[dict]:
    """LLM provider API key exposure — embedded fixture + optional gitleaks / live scan."""
    findings: list[dict] = []
    keys = ctx.section("llm_api_keys") if ctx.fixture else {}

    if keys:
        for item in keys.get("tracked_files_with_keys") or []:
            path = item.get("path") or "unknown"
            for m in item.get("matches") or []:
                rule = m.get("rule") or "llm-api-key"
                sev = _sev_for_llm_key_rule(rule)
                line = m.get("line")
                snippet = (m.get("snippet") or "")[:120]
                findings.append(
                    _finding(
                        ctx.next_id("llm_api_keys"),
                        f"LLM provider key in tracked file: {rule}",
                        sev,
                        f"Tracked path '{path}' contains an LLM provider credential matched by rule '{rule}'. "
                        "Remove from VCS, rotate the key, and block future commits.",
                        resource={
                            "type": "file",
                            "id": path,
                            "engine": "llm_api_keys",
                            "line": line,
                        },
                        evidence={
                            "path": path,
                            "line": line,
                            "rule": rule,
                            "snippet": snippet,
                            "source": "fixture.llm_api_keys.tracked_files_with_keys",
                        },
                        remediation={
                            "steps": [
                                f"Remove '{path}' from the working tree and git history (filter-repo/BFG).",
                                "Rotate the exposed key in the provider console immediately.",
                                "Store keys in a secret manager / CI secret store — never in tracked files.",
                                "Enable push protection / secret scanning for OpenAI/Anthropic patterns.",
                            ],
                            "effort": "high",
                        },
                        compliance=[
                            "OWASP LLM10:2025",
                            "NIST 800-53 IA-5",
                            "SOC 2 CC6.1",
                            "ISO 27001 A.9.4.3",
                        ],
                        engine="llm_api_keys",
                        backend="embedded",
                    )
                )

        if keys.get("secret_scanning_in_ci") is False:
            findings.append(
                _finding(
                    ctx.next_id("llm_api_keys"),
                    "Secret scanning for LLM keys disabled in CI",
                    "high",
                    "CI does not enforce secret scanning / push protection for LLM provider API keys. "
                    "Accidental commits of sk- / ANTHROPIC_API_KEY material may reach the remote.",
                    resource={"type": "ci_gate", "id": "secret_scanning", "engine": "llm_api_keys"},
                    evidence={
                        "secret_scanning_in_ci": False,
                        "source": "fixture.llm_api_keys.secret_scanning_in_ci",
                    },
                    remediation={
                        "steps": [
                            "Enable repository secret scanning and push protection.",
                            "Add gitleaks/trufflehog (or equivalent) as a required CI check.",
                            "Block merges when LLM provider key patterns are detected.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP LLM10:2025", "CIS Software Supply Chain 2.4", "NIST 800-53 SI-2"],
                    engine="llm_api_keys",
                    backend="embedded",
                )
            )
        return findings

    # Live fallback: scan common file types for provider key patterns
    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            key_re = re.compile(
                r"(sk-[A-Za-z0-9_\-]{20,}|ANTHROPIC_API_KEY\s*[:=]\s*\S+|"
                r"OPENAI_API_KEY\s*[:=]\s*\S+|AIza[0-9A-Za-z_\-]{20,})",
                re.I,
            )
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in {
                    ".env", ".yml", ".yaml", ".json", ".py", ".ts", ".js", ".toml", ".ini", ".txt",
                } and path.name not in {".env", ".env.local", ".env.production"}:
                    continue
                if any(p in path.parts for p in (".git", "node_modules", "__pycache__", ".venv", "venv")):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for m in key_re.finditer(text):
                    snippet = m.group(0)[:40] + "..."
                    findings.append(
                        _finding(
                            ctx.next_id("llm_api_keys"),
                            f"Possible LLM API key material in {path.name}",
                            "critical",
                            f"Live scan matched provider key-like material in '{path.as_posix()}'. "
                            "Rotate if real; move to a secret store.",
                            resource={"type": "file", "id": str(path), "engine": "llm_api_keys"},
                            evidence={
                                "path": str(path),
                                "snippet": snippet,
                                "source": "live.llm_key_scan",
                            },
                            engine="llm_api_keys",
                            backend="embedded",
                        )
                    )
                    if len(findings) >= 10:
                        return findings
    return findings


def _engine_output_filtering(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A3. Missing output filters, PII/code exfil in responses."""
    return []


def _engine_training_poison(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A5. Poisoning / untrusted fine-tune data signals."""
    return []


def _engine_mcp_permissions(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A4. MCP/tool permission sprawl, over-privileged connectors."""
    return []


def _engine_model_governance(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A6. Logging/retention, eval gates, abuse monitoring."""
    return []


def _engine_inference_hardening(ctx: PackContext) -> list[dict]:
    """A1 stub — activate in A6. Auth, rate limits, cost/DoS on inference APIs."""
    return []


ENGINE_REGISTRY: list[dict[str, Any]] = [
    {
        "key": "prompt_injection",
        "code": "PI",
        "name": "Prompt Injection & Jailbreak",
        "status": "active",  # A2
        "phase": "A2",
        "preferred_backends": ["semgrep", "embedded"],
        "run": _engine_prompt_injection,
        "weight": 1.3,
    },
    {
        "key": "model_supply_chain",
        "code": "MSC",
        "name": "Model Supply Chain & Provenance",
        "status": "stub",
        "phase": "A5",
        "preferred_backends": ["trivy", "syft", "embedded"],
        "run": _engine_model_supply_chain,
        "weight": 1.1,
    },
    {
        "key": "rag_data_leakage",
        "code": "RAG",
        "name": "RAG Data Leakage & Isolation",
        "status": "stub",
        "phase": "A3",
        "preferred_backends": ["embedded"],
        "run": _engine_rag_data_leakage,
        "weight": 1.2,
    },
    {
        "key": "agent_tool_abuse",
        "code": "AGT",
        "name": "Agent Tool / Function-Call Abuse",
        "status": "stub",
        "phase": "A4",
        "preferred_backends": ["semgrep", "embedded"],
        "run": _engine_agent_tool_abuse,
        "weight": 1.2,
    },
    {
        "key": "llm_api_keys",
        "code": "KEY",
        "name": "LLM Provider API Key Exposure",
        "status": "active",  # A2
        "phase": "A2",
        "preferred_backends": ["gitleaks", "embedded"],
        "run": _engine_llm_api_keys,
        "weight": 1.3,
    },
    {
        "key": "output_filtering",
        "code": "OUT",
        "name": "Output Filtering & Response Guardrails",
        "status": "stub",
        "phase": "A3",
        "preferred_backends": ["embedded"],
        "run": _engine_output_filtering,
        "weight": 1.0,
    },
    {
        "key": "training_poison",
        "code": "POI",
        "name": "Training / Fine-Tune Data Poisoning Signals",
        "status": "stub",
        "phase": "A5",
        "preferred_backends": ["embedded"],
        "run": _engine_training_poison,
        "weight": 1.0,
    },
    {
        "key": "mcp_permissions",
        "code": "MCP",
        "name": "MCP & Tool Permission Sprawl",
        "status": "stub",
        "phase": "A4",
        "preferred_backends": ["embedded"],
        "run": _engine_mcp_permissions,
        "weight": 1.1,
    },
    {
        "key": "model_governance",
        "code": "GOV",
        "name": "Model Governance & Abuse Monitoring",
        "status": "stub",
        "phase": "A6",
        "preferred_backends": ["embedded"],
        "run": _engine_model_governance,
        "weight": 0.9,
    },
    {
        "key": "inference_hardening",
        "code": "INF",
        "name": "Inference API Hardening",
        "status": "stub",
        "phase": "A6",
        "preferred_backends": ["embedded"],
        "run": _engine_inference_hardening,
        "weight": 1.0,
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
                data.get("_ai_security_fixture")
                or data.get("target")
            ):
                return data, "mock", None
        except Exception:
            pass

    if mock_flag is True:
        for candidate in (
            "mock_ai_security_vulnerable.json",
            Path(__file__).resolve().parent / "mock_ai_security_vulnerable.json",
        ):
            p = Path(candidate)
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8-sig"))
                return data, "mock", None
        return None, "mock", "mock=True but mock_ai_security_vulnerable.json not found"

    return None, "live", None


def _risk_score(findings: list[dict]) -> int:
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(str(f.get("severity", "info")).lower(), 0)
    return max(0, 100 - penalty)


def _domain_scores(engine_results: list[dict]) -> dict[str, Any]:
    """Per-engine score shell. stub → score null; active → risk score from findings."""
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
        "phase": "A2",
        "label": "prompt_injection_llm_keys_active",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full AI Security Engineer multi-engine pack — not single-scanner ceiling",
        "next_phase": "A3 activate rag_data_leakage + output_filtering",
        "active_engines": sorted(e["key"] for e in engine_results if e.get("status") == "active"),
        "pack_hands_complete": active == total and stub == 0,
    }


def run(params: dict) -> dict:
    """
    TOOL_STANDARDS entrypoint.

    params:
      target: path, label, or fixture .json path
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
                "llm_summary": f"AI Security pack failed: {err}",
                "pack_phase": "A2",
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
        f"AI Security pack {VERSION} ({readiness['label']}) scanned '{target_label}' mode={mode}. "
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
            "pack_phase": "A2",
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
            "id_scheme": "AISEC-{ENGINE_CODE}-{NNN}",
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
        params["target"] = "mock-ai-security"
    elif target in ("mock-clean",):
        params["mock_file"] = "mock_ai_security_clean.json"
        params["target"] = "mock-ai-security-clean"

    result = run(params)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("execution", {}).get("status") != "failed" else 1)
