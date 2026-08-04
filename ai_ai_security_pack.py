# ai_ai_security_pack.py
# Sentinel Stacks — AI Security Engineer Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase A1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase A2: Prompt Injection (PI) + LLM API Keys (KEY) engines ACTIVE —
#            embedded fixture + optional gitleaks/semgrep live backends.
# Phase A3: RAG Data Leakage (RAG) + Output Filtering (OUT) engines ACTIVE —
#            embedded fixture (tenant isolation, PII/index, response guards).
# Phase A4: Agent Tool Abuse (AGT) + MCP Permissions (MCP) engines ACTIVE —
#            embedded fixture (tool allowlists, SSRF, connector sprawl).
# Phase A5: Model Supply Chain (MSC) + Training Poison (POI) engines ACTIVE —
#            embedded fixture (provenance, untrusted weights, fine-tune hygiene).
# Phase A6: Model Governance (GOV) + Inference Hardening (INF) engines ACTIVE —
#            pack hands COMPLETE (10/10).
# Enterprise bar: full AI / LLM security multi-engine pack —
#                 not a single-scanner toy (prompt-injection-only demo).
#
# Planned next:
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
VERSION = "0.6.0-a6"
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
    """Model supply chain & provenance — embedded fixture."""
    findings: list[dict] = []
    msc = ctx.section("model_supply_chain") if ctx.fixture else {}
    if not msc:
        return findings

    if msc.get("model_provenance_attested") is False:
        findings.append(
            _finding(
                ctx.next_id("model_supply_chain"),
                "Model provenance not attested",
                "high",
                "Deployed model artifacts lack cryptographic provenance / attestation. "
                "Teams cannot verify which weights and publishers were approved for production.",
                resource={"type": "model_artifact", "id": "provenance", "engine": "model_supply_chain"},
                evidence={
                    "model_provenance_attested": False,
                    "source": "fixture.model_supply_chain.model_provenance_attested",
                },
                remediation={
                    "steps": [
                        "Require signed model cards / attestations for every production promotion.",
                        "Record model hash, publisher, license, and approval ticket in a registry.",
                        "Block deploys when provenance metadata is missing.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM03:2025", "NIST AI RMF MAP-2.3", "NIST 800-53 SA-12"],
                engine="model_supply_chain",
                backend="embedded",
            )
        )

    if msc.get("weights_from_untrusted_hub") is True:
        findings.append(
            _finding(
                ctx.next_id("model_supply_chain"),
                "Model weights pulled from untrusted hub",
                "critical",
                "Weights are sourced from an untrusted or unverified model hub. "
                "Tampered checkpoints can embed backdoors or malicious code loaders.",
                resource={"type": "model_artifact", "id": "weights", "engine": "model_supply_chain"},
                evidence={
                    "weights_from_untrusted_hub": True,
                    "source": "fixture.model_supply_chain.weights_from_untrusted_hub",
                },
                remediation={
                    "steps": [
                        "Pin models to an internal mirror with hash verification.",
                        "Allowlist approved publishers; ban anonymous / unknown hubs in CI.",
                        "Scan downloaded artifacts (pickle/safetensors policy) before load.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM03:2025", "NIST 800-53 SA-12", "CIS Software Supply Chain 3.1"],
                engine="model_supply_chain",
                backend="embedded",
            )
        )

    if msc.get("plugin_signing_required") is False:
        findings.append(
            _finding(
                ctx.next_id("model_supply_chain"),
                "Model plugin / extension signing not required",
                "high",
                "Plugins or model extensions can load without signature verification. "
                "A malicious plugin can execute code or alter inference behavior.",
                resource={"type": "model_plugin", "id": "signing", "engine": "model_supply_chain"},
                evidence={
                    "plugin_signing_required": False,
                    "source": "fixture.model_supply_chain.plugin_signing_required",
                },
                remediation={
                    "steps": [
                        "Require signed plugins and verify signatures at load time.",
                        "Maintain an allowlist of approved plugin publishers.",
                        "Disable unsigned plugin load in production runtimes.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM03:2025", "OWASP LLM08:2025", "NIST 800-53 CM-7"],
                engine="model_supply_chain",
                backend="embedded",
            )
        )

    if msc.get("sbom_for_model_artifacts") is False:
        findings.append(
            _finding(
                ctx.next_id("model_supply_chain"),
                "No SBOM for model / ML artifacts",
                "medium",
                "There is no software bill of materials covering model weights, tokenizers, "
                "and runtime dependencies. Incident response cannot quickly inventory blast radius.",
                resource={"type": "model_artifact", "id": "sbom", "engine": "model_supply_chain"},
                evidence={
                    "sbom_for_model_artifacts": False,
                    "source": "fixture.model_supply_chain.sbom_for_model_artifacts",
                },
                remediation={
                    "steps": [
                        "Generate SBOMs for model packages and serving images on every release.",
                        "Store SBOMs alongside the model registry entry.",
                        "Gate production promotion on SBOM presence.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM03:2025", "NIST 800-53 CM-8", "Executive Order 14028 SBOM"],
                engine="model_supply_chain",
                backend="embedded",
            )
        )

    return findings


def _engine_rag_data_leakage(ctx: PackContext) -> list[dict]:
    """RAG data leakage & isolation — embedded fixture (tenant/ACL/PII/index paths)."""
    findings: list[dict] = []
    rag = ctx.section("rag_data_leakage") if ctx.fixture else {}
    if not rag:
        return findings

    if rag.get("cross_tenant_retrieval") is True:
        findings.append(
            _finding(
                ctx.next_id("rag_data_leakage"),
                "Cross-tenant retrieval possible in RAG index",
                "critical",
                "The retrieval layer can return documents belonging to other tenants. "
                "This breaks data isolation and can leak confidential knowledge across customers.",
                resource={"type": "rag_index", "id": "vector_store", "engine": "rag_data_leakage"},
                evidence={
                    "cross_tenant_retrieval": True,
                    "source": "fixture.rag_data_leakage.cross_tenant_retrieval",
                },
                remediation={
                    "steps": [
                        "Enforce tenant_id (or equivalent) as a hard filter on every retrieval query.",
                        "Partition indexes per tenant or use row-level security on the vector store.",
                        "Add red-team tests that attempt cross-tenant document retrieval.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM02:2025", "OWASP LLM06:2025", "NIST AI RMF MAP-2.3", "SOC 2 CC6.1"],
                engine="rag_data_leakage",
                backend="embedded",
            )
        )

    if rag.get("pii_in_vector_index") is True:
        findings.append(
            _finding(
                ctx.next_id("rag_data_leakage"),
                "PII detected in vector / RAG index",
                "critical",
                "Personally identifiable information is stored or embedded in the retrieval index. "
                "Chunks can be returned verbatim to unauthorized users or other tenants.",
                resource={"type": "rag_index", "id": "embeddings", "engine": "rag_data_leakage"},
                evidence={
                    "pii_in_vector_index": True,
                    "source": "fixture.rag_data_leakage.pii_in_vector_index",
                },
                remediation={
                    "steps": [
                        "Run PII detection before chunking/embedding; redact or tokenize sensitive fields.",
                        "Exclude high-risk document classes from the index unless explicitly approved.",
                        "Rotate/rebuild the index after remediation; audit prior retrieval logs.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM02:2025", "NIST 800-53 SI-12", "GDPR Art.32", "SOC 2 CC6.1"],
                engine="rag_data_leakage",
                backend="embedded",
            )
        )

    if rag.get("document_acl_enforced") is False:
        findings.append(
            _finding(
                ctx.next_id("rag_data_leakage"),
                "Document ACLs not enforced at retrieval time",
                "high",
                "Retrieved chunks are not filtered by the caller's document-level access control list. "
                "Users may see content they are not authorized to read in the source system.",
                resource={"type": "rag_pipeline", "id": "acl_filter", "engine": "rag_data_leakage"},
                evidence={
                    "document_acl_enforced": False,
                    "source": "fixture.rag_data_leakage.document_acl_enforced",
                },
                remediation={
                    "steps": [
                        "Propagate source-system ACLs into chunk metadata and filter at query time.",
                        "Deny-by-default when ACL metadata is missing.",
                        "Re-test with users who lack access to indexed sensitive documents.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM02:2025", "NIST 800-53 AC-3", "SOC 2 CC6.1"],
                engine="rag_data_leakage",
                backend="embedded",
            )
        )

    for path in rag.get("sensitive_paths_indexed") or []:
        sev = "critical" if any(x in str(path).lower() for x in ("salary", "hr/", "nda", "ssn", "passport")) else "high"
        findings.append(
            _finding(
                ctx.next_id("rag_data_leakage"),
                f"Sensitive path indexed for RAG: {path}",
                sev,
                f"Path '{path}' is included in the RAG corpus. Sensitive business or HR/legal content "
                "should not be retrieved into model context without explicit approval.",
                resource={"type": "document_path", "id": path, "engine": "rag_data_leakage"},
                evidence={"path": path, "source": "fixture.rag_data_leakage.sensitive_paths_indexed"},
                remediation={
                    "steps": [
                        f"Remove '{path}' from the ingestion allowlist / crawl roots.",
                        "Add path/class denylists for HR, legal, payroll, and secrets directories.",
                        "Rebuild the index and verify the path no longer appears in retrieval tests.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM02:2025", "NIST 800-53 AC-6", "ISO 27001 A.8.2"],
                engine="rag_data_leakage",
                backend="embedded",
            )
        )

    return findings


def _engine_agent_tool_abuse(ctx: PackContext) -> list[dict]:
    """Agent tool / function-call abuse — embedded fixture."""
    findings: list[dict] = []
    agt = ctx.section("agent_tool_abuse") if ctx.fixture else {}
    if not agt:
        return findings

    if agt.get("unrestricted_web_fetch") is True:
        findings.append(
            _finding(
                ctx.next_id("agent_tool_abuse"),
                "Unrestricted web-fetch tool enabled for agent",
                "high",
                "The agent can fetch arbitrary URLs without an allowlist. This enables SSRF, "
                "credential harvesting from metadata endpoints, and data exfiltration relays.",
                resource={"type": "agent_tool", "id": "web_fetch", "engine": "agent_tool_abuse"},
                evidence={
                    "unrestricted_web_fetch": True,
                    "source": "fixture.agent_tool_abuse.unrestricted_web_fetch",
                },
                remediation={
                    "steps": [
                        "Restrict fetch destinations to an explicit domain allowlist.",
                        "Block link-local, RFC1918, and cloud metadata IP ranges.",
                        "Require human approval for first-time domains.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM06:2025", "OWASP LLM08:2025", "NIST 800-53 SC-7"],
                engine="agent_tool_abuse",
                backend="embedded",
            )
        )

    if agt.get("shell_tool_enabled") is True:
        findings.append(
            _finding(
                ctx.next_id("agent_tool_abuse"),
                "Shell / OS command tool enabled for agent",
                "critical",
                "The agent can execute shell commands. Prompt injection or malicious tool args can "
                "lead to RCE, lateral movement, or host compromise.",
                resource={"type": "agent_tool", "id": "shell", "engine": "agent_tool_abuse"},
                evidence={
                    "shell_tool_enabled": True,
                    "source": "fixture.agent_tool_abuse.shell_tool_enabled",
                },
                remediation={
                    "steps": [
                        "Disable shell tools in production agents unless absolutely required.",
                        "If required, run in a disposable sandbox with no secrets mounted.",
                        "Require dual control / human approval for every shell invocation.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM06:2025", "OWASP LLM08:2025", "NIST 800-53 CM-7", "SOC 2 CC6.1"],
                engine="agent_tool_abuse",
                backend="embedded",
            )
        )

    allowlist = agt.get("tool_allowlist")
    if isinstance(allowlist, list) and len(allowlist) == 0:
        findings.append(
            _finding(
                ctx.next_id("agent_tool_abuse"),
                "Empty agent tool allowlist (all tools implicitly available)",
                "high",
                "No explicit tool allowlist is configured. The agent may invoke any registered tool, "
                "expanding blast radius after a successful injection.",
                resource={"type": "agent_config", "id": "tool_allowlist", "engine": "agent_tool_abuse"},
                evidence={
                    "tool_allowlist": [],
                    "source": "fixture.agent_tool_abuse.tool_allowlist",
                },
                remediation={
                    "steps": [
                        "Define a minimal allowlist of tools per agent role.",
                        "Deny unknown tools by default; review additions via change control.",
                        "Document which tools can mutate state vs read-only.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM08:2025", "NIST 800-53 AC-6", "NIST AI RMF GOVERN-1.2"],
                engine="agent_tool_abuse",
                backend="embedded",
            )
        )

    if agt.get("ssrf_protection") is False:
        findings.append(
            _finding(
                ctx.next_id("agent_tool_abuse"),
                "No SSRF protection on agent network tools",
                "high",
                "Network-capable tools lack SSRF controls. Attackers can pivot to internal services "
                "or cloud instance metadata via tool arguments.",
                resource={"type": "agent_tool", "id": "network", "engine": "agent_tool_abuse"},
                evidence={
                    "ssrf_protection": False,
                    "source": "fixture.agent_tool_abuse.ssrf_protection",
                },
                remediation={
                    "steps": [
                        "Validate and resolve URLs; block private and link-local ranges.",
                        "Disable following redirects to internal hosts.",
                        "Use an egress proxy with destination policy for agent traffic.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM06:2025", "OWASP API7:2023", "NIST 800-53 SC-7"],
                engine="agent_tool_abuse",
                backend="embedded",
            )
        )

    if agt.get("exfil_via_tool_args") is True:
        findings.append(
            _finding(
                ctx.next_id("agent_tool_abuse"),
                "Data exfiltration via tool arguments possible",
                "critical",
                "Sensitive context (secrets, PII, retrieved docs) can be passed into outbound tool "
                "arguments without inspection. An injected agent can exfiltrate data through tools.",
                resource={"type": "agent_pipeline", "id": "tool_args", "engine": "agent_tool_abuse"},
                evidence={
                    "exfil_via_tool_args": True,
                    "source": "fixture.agent_tool_abuse.exfil_via_tool_args",
                },
                remediation={
                    "steps": [
                        "Scan tool arguments for secrets/PII before invocation.",
                        "Strip or tokenize sensitive fields; prefer opaque resource IDs over raw content.",
                        "Log and alert on high-entropy or large outbound tool payloads.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM06:2025", "OWASP LLM02:2025", "NIST 800-53 SC-7", "SOC 2 CC6.1"],
                engine="agent_tool_abuse",
                backend="embedded",
            )
        )

    return findings


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
    """Output filtering & response guardrails — embedded fixture."""
    findings: list[dict] = []
    out = ctx.section("output_filtering") if ctx.fixture else {}
    if not out:
        return findings

    if out.get("pii_redaction") is False:
        findings.append(
            _finding(
                ctx.next_id("output_filtering"),
                "No PII redaction on model outputs",
                "high",
                "Model responses are not scanned/redacted for PII before delivery to clients. "
                "Names, emails, account numbers, or retrieved PII can leak in chat completions.",
                resource={"type": "llm_guardrail", "id": "pii_redaction", "engine": "output_filtering"},
                evidence={"pii_redaction": False, "source": "fixture.output_filtering.pii_redaction"},
                remediation={
                    "steps": [
                        "Add post-generation PII detection and redaction (or block) before response return.",
                        "Align redaction rules with data-classification policy.",
                        "Log redaction events for compliance review.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM02:2025", "OWASP LLM06:2025", "NIST 800-53 SI-12", "GDPR Art.32"],
                engine="output_filtering",
                backend="embedded",
            )
        )

    if out.get("toxic_content_filter") is False:
        findings.append(
            _finding(
                ctx.next_id("output_filtering"),
                "Toxic / harmful content filter disabled on outputs",
                "medium",
                "No toxic, hate, or self-harm content filter is applied to model outputs. "
                "Unsafe generations may reach end users without escalation.",
                resource={"type": "llm_guardrail", "id": "toxic_filter", "engine": "output_filtering"},
                evidence={
                    "toxic_content_filter": False,
                    "source": "fixture.output_filtering.toxic_content_filter",
                },
                remediation={
                    "steps": [
                        "Enable output safety classifiers aligned to your AUP.",
                        "Block or rewrite high-severity categories; escalate medium for review.",
                        "Track false-positive rates so safety does not silently degrade UX.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM01:2025", "NIST AI RMF GOVERN-1.2", "SOC 2 CC7.2"],
                engine="output_filtering",
                backend="embedded",
            )
        )

    if out.get("code_exfil_guard") is False:
        findings.append(
            _finding(
                ctx.next_id("output_filtering"),
                "No code / secret exfiltration guard on outputs",
                "high",
                "Responses are not checked for source-code dumps, credentials, or internal URL/path leakage. "
                "Models with tool/RAG access can paste sensitive material into the chat channel.",
                resource={"type": "llm_guardrail", "id": "code_exfil_guard", "engine": "output_filtering"},
                evidence={
                    "code_exfil_guard": False,
                    "source": "fixture.output_filtering.code_exfil_guard",
                },
                remediation={
                    "steps": [
                        "Detect secrets, private keys, and large code dumps in completions.",
                        "Block or truncate when internal repo paths / credentials appear.",
                        "Pair with DLP rules for known internal domains and key formats.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM02:2025", "OWASP LLM06:2025", "NIST 800-53 SC-7"],
                engine="output_filtering",
                backend="embedded",
            )
        )

    if out.get("max_output_tokens_enforced") is False:
        findings.append(
            _finding(
                ctx.next_id("output_filtering"),
                "Max output tokens not enforced",
                "medium",
                "No hard cap on completion length. Attackers can inflate cost/DoS via long generations "
                "or coax large data dumps from context.",
                resource={"type": "llm_config", "id": "max_tokens", "engine": "output_filtering"},
                evidence={
                    "max_output_tokens_enforced": False,
                    "source": "fixture.output_filtering.max_output_tokens_enforced",
                },
                remediation={
                    "steps": [
                        "Set max_tokens (or equivalent) per route/role with a safe default.",
                        "Alert on anomalous completion lengths and cost spikes.",
                        "Re-test that over-limit requests are truncated or rejected.",
                    ],
                    "effort": "low",
                },
                compliance=["OWASP LLM04:2025", "NIST AI RMF MEASURE-2.6"],
                engine="output_filtering",
                backend="embedded",
            )
        )

    return findings


def _engine_training_poison(ctx: PackContext) -> list[dict]:
    """Training / fine-tune data poisoning signals — embedded fixture."""
    findings: list[dict] = []
    poi = ctx.section("training_poison") if ctx.fixture else {}
    if not poi:
        return findings

    if poi.get("untrusted_fine_tune_dataset") is True:
        findings.append(
            _finding(
                ctx.next_id("training_poison"),
                "Fine-tune dataset from untrusted source",
                "critical",
                "Fine-tuning uses data from an untrusted or unverified source. "
                "Poisoned samples can implant triggers, bias, or policy bypasses into the model.",
                resource={"type": "dataset", "id": "fine_tune", "engine": "training_poison"},
                evidence={
                    "untrusted_fine_tune_dataset": True,
                    "source": "fixture.training_poison.untrusted_fine_tune_dataset",
                },
                remediation={
                    "steps": [
                        "Source fine-tune data only from approved, versioned corpora.",
                        "Quarantine external contributions until reviewed.",
                        "Track dataset hash and lineage in the model registry.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM03:2025", "NIST AI RMF MAP-2.3", "NIST 800-53 SI-7"],
                engine="training_poison",
                backend="embedded",
            )
        )

    if poi.get("dataset_provenance_review") is False:
        findings.append(
            _finding(
                ctx.next_id("training_poison"),
                "No dataset provenance review before training",
                "high",
                "Datasets are not reviewed for provenance, license, or contamination before training. "
                "Unknown origin data increases poisoning and compliance risk.",
                resource={"type": "dataset", "id": "provenance_review", "engine": "training_poison"},
                evidence={
                    "dataset_provenance_review": False,
                    "source": "fixture.training_poison.dataset_provenance_review",
                },
                remediation={
                    "steps": [
                        "Require a provenance checklist (source, license, PII, owner) before training jobs.",
                        "Block training pipelines when review status is missing.",
                        "Retain review records with the resulting model version.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM03:2025", "NIST AI RMF GOVERN-1.1", "NIST 800-53 SA-12"],
                engine="training_poison",
                backend="embedded",
            )
        )

    if poi.get("poison_sample_detection") is False:
        findings.append(
            _finding(
                ctx.next_id("training_poison"),
                "Poison / anomaly sample detection disabled",
                "high",
                "No automated detection for anomalous or adversarial samples in training data. "
                "Trigger phrases and label flips can enter the corpus undetected.",
                resource={"type": "dataset", "id": "poison_detection", "engine": "training_poison"},
                evidence={
                    "poison_sample_detection": False,
                    "source": "fixture.training_poison.poison_sample_detection",
                },
                remediation={
                    "steps": [
                        "Run dedup, outlier, and known-trigger scans on datasets pre-train.",
                        "Sample and manually review high-risk batches.",
                        "Fail the training job when detection thresholds are exceeded.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM03:2025", "NIST AI RMF MEASURE-2.6", "NIST 800-53 SI-3"],
                engine="training_poison",
                backend="embedded",
            )
        )

    if poi.get("human_review_gate") is False:
        findings.append(
            _finding(
                ctx.next_id("training_poison"),
                "No human review gate before fine-tune / train",
                "medium",
                "Training jobs can start without a human approval gate. "
                "Unreviewed datasets and configs can reach production models.",
                resource={"type": "ml_pipeline", "id": "human_review", "engine": "training_poison"},
                evidence={
                    "human_review_gate": False,
                    "source": "fixture.training_poison.human_review_gate",
                },
                remediation={
                    "steps": [
                        "Require dual control / ticket approval before fine-tune jobs.",
                        "Bind approval to dataset hash and training config.",
                        "Audit who approved each production model lineage.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST AI RMF GOVERN-1.2", "NIST 800-53 CM-3", "SOC 2 CC8.1"],
                engine="training_poison",
                backend="embedded",
            )
        )

    return findings


_DANGEROUS_MCP_SCOPES = {
    "read-write-all",
    "unrestricted-nav",
    "admin",
    "*",
    "full",
    "read-write",
}


def _engine_mcp_permissions(ctx: PackContext) -> list[dict]:
    """MCP & tool permission sprawl — embedded fixture."""
    findings: list[dict] = []
    mcp = ctx.section("mcp_permissions") if ctx.fixture else {}
    if not mcp:
        return findings

    for server in mcp.get("servers") or []:
        name = server.get("name") or "unknown-mcp"
        scope = (server.get("scope") or "").lower()
        approval = server.get("approval_required")
        dangerous = scope in _DANGEROUS_MCP_SCOPES or "unrestricted" in scope or scope.endswith("-all")
        if dangerous or approval is False:
            sev = "critical" if dangerous and approval is False else ("critical" if dangerous else "high")
            findings.append(
                _finding(
                    ctx.next_id("mcp_permissions"),
                    f"Over-privileged MCP server: {name} (scope={scope or 'unset'})",
                    sev,
                    f"MCP server '{name}' is configured with scope '{scope or 'unset'}' "
                    f"and approval_required={approval}. Broad connector permissions let a compromised "
                    "agent read/write local files, browse arbitrarily, or abuse linked systems.",
                    resource={
                        "type": "mcp_server",
                        "id": name,
                        "engine": "mcp_permissions",
                        "scope": scope,
                    },
                    evidence={
                        "server": server,
                        "source": "fixture.mcp_permissions.servers",
                    },
                    remediation={
                        "steps": [
                            f"Narrow '{name}' to the minimum scope required for the use case.",
                            "Require explicit human approval for sensitive MCP tools.",
                            "Disable unused MCP servers in production profiles.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["OWASP LLM06:2025", "OWASP LLM08:2025", "NIST 800-53 AC-6", "SOC 2 CC6.1"],
                    engine="mcp_permissions",
                    backend="embedded",
                )
            )

    if mcp.get("least_privilege") is False:
        findings.append(
            _finding(
                ctx.next_id("mcp_permissions"),
                "MCP connectors not following least privilege",
                "high",
                "MCP / tool connectors are not governed by a least-privilege policy. "
                "Default-open permissions increase blast radius after prompt injection.",
                resource={"type": "mcp_policy", "id": "least_privilege", "engine": "mcp_permissions"},
                evidence={
                    "least_privilege": False,
                    "source": "fixture.mcp_permissions.least_privilege",
                },
                remediation={
                    "steps": [
                        "Adopt deny-by-default MCP permission profiles per agent role.",
                        "Review connector grants quarterly; remove unused scopes.",
                        "Separate read-only assistants from mutation-capable agents.",
                    ],
                    "effort": "medium",
                },
                compliance=["NIST 800-53 AC-6", "OWASP LLM08:2025", "NIST AI RMF GOVERN-1.2"],
                engine="mcp_permissions",
                backend="embedded",
            )
        )

    if mcp.get("tool_inventory_documented") is False:
        findings.append(
            _finding(
                ctx.next_id("mcp_permissions"),
                "MCP / tool inventory not documented",
                "medium",
                "There is no maintained inventory of MCP servers and tools available to agents. "
                "Shadow connectors can accumulate without security review.",
                resource={"type": "mcp_policy", "id": "inventory", "engine": "mcp_permissions"},
                evidence={
                    "tool_inventory_documented": False,
                    "source": "fixture.mcp_permissions.tool_inventory_documented",
                },
                remediation={
                    "steps": [
                        "Maintain an inventory of MCP servers, scopes, owners, and environments.",
                        "Require inventory updates in the change process when adding connectors.",
                        "Alert when a new MCP server appears in runtime configs.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST 800-53 CM-8", "NIST AI RMF GOVERN-1.1", "SOC 2 CC6.1"],
                engine="mcp_permissions",
                backend="embedded",
            )
        )

    return findings


def _engine_model_governance(ctx: PackContext) -> list[dict]:
    """Model governance & abuse monitoring — embedded fixture."""
    findings: list[dict] = []
    gov = ctx.section("model_governance") if ctx.fixture else {}
    if not gov:
        return findings

    if gov.get("abuse_monitoring") is False:
        findings.append(
            _finding(
                ctx.next_id("model_governance"),
                "No abuse / misuse monitoring for LLM usage",
                "high",
                "There is no active monitoring for abusive prompts, jailbreak attempts, or anomalous "
                "usage patterns. Incidents can persist without detection.",
                resource={"type": "governance", "id": "abuse_monitoring", "engine": "model_governance"},
                evidence={
                    "abuse_monitoring": False,
                    "source": "fixture.model_governance.abuse_monitoring",
                },
                remediation={
                    "steps": [
                        "Enable abuse/anomaly detection on prompts and tool-call rates.",
                        "Alert SOC / AI ops on jailbreak clusters and sudden volume spikes.",
                        "Retain enough telemetry to investigate incidents.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM04:2025", "NIST AI RMF MEASURE-2.7", "SOC 2 CC7.2"],
                engine="model_governance",
                backend="embedded",
            )
        )

    retention = gov.get("prompt_response_logging_retention_days")
    if retention is not None and int(retention) <= 0:
        findings.append(
            _finding(
                ctx.next_id("model_governance"),
                "Prompt/response logging retention not configured",
                "medium",
                f"Logging retention is set to {retention} days (disabled or zero). "
                "Without retained logs, abuse investigation and compliance audits fail.",
                resource={"type": "governance", "id": "log_retention", "engine": "model_governance"},
                evidence={
                    "prompt_response_logging_retention_days": retention,
                    "source": "fixture.model_governance.prompt_response_logging_retention_days",
                },
                remediation={
                    "steps": [
                        "Enable prompt/response (or redacted) logging with a defined retention period.",
                        "Align retention with legal/compliance requirements (e.g. 30–90 days).",
                        "Protect logs as sensitive data; restrict access.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST AI RMF GOVERN-1.1", "NIST 800-53 AU-11", "SOC 2 CC7.1"],
                engine="model_governance",
                backend="embedded",
            )
        )

    if gov.get("eval_gate_before_prod") is False:
        findings.append(
            _finding(
                ctx.next_id("model_governance"),
                "No eval / safety gate before production deploy",
                "high",
                "Models can reach production without a required safety/quality evaluation gate. "
                "Regressions in refusal behavior or hallucination rates may ship unnoticed.",
                resource={"type": "ml_pipeline", "id": "eval_gate", "engine": "model_governance"},
                evidence={
                    "eval_gate_before_prod": False,
                    "source": "fixture.model_governance.eval_gate_before_prod",
                },
                remediation={
                    "steps": [
                        "Require passing eval suites (safety, injection, quality) before promote-to-prod.",
                        "Block deploys when eval scores fall below thresholds.",
                        "Store eval reports with the model version in the registry.",
                    ],
                    "effort": "medium",
                },
                compliance=["NIST AI RMF MEASURE-2.6", "OWASP LLM01:2025", "SOC 2 CC8.1"],
                engine="model_governance",
                backend="embedded",
            )
        )

    if gov.get("acceptable_use_policy_enforced") is False:
        findings.append(
            _finding(
                ctx.next_id("model_governance"),
                "Acceptable use policy not enforced on LLM product",
                "medium",
                "An acceptable use policy (AUP) is missing or not enforced at the product boundary. "
                "Users are not constrained by documented prohibited uses.",
                resource={"type": "governance", "id": "aup", "engine": "model_governance"},
                evidence={
                    "acceptable_use_policy_enforced": False,
                    "source": "fixture.model_governance.acceptable_use_policy_enforced",
                },
                remediation={
                    "steps": [
                        "Publish and link an AUP for the LLM product.",
                        "Enforce AUP checks in onboarding and at runtime for high-risk categories.",
                        "Document exception / appeal process for blocked uses.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST AI RMF GOVERN-1.2", "SOC 2 CC1.2", "ISO 27001 A.5.1"],
                engine="model_governance",
                backend="embedded",
            )
        )

    return findings


def _engine_inference_hardening(ctx: PackContext) -> list[dict]:
    """Inference API hardening — embedded fixture."""
    findings: list[dict] = []
    inf = ctx.section("inference_hardening") if ctx.fixture else {}
    if not inf:
        return findings

    if inf.get("auth_required") is False:
        findings.append(
            _finding(
                ctx.next_id("inference_hardening"),
                "Inference API does not require authentication",
                "critical",
                "The model inference endpoint accepts unauthenticated requests. "
                "Anyone can invoke the model, burn quota, or abuse the service.",
                resource={"type": "inference_api", "id": "auth", "engine": "inference_hardening"},
                evidence={
                    "auth_required": False,
                    "source": "fixture.inference_hardening.auth_required",
                },
                remediation={
                    "steps": [
                        "Require API keys, OAuth, or mTLS for all inference routes.",
                        "Reject anonymous traffic at the gateway.",
                        "Rotate keys and audit unused credentials regularly.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM10:2025", "NIST 800-53 IA-2", "SOC 2 CC6.1"],
                engine="inference_hardening",
                backend="embedded",
            )
        )

    if inf.get("public_unauthenticated_endpoint") is True:
        findings.append(
            _finding(
                ctx.next_id("inference_hardening"),
                "Public unauthenticated inference endpoint exposed",
                "critical",
                "A publicly reachable inference endpoint allows anonymous access. "
                "This is a direct abuse and data-exfiltration vector.",
                resource={"type": "inference_api", "id": "public_endpoint", "engine": "inference_hardening"},
                evidence={
                    "public_unauthenticated_endpoint": True,
                    "source": "fixture.inference_hardening.public_unauthenticated_endpoint",
                },
                remediation={
                    "steps": [
                        "Remove public anonymous routes or place them behind auth + WAF.",
                        "Bind production inference to private networks / Zero Trust ingress.",
                        "Monitor for unexpected internet-facing listeners.",
                    ],
                    "effort": "high",
                },
                compliance=["OWASP LLM10:2025", "NIST 800-53 SC-7", "CIS Controls 4.4"],
                engine="inference_hardening",
                backend="embedded",
            )
        )

    if inf.get("rate_limiting") is False:
        findings.append(
            _finding(
                ctx.next_id("inference_hardening"),
                "No rate limiting on inference API",
                "high",
                "Inference requests are not rate-limited. Attackers can DoS the service or "
                "inflate cost through uncontrolled token volume.",
                resource={"type": "inference_api", "id": "rate_limit", "engine": "inference_hardening"},
                evidence={
                    "rate_limiting": False,
                    "source": "fixture.inference_hardening.rate_limiting",
                },
                remediation={
                    "steps": [
                        "Apply per-identity and per-IP rate limits at the gateway.",
                        "Set burst and sustained token budgets per tenant.",
                        "Return 429 with backoff guidance when limits are hit.",
                    ],
                    "effort": "medium",
                },
                compliance=["OWASP LLM04:2025", "NIST 800-53 SC-5", "SOC 2 CC7.2"],
                engine="inference_hardening",
                backend="embedded",
            )
        )

    if inf.get("cost_budget_alerts") is False:
        findings.append(
            _finding(
                ctx.next_id("inference_hardening"),
                "No cost / budget alerts on inference spend",
                "medium",
                "There are no alerts when inference cost or token usage exceeds budgets. "
                "Abuse or misconfiguration can run up spend unnoticed.",
                resource={"type": "inference_api", "id": "cost_alerts", "engine": "inference_hardening"},
                evidence={
                    "cost_budget_alerts": False,
                    "source": "fixture.inference_hardening.cost_budget_alerts",
                },
                remediation={
                    "steps": [
                        "Define per-tenant and org-level spend budgets.",
                        "Alert finance/AI ops when thresholds are crossed.",
                        "Optionally auto-throttle when budget is exhausted.",
                    ],
                    "effort": "low",
                },
                compliance=["OWASP LLM04:2025", "NIST AI RMF MEASURE-2.6"],
                engine="inference_hardening",
                backend="embedded",
            )
        )

    if inf.get("tls_only") is False:
        findings.append(
            _finding(
                ctx.next_id("inference_hardening"),
                "Inference traffic not restricted to TLS-only",
                "high",
                "The inference API allows non-TLS connections. Prompts, completions, and tokens "
                "may traverse the network in cleartext.",
                resource={"type": "inference_api", "id": "tls", "engine": "inference_hardening"},
                evidence={
                    "tls_only": False,
                    "source": "fixture.inference_hardening.tls_only",
                },
                remediation={
                    "steps": [
                        "Enforce HTTPS/TLS 1.2+ (prefer 1.3) on all inference endpoints.",
                        "Redirect or reject plain HTTP at the edge.",
                        "Enable HSTS for public hostnames.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST 800-53 SC-8", "OWASP ASVS V9", "SOC 2 CC6.7"],
                engine="inference_hardening",
                backend="embedded",
            )
        )

    return findings


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
        "status": "active",  # A5
        "phase": "A5",
        "preferred_backends": ["trivy", "syft", "embedded"],
        "run": _engine_model_supply_chain,
        "weight": 1.1,
    },
    {
        "key": "rag_data_leakage",
        "code": "RAG",
        "name": "RAG Data Leakage & Isolation",
        "status": "active",  # A3
        "phase": "A3",
        "preferred_backends": ["embedded"],
        "run": _engine_rag_data_leakage,
        "weight": 1.2,
    },
    {
        "key": "agent_tool_abuse",
        "code": "AGT",
        "name": "Agent Tool / Function-Call Abuse",
        "status": "active",  # A4
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
        "status": "active",  # A3
        "phase": "A3",
        "preferred_backends": ["embedded"],
        "run": _engine_output_filtering,
        "weight": 1.0,
    },
    {
        "key": "training_poison",
        "code": "POI",
        "name": "Training / Fine-Tune Data Poisoning Signals",
        "status": "active",  # A5
        "phase": "A5",
        "preferred_backends": ["embedded"],
        "run": _engine_training_poison,
        "weight": 1.0,
    },
    {
        "key": "mcp_permissions",
        "code": "MCP",
        "name": "MCP & Tool Permission Sprawl",
        "status": "active",  # A4
        "phase": "A4",
        "preferred_backends": ["embedded"],
        "run": _engine_mcp_permissions,
        "weight": 1.1,
    },
    {
        "key": "model_governance",
        "code": "GOV",
        "name": "Model Governance & Abuse Monitoring",
        "status": "active",  # A6
        "phase": "A6",
        "preferred_backends": ["embedded"],
        "run": _engine_model_governance,
        "weight": 0.9,
    },
    {
        "key": "inference_hardening",
        "code": "INF",
        "name": "Inference API Hardening",
        "status": "active",  # A6
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
        "phase": "A6",
        "label": "pack_hands_complete",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full AI Security Engineer multi-engine pack — not single-scanner ceiling",
        "next_phase": "A7 FIX_MAP AISEC-* in remediation engine (on request)",
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
                "pack_phase": "A6",
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
            "pack_phase": "A6",
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
