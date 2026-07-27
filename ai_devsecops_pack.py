# ai_devsecops_pack.py
# Sentinel Stacks — DevSecOps Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase D1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Engines fill in D2+ (secrets, sca/trivy, container, iac, cicd, …).
# Enterprise bar: no 18-check ceiling. Capacity grows by engine.

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import datetime
from pathlib import Path
from typing import Any, Callable

TOOL_ID = "scan_devsecops_pack"
VERSION = "0.1.0-d1"
DOMAIN = "devsecops"
SUBDOMAIN = "devsecops/pack"
SENTINEL = "infrastructure"
TIER = 1
TAGS = [
    "devsecops",
    "multi-engine",
    "cicd",
    "secrets",
    "sca",
    "container",
    "iac",
    "supply-chain",
    "trivy",
    "gitleaks",
    "enterprise",
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

# ── Finding ID scheme (locked) ───────────────────────────────────────────────
# DEVSEC-{ENGINE}-{NNN}
# ENGINE codes are stable forever; NNN grows without artificial ceilings.
ENGINE_CODES = {
    "secrets": "SEC",
    "sca": "SCA",
    "container": "CTR",
    "iac": "IAC",
    "sast": "SAST",
    "cicd": "CICD",
    "supply_chain": "SC",
    "policy": "POL",
    "repo_gov": "GOV",
    "release": "REL",
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
    """Discover enterprise scanners available on PATH (optional live backends)."""
    backends: dict[str, dict[str, Any]] = {}

    gl = _which("gitleaks")
    backends["gitleaks"] = {
        "available": bool(gl),
        "path": gl,
        "version": _tool_version([gl, "version"]) if gl else None,
        "engines": ["secrets"],
    }

    trivy = _which("trivy")
    backends["trivy"] = {
        "available": bool(trivy),
        "path": trivy,
        "version": _tool_version([trivy, "--version"]) if trivy else None,
        "engines": ["sca", "container", "iac"],
    }

    # Optional peers (auto-wire when present; embedded fallback always wins offline)
    for name, eng in (
        ("checkov", ["iac", "policy"]),
        ("semgrep", ["sast"]),
        ("syft", ["supply_chain", "sca"]),
        ("grype", ["sca", "container"]),
        ("actionlint", ["cicd"]),
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
        return f"DEVSEC-{code}-{self._counters[engine_key]:03d}"

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
        or {"type": "devsecops", "id": fid, "engine": engine},
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
                "Review evidence paths and suppress only with documented risk acceptance.",
                "Apply the matching hardening kit artifact when available.",
                "Re-run scan_devsecops_pack to verify the control passes.",
            ],
            "effort": "medium",
        },
        "compliance": compliance
        or [
            "NIST 800-53 SI-2",
            "NIST 800-53 SA-11",
            "SOC 2 CC7.1",
            "ISO 27001 A.14.2.1",
        ],
    }


# ── Engine protocol ──────────────────────────────────────────────────────────
# status:
#   active  — emits real findings this release
#   stub    — registered, executes, returns [] until filled (D2+)
# backend preference: live tool if available else embedded

EngineFn = Callable[[PackContext], list[dict]]


def _engine_secrets(ctx: PackContext) -> list[dict]:
    """D2 will implement gitleaks + embedded entropy/pattern. D1: skeleton only."""
    _ = ctx
    return []


def _engine_sca(ctx: PackContext) -> list[dict]:
    """D3: trivy fs / OSV / lockfile. D1 stub."""
    _ = ctx
    return []


def _engine_container(ctx: PackContext) -> list[dict]:
    """D3: trivy image + Dockerfile policy. D1 stub."""
    _ = ctx
    return []


def _engine_iac(ctx: PackContext) -> list[dict]:
    """D4: trivy config / checkov-class. D1 stub."""
    _ = ctx
    return []


def _engine_sast(ctx: PackContext) -> list[dict]:
    """D6: semgrep-class / language rules. D1 stub."""
    _ = ctx
    return []


def _engine_cicd(ctx: PackContext) -> list[dict]:
    """D2: GitHub Actions / pipeline hardening. D1 stub."""
    _ = ctx
    return []


def _engine_supply_chain(ctx: PackContext) -> list[dict]:
    """D5: SBOM / cosign hooks. D1 stub."""
    _ = ctx
    return []


def _engine_policy(ctx: PackContext) -> list[dict]:
    """D4: OPA/Conftest-class. D1 stub."""
    _ = ctx
    return []


def _engine_repo_gov(ctx: PackContext) -> list[dict]:
    """D5: CODEOWNERS / branch protection. D1 stub."""
    _ = ctx
    return []


def _engine_release(ctx: PackContext) -> list[dict]:
    """D5: release attestation / artifact retention. D1 stub."""
    _ = ctx
    return []


# Single source of truth — grow without rebuilding the facade
ENGINE_REGISTRY: list[dict[str, Any]] = [
    {
        "key": "secrets",
        "code": "SEC",
        "name": "Secrets & Credential Exposure",
        "status": "stub",  # → active in D2
        "phase": "D2",
        "preferred_backends": ["gitleaks", "embedded"],
        "run": _engine_secrets,
        "weight": 1.2,
    },
    {
        "key": "sca",
        "code": "SCA",
        "name": "Software Composition Analysis",
        "status": "stub",  # → D3
        "phase": "D3",
        "preferred_backends": ["trivy", "grype", "embedded"],
        "run": _engine_sca,
        "weight": 1.2,
    },
    {
        "key": "container",
        "code": "CTR",
        "name": "Container Image & Dockerfile",
        "status": "stub",  # → D3
        "phase": "D3",
        "preferred_backends": ["trivy", "embedded"],
        "run": _engine_container,
        "weight": 1.1,
    },
    {
        "key": "iac",
        "code": "IAC",
        "name": "Infrastructure as Code",
        "status": "stub",  # → D4
        "phase": "D4",
        "preferred_backends": ["trivy", "checkov", "embedded"],
        "run": _engine_iac,
        "weight": 1.1,
    },
    {
        "key": "sast",
        "code": "SAST",
        "name": "Static Application Security (pipeline-side)",
        "status": "stub",  # → D6
        "phase": "D6",
        "preferred_backends": ["semgrep", "embedded"],
        "run": _engine_sast,
        "weight": 1.0,
    },
    {
        "key": "cicd",
        "code": "CICD",
        "name": "CI/CD Pipeline Hardening",
        "status": "stub",  # → D2
        "phase": "D2",
        "preferred_backends": ["actionlint", "embedded"],
        "run": _engine_cicd,
        "weight": 1.2,
    },
    {
        "key": "supply_chain",
        "code": "SC",
        "name": "Supply Chain & SBOM",
        "status": "stub",  # → D5
        "phase": "D5",
        "preferred_backends": ["syft", "embedded"],
        "run": _engine_supply_chain,
        "weight": 1.0,
    },
    {
        "key": "policy",
        "code": "POL",
        "name": "Policy as Code",
        "status": "stub",  # → D4
        "phase": "D4",
        "preferred_backends": ["checkov", "embedded"],
        "run": _engine_policy,
        "weight": 0.9,
    },
    {
        "key": "repo_gov",
        "code": "GOV",
        "name": "Repository Governance",
        "status": "stub",  # → D5
        "phase": "D5",
        "preferred_backends": ["embedded"],
        "run": _engine_repo_gov,
        "weight": 0.9,
    },
    {
        "key": "release",
        "code": "REL",
        "name": "Release & Artifact Integrity",
        "status": "stub",  # → D5
        "phase": "D5",
        "preferred_backends": ["embedded"],
        "run": _engine_release,
        "weight": 0.9,
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

    # Explicit mock_file path
    if mock_file:
        path = Path(str(mock_file))
        if not path.is_file():
            # try cwd / scripts dir neighbors
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

    # target itself is a fixture file
    tpath = Path(str(target))
    if tpath.is_file() and tpath.suffix.lower() == ".json":
        try:
            data = json.loads(tpath.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and (
                data.get("_devsecops_fixture")
                or data.get("engines")
                or data.get("repo")
            ):
                return data, "mock", None
        except Exception:
            pass

    # mock=True without file → default vulnerable fixture name
    if mock_flag is True:
        for candidate in (
            "mock_devsecops_vulnerable.json",
            Path(__file__).resolve().parent / "mock_devsecops_vulnerable.json",
        ):
            p = Path(candidate)
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8-sig"))
                return data, "mock", None
        return None, "mock", "mock=True but mock_devsecops_vulnerable.json not found"

    # live path: target is a directory/repo root (engines use when active)
    return None, "live", None


def _risk_score(findings: list[dict]) -> int:
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(str(f.get("severity", "info")).lower(), 0)
    return max(0, 100 - penalty)


def _domain_scores(
    engine_results: list[dict],
) -> dict[str, Any]:
    """Per-engine score shell. 100 when stub/no findings; drops when findings exist."""
    out = {}
    for er in engine_results:
        key = er["key"]
        findings = er.get("findings") or []
        if er.get("status") == "stub" and not findings:
            # not yet scored — wide-open debt is not silently "100 secure"
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
    return {
        "phase": "D1",
        "label": "pack_skeleton",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": round((active / total) * 100) if total else 0,
        "enterprise_bar": "full multi-engine pack — not 18-check ceiling",
        "next_phase": "D2 secrets + cicd engines",
    }


def run(params: dict) -> dict:
    """
    TOOL_STANDARDS entrypoint.

    params:
      target: repo path, label, or fixture .json path
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
                "llm_summary": f"DevSecOps pack failed: {err}",
                "pack_phase": "D1",
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
            # annotate backend on each finding evidence if missing
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

    # Summary counts
    crit = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    med = sum(1 for f in all_findings if f.get("severity") == "medium")
    low = sum(1 for f in all_findings if f.get("severity") == "low")
    info = sum(1 for f in all_findings if f.get("severity") == "info")
    total = len(all_findings)
    score = _risk_score(all_findings)
    readiness = _pack_readiness(engine_results)
    domain_scores = _domain_scores(engine_results)

    # D1: good skeleton == structural success even if all engines stub
    if errors and not all_findings and readiness["engines_active"] == 0:
        status = "partial" if len(errors) < len(engine_results) else "failed"
    elif crit or high:
        status = "failed" if crit else "partial"
    else:
        status = "success"

    duration = (_now() - started).total_seconds()
    live_tools = [k for k, v in backends.items() if k != "embedded" and v.get("available")]
    llm = (
        f"DevSecOps pack {VERSION} ({readiness['label']}) scanned '{target}' mode={mode}. "
        f"Engines: {readiness['engines_active']} active / {readiness['engines_stub']} stub "
        f"/ {readiness['engines_total']} total ({readiness['complete_pct']}% pack complete). "
        f"Live backends detected: {', '.join(live_tools) if live_tools else 'none (embedded only)'}. "
        f"Findings: {total} (C:{crit} H:{high} M:{med} L:{low} I:{info}). "
        f"Risk score {score}/100. "
        f"Next: {readiness['next_phase']}."
    )

    return {
        "tool_id": TOOL_ID,
        "version": VERSION,
        "execution": {
            "timestamp": _ts(),
            "duration_seconds": round(duration, 3),
            "target": target if mode != "mock" else (fixture or {}).get("repo", {}).get("name", target),
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
            "checks_passed": 0,  # meaningful once engines active
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
            "pack_phase": "D1",
            "pack_readiness": readiness,
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
            "id_scheme": "DEVSEC-{ENGINE_CODE}-{NNN}",
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
    flags = set(a for a in sys.argv[1:] if a.startswith("--"))
    target = args[0] if args else "."
    mock_file = args[1] if len(args) > 1 else None

    params: dict[str, Any] = {"target": target}
    if mock_file:
        params["mock_file"] = mock_file
    elif "--mock" in flags or target in ("mock", "mock-vuln", "mock-vulnerable"):
        params["mock"] = True
        params["target"] = "mock-devsecops"
    elif target in ("mock-clean",):
        params["mock_file"] = "mock_devsecops_clean.json"
        params["target"] = "mock-devsecops-clean"

    result = run(params)
    print(json.dumps(result, indent=2))
    # exit non-zero only on hard failure
    sys.exit(0 if result.get("execution", {}).get("status") != "failed" else 1)
