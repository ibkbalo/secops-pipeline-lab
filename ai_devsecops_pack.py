# ai_devsecops_pack.py
# Sentinel Stacks — DevSecOps Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase D1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase D2: Secrets (SEC) + CI/CD (CICD) engines ACTIVE — embedded fixture
#            + optional gitleaks/actionlint live backends.
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
VERSION = "0.2.0-d2"
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


def _sev_for_secret_rule(rule: str) -> str:
    r = (rule or "").lower()
    if any(x in r for x in ("aws", "private-key", "rsa", "ssh", "github-pat", "ghp_", "stripe", "slack-token")):
        return "critical"
    if any(x in r for x in ("password", "secret", "token", "api-key", "apikey", "credential", "jwt")):
        return "high"
    return "high"


def _engine_secrets(ctx: PackContext) -> list[dict]:
    """Secrets & credential exposure — embedded fixture + optional gitleaks live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "secrets"),
        ctx.backends,
    )
    sec = ctx.section("secrets") if ctx.fixture else {}

    # Prefer fixture when present (mock/hybrid deterministic path)
    if sec:
        for item in sec.get("tracked_files_with_secrets") or []:
            path = item.get("path") or "unknown"
            for m in item.get("matches") or []:
                rule = m.get("rule") or "secret-match"
                sev = _sev_for_secret_rule(rule)
                line = m.get("line")
                snippet = (m.get("snippet") or "")[:120]
                findings.append(
                    _finding(
                        ctx.next_id("secrets"),
                        f"Secret in tracked file: {rule}",
                        sev,
                        f"Tracked path '{path}' contains a credential matched by rule '{rule}'. "
                        f"Remove from VCS, rotate the secret, and enable history scanning.",
                        resource={
                            "type": "file",
                            "id": path,
                            "engine": "secrets",
                            "line": line,
                        },
                        evidence={
                            "path": path,
                            "line": line,
                            "rule": rule,
                            "snippet": snippet,
                            "source": "fixture.tracked_files_with_secrets",
                        },
                        remediation={
                            "steps": [
                                f"Remove '{path}' from the working tree and git history (filter-repo/BFG).",
                                "Rotate the exposed credential immediately in the provider console.",
                                "Add path patterns to .gitignore and enable org secret scanning / push protection.",
                                "Re-run scan_devsecops_pack (secrets engine) to verify clean.",
                            ],
                            "effort": "high",
                        },
                        compliance=[
                            "NIST 800-53 IA-5",
                            "NIST 800-53 SI-2",
                            "SOC 2 CC6.1",
                            "ISO 27001 A.9.4.3",
                            "CIS Software Supply Chain 2.4",
                        ],
                        engine="secrets",
                        backend="embedded",
                    )
                )

        for env in sec.get("ci_env_plaintext") or []:
            wf = env.get("workflow") or "unknown-workflow"
            key = env.get("key") or "SECRET"
            findings.append(
                _finding(
                    ctx.next_id("secrets"),
                    f"CI plaintext secret env: {key}",
                    "critical",
                    f"Workflow '{wf}' appears to materialize '{key}' as plaintext env "
                    f"(value_present={env.get('value_present')}). Prefer encrypted secrets / OIDC.",
                    resource={"type": "workflow", "id": wf, "engine": "secrets", "key": key},
                    evidence={
                        "workflow": wf,
                        "key": key,
                        "value_present": env.get("value_present"),
                        "source": "fixture.ci_env_plaintext",
                    },
                    remediation={
                        "steps": [
                            f"Move '{key}' to the platform secret store (GitHub Actions secrets).",
                            "Reference via ${{ secrets.NAME }} — never hardcode values in YAML.",
                            "Prefer OIDC cloud auth over long-lived static keys in CI.",
                            "Audit workflow run logs for prior leakage.",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "NIST 800-53 IA-5",
                        "CIS GitHub Actions 1.4",
                        "SOC 2 CC6.1",
                    ],
                    engine="secrets",
                    backend="embedded",
                )
            )

        for g in sec.get("gitleaks_findings") or []:
            rule = g.get("RuleID") or g.get("rule") or "gitleaks"
            file_path = g.get("File") or g.get("path") or "unknown"
            line = g.get("StartLine") or g.get("line")
            findings.append(
                _finding(
                    ctx.next_id("secrets"),
                    f"Gitleaks detection: {rule}",
                    _sev_for_secret_rule(str(rule)),
                    f"Gitleaks-style finding on '{file_path}' rule={rule}.",
                    resource={"type": "file", "id": file_path, "engine": "secrets", "line": line},
                    evidence={"gitleaks": g, "source": "fixture.gitleaks_findings"},
                    engine="secrets",
                    backend="embedded",
                )
            )

        if sec.get("secret_scanning_enabled") is False:
            findings.append(
                _finding(
                    ctx.next_id("secrets"),
                    "Repository secret scanning disabled",
                    "high",
                    "Secret scanning / push protection is not enabled on the repository. "
                    "Enable advanced security secret scanning to block credential commits.",
                    resource={"type": "repo_setting", "id": "secret_scanning", "engine": "secrets"},
                    evidence={
                        "secret_scanning_enabled": False,
                        "history_scan_required": sec.get("history_scan_required"),
                        "source": "fixture.secret_scanning_enabled",
                    },
                    remediation={
                        "steps": [
                            "Enable GitHub secret scanning and push protection (or equivalent).",
                            "Run a one-time history scan (gitleaks detect --log-opts=--all).",
                            "Document exception process for false positives.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS Software Supply Chain 2.4", "NIST 800-53 SI-4"],
                    engine="secrets",
                    backend="embedded",
                )
            )

        return findings

    # Live path without fixture: optional gitleaks when installed
    if ctx.mode == "live" and backend == "gitleaks":
        gl = (ctx.backends.get("gitleaks") or {}).get("path")
        target = Path(ctx.target)
        if gl and target.exists():
            try:
                cmd = [gl, "detect", "--source", str(target), "--report-format", "json", "--no-git", "-v"]
                # Prefer git-aware when .git present
                if (target / ".git").exists():
                    cmd = [gl, "detect", "--source", str(target), "--report-format", "json", "-v"]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
                raw = (p.stdout or "").strip()
                if raw:
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        data = []
                    if isinstance(data, dict):
                        data = data.get("findings") or data.get("leaks") or []
                    for g in data or []:
                        rule = g.get("RuleID") or g.get("Description") or "gitleaks"
                        file_path = g.get("File") or "unknown"
                        line = g.get("StartLine")
                        findings.append(
                            _finding(
                                ctx.next_id("secrets"),
                                f"Gitleaks: {rule}",
                                _sev_for_secret_rule(str(rule)),
                                f"Live gitleaks reported rule '{rule}' in '{file_path}'.",
                                resource={"type": "file", "id": file_path, "engine": "secrets", "line": line},
                                evidence={"gitleaks": g, "source": "live.gitleaks"},
                                engine="secrets",
                                backend="gitleaks",
                            )
                        )
            except Exception:
                pass
    return findings


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
    """CI/CD pipeline hardening — workflows + branch protection (embedded fixture)."""
    findings: list[dict] = []
    cicd = ctx.section("cicd") if ctx.fixture else {}
    if not cicd:
        return findings

    platform = cicd.get("platform") or "unknown"
    for wf in cicd.get("workflows") or []:
        path = wf.get("path") or "unknown-workflow"
        perms = wf.get("permissions")
        if perms in ("write-all", "write", "*") or (
            isinstance(perms, str) and "write-all" in perms.lower()
        ):
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"Overbroad workflow permissions: {path}",
                    "critical",
                    f"Workflow '{path}' sets permissions='{perms}'. Use least-privilege "
                    f"(contents: read default; grant write only on need-to-know jobs).",
                    resource={"type": "workflow", "id": path, "engine": "cicd", "platform": platform},
                    evidence={
                        "path": path,
                        "permissions": perms,
                        "source": "fixture.cicd.workflows.permissions",
                    },
                    remediation={
                        "steps": [
                            "Set top-level permissions: contents: read (and id-token: write only if OIDC).",
                            "Elevate per job only where required (packages: write, contents: write on release).",
                            "Block write-all via org policy / actionlint custom checks.",
                        ],
                        "effort": "low",
                    },
                    compliance=[
                        "CIS GitHub Actions 1.1",
                        "NIST 800-53 AC-6",
                        "SLSA builders guide",
                    ],
                    engine="cicd",
                    backend="embedded",
                )
            )

        actions = wf.get("actions") or []
        unpinned = [a for a in actions if not a.get("pinned_sha")]
        if unpinned:
            uses_list = [a.get("uses") for a in unpinned]
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"Unpinned Actions in {path}",
                    "high",
                    f"Workflow '{path}' uses {len(unpinned)} action(s) without full commit SHA pin: "
                    f"{', '.join(str(u) for u in uses_list[:6])}.",
                    resource={"type": "workflow", "id": path, "engine": "cicd"},
                    evidence={
                        "path": path,
                        "unpinned": uses_list,
                        "source": "fixture.cicd.workflows.actions",
                    },
                    remediation={
                        "steps": [
                            "Pin third-party actions to full 40-char commit SHA.",
                            "Optionally keep a version tag comment for human readability.",
                            "Enable Dependabot for github-actions ecosystem.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["CIS GitHub Actions 1.2", "SLSA L2+"],
                    engine="cicd",
                    backend="embedded",
                )
            )

        if wf.get("secrets_in_env_plain") is True:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"Secrets exposed via plain env: {path}",
                    "critical",
                    f"Workflow '{path}' flags secrets_in_env_plain=true — credentials may leak "
                    f"into logs, fork PRs, or intermediate steps.",
                    resource={"type": "workflow", "id": path, "engine": "cicd"},
                    evidence={
                        "path": path,
                        "secrets_in_env_plain": True,
                        "source": "fixture.cicd.workflows.secrets_in_env_plain",
                    },
                    remediation={
                        "steps": [
                            "Remove literal secret values from env: blocks.",
                            "Use ${{ secrets.* }} and mask sensitive outputs.",
                            "Avoid pull_request_target with untrusted checkout + secrets.",
                        ],
                        "effort": "high",
                    },
                    compliance=["CIS GitHub Actions 1.4", "NIST 800-53 IA-5"],
                    engine="cicd",
                    backend="embedded",
                )
            )

        jobs = wf.get("jobs") or []
        sec_jobs = wf.get("security_jobs") or []
        if jobs and not sec_jobs:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"No security jobs in pipeline: {path}",
                    "high",
                    f"Workflow '{path}' runs jobs {jobs} but has empty security_jobs. "
                    f"Add gitleaks/trivy/SAST (or org reusable workflow) as required checks.",
                    resource={"type": "workflow", "id": path, "engine": "cicd"},
                    evidence={
                        "path": path,
                        "jobs": jobs,
                        "security_jobs": sec_jobs,
                        "source": "fixture.cicd.workflows.security_jobs",
                    },
                    remediation={
                        "steps": [
                            "Add secrets scan (gitleaks), SCA/container (trivy), and SAST jobs.",
                            "Mark security jobs as required status checks on protected branches.",
                            "Fail the pipeline on critical/high findings (policy gate).",
                        ],
                        "effort": "medium",
                    },
                    compliance=["NIST 800-53 SA-11", "CIS Software Supply Chain 4.1"],
                    engine="cicd",
                    backend="embedded",
                )
            )

        for pat in wf.get("dangerous_patterns") or []:
            sev = "critical" if pat in ("curl-bash-install", "pull_request_target-untrusted") else "high"
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"Dangerous CI pattern '{pat}': {path}",
                    sev,
                    f"Workflow '{path}' contains dangerous pattern '{pat}'.",
                    resource={"type": "workflow", "id": path, "engine": "cicd"},
                    evidence={
                        "path": path,
                        "pattern": pat,
                        "source": "fixture.cicd.workflows.dangerous_patterns",
                    },
                    remediation={
                        "steps": [
                            "Replace curl|bash installers with pinned package installs or verified checksums.",
                            "Review pull_request_target usage against GitHub security best practices.",
                            "Prefer official hardened runners / reusable workflows.",
                        ],
                        "effort": "medium",
                    },
                    compliance=["CIS GitHub Actions 1.3", "NIST 800-53 SI-7"],
                    engine="cicd",
                    backend="embedded",
                )
            )

        if wf.get("pull_request_target") is True:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"pull_request_target enabled: {path}",
                    "high",
                    f"Workflow '{path}' uses pull_request_target which runs with base-repo secrets — "
                    f"high risk if combined with untrusted checkout.",
                    resource={"type": "workflow", "id": path, "engine": "cicd"},
                    evidence={"path": path, "pull_request_target": True},
                    engine="cicd",
                    backend="embedded",
                )
            )

    bp = cicd.get("branch_protection") or {}
    for branch, rules in bp.items():
        if not isinstance(rules, dict):
            continue
        if rules.get("allow_force_push") is True:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"Force push allowed on '{branch}'",
                    "critical",
                    f"Branch '{branch}' allows force push. Attackers or mistakes can rewrite history "
                    f"and bypass reviews.",
                    resource={"type": "branch_protection", "id": branch, "engine": "cicd"},
                    evidence={
                        "branch": branch,
                        "allow_force_push": True,
                        "source": "fixture.cicd.branch_protection",
                    },
                    remediation={
                        "steps": [
                            f"Disable force push on '{branch}' (and tags).",
                            "Restrict who can push; require linear history if appropriate.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.9", "NIST 800-53 CM-3"],
                    engine="cicd",
                    backend="embedded",
                )
            )
        if rules.get("required_pull_request") is False:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"PR review not required on '{branch}'",
                    "high",
                    f"Branch '{branch}' does not require pull requests before merge.",
                    resource={"type": "branch_protection", "id": branch, "engine": "cicd"},
                    evidence={
                        "branch": branch,
                        "required_pull_request": False,
                        "source": "fixture.cicd.branch_protection",
                    },
                    remediation={
                        "steps": [
                            "Enable 'Require a pull request before merging'.",
                            "Require at least 1 (prefer 2) approving reviews on default branch.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.3", "SOC 2 CC8.1"],
                    engine="cicd",
                    backend="embedded",
                )
            )
        checks = rules.get("required_status_checks")
        if isinstance(checks, list) and len(checks) == 0:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"No required status checks on '{branch}'",
                    "high",
                    f"Branch '{branch}' has empty required_status_checks — CI security gates can be skipped.",
                    resource={"type": "branch_protection", "id": branch, "engine": "cicd"},
                    evidence={
                        "branch": branch,
                        "required_status_checks": checks,
                        "source": "fixture.cicd.branch_protection",
                    },
                    remediation={
                        "steps": [
                            "Require security job names (gitleaks, trivy, sast, build) as status checks.",
                            "Enable 'Require branches to be up to date before merging'.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.4", "NIST 800-53 SA-11"],
                    engine="cicd",
                    backend="embedded",
                )
            )
        if rules.get("require_codeowner_review") is False:
            findings.append(
                _finding(
                    ctx.next_id("cicd"),
                    f"CODEOWNER review not required on '{branch}'",
                    "medium",
                    f"Branch '{branch}' does not require code owner review — sensitive paths may merge unreviewed.",
                    resource={"type": "branch_protection", "id": branch, "engine": "cicd"},
                    evidence={
                        "branch": branch,
                        "require_codeowner_review": False,
                        "source": "fixture.cicd.branch_protection",
                    },
                    remediation={
                        "steps": [
                            "Add CODEOWNERS for critical paths (infra, workflows, auth).",
                            "Enable 'Require review from Code Owners'.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.6"],
                    engine="cicd",
                    backend="embedded",
                )
            )

    return findings


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
        "status": "active",  # D2
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
        "status": "active",  # D2
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
    pct = round((active / total) * 100) if total else 0
    return {
        "phase": "D2",
        "label": "secrets_cicd_active",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full multi-engine pack — not 18-check ceiling",
        "next_phase": "D3 sca + container + iac (trivy)",
        "active_engines": sorted(e["key"] for e in engine_results if e.get("status") == "active"),
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
                "pack_phase": "D2",
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

    # Active engines with findings drive status; stubs alone do not force failure
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
            "pack_phase": "D2",
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
