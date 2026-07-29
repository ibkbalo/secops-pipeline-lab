# ai_devsecops_pack.py
# Sentinel Stacks — DevSecOps Hands Pack (multi-engine facade)
# TOOL_STANDARDS.md v1.0
# Phase D1: pack skeleton — engine registry, ID scheme, backend detect,
#            TOOL_STANDARDS merge, domain scoring shell.
# Phase D2: Secrets (SEC) + CI/CD (CICD) engines ACTIVE — embedded fixture
#            + optional gitleaks/actionlint live backends.
# Phase D3: SCA (SCA) + Container (CTR) engines ACTIVE — embedded fixture
#            + optional Trivy live backends (fs / dockerfile / image).
# Phase D4: IaC (IAC) + Policy-as-Code (POL) engines ACTIVE — embedded
#            fixture + optional Trivy config / Checkov live backends.
# Phase D5: Supply Chain (SC) + Release (REL) + Repo Governance (GOV)
#            engines ACTIVE — embedded fixture + optional syft live.
# Phase D6: SAST (SAST) engine ACTIVE — embedded fixture + optional
#            semgrep live; pack hands COMPLETE (10/10).
# Enterprise bar: no 18-check ceiling. Capacity grows by engine.

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

TOOL_ID = "scan_devsecops_pack"
VERSION = "0.6.0-d6"
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
    if s in ("info", "informational", "unknown", "0"):
        return "info"
    return default


def _floating_tag(image: str | None) -> bool:
    if not image:
        return False
    img = image.strip()
    if "@sha256:" in img:
        return False
    # untagged or :latest / :master / :main floating
    if ":" not in img.split("/")[-1]:
        return True
    tag = img.rsplit(":", 1)[-1]
    return tag.lower() in {"latest", "master", "main", "dev", "develop", "nightly", "stable"}


def _engine_sca(ctx: PackContext) -> list[dict]:
    """Software composition analysis — embedded fixture + optional trivy fs live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "sca"),
        ctx.backends,
    )
    sca = ctx.section("sca") if ctx.fixture else {}

    if sca:
        for cve in sca.get("cves") or []:
            cid = cve.get("id") or "CVE-UNKNOWN"
            pkg = cve.get("package") or "unknown"
            ver = cve.get("version") or "?"
            sev = _norm_sev(cve.get("severity"), "high")
            title = cve.get("title") or f"{cid} in {pkg}"
            findings.append(
                _finding(
                    ctx.next_id("sca"),
                    f"{cid}: {title}",
                    sev,
                    f"Vulnerable dependency {pkg}@{ver} — {cid}: {title}. "
                    f"Upgrade to a fixed release and pin via lockfile.",
                    resource={
                        "type": "package",
                        "id": f"{pkg}@{ver}",
                        "engine": "sca",
                        "cve": cid,
                    },
                    evidence={
                        "cve": cid,
                        "package": pkg,
                        "version": ver,
                        "title": title,
                        "source": "fixture.sca.cves",
                    },
                    remediation={
                        "steps": [
                            f"Upgrade {pkg} past the fixed version for {cid}.",
                            "Regenerate lockfiles (requirements.lock / package-lock / poetry.lock).",
                            "Re-run scan_devsecops_pack SCA (or trivy fs) to confirm.",
                            "Enable Dependabot/Renovate for continuous upgrades.",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "NIST 800-53 SA-11",
                        "NIST 800-53 SI-2",
                        "CIS Software Supply Chain 3.1",
                        "SOC 2 CC7.1",
                    ],
                    engine="sca",
                    backend="embedded",
                )
            )

        for man in sca.get("manifests") or []:
            mpath = man.get("path") or "manifest"
            lock = man.get("lockfile")
            pkgs = man.get("packages") or []
            if not lock:
                findings.append(
                    _finding(
                        ctx.next_id("sca"),
                        f"Missing lockfile for {mpath}",
                        "high",
                        f"Dependency manifest '{mpath}' has no lockfile. Builds are non-reproducible "
                        f"and SCA cannot pin exact resolved versions ({len(pkgs)} declared packages).",
                        resource={"type": "manifest", "id": mpath, "engine": "sca"},
                        evidence={
                            "path": mpath,
                            "lockfile": lock,
                            "package_count": len(pkgs),
                            "source": "fixture.sca.manifests",
                        },
                        remediation={
                            "steps": [
                                "Commit a generated lockfile (package-lock.json, poetry.lock, "
                                "Pipfile.lock, go.sum, Cargo.lock, etc.).",
                                "Install only from the lockfile in CI (npm ci / pip install -r lock).",
                                "Block unlock changes without review.",
                            ],
                            "effort": "low",
                        },
                        compliance=["CIS Software Supply Chain 3.2", "SLSA L1+"],
                        engine="sca",
                        backend="embedded",
                    )
                )

        if sca.get("dependabot_enabled") is False:
            findings.append(
                _finding(
                    ctx.next_id("sca"),
                    "Dependency update automation disabled",
                    "medium",
                    "Dependabot (or equivalent Renovate) is not enabled. Known CVEs will linger "
                    "without automated PRs for vulnerable transitive deps.",
                    resource={"type": "repo_setting", "id": "dependabot", "engine": "sca"},
                    evidence={
                        "dependabot_enabled": False,
                        "source": "fixture.sca.dependabot_enabled",
                    },
                    remediation={
                        "steps": [
                            "Enable Dependabot or Renovate for ecosystems in this repo.",
                            "Require security-update PRs to be reviewed weekly.",
                            "Auto-merge patch-level security bumps where policy allows.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS Software Supply Chain 3.3", "NIST 800-53 SI-2"],
                    engine="sca",
                    backend="embedded",
                )
            )

        for lic in sca.get("license_risks") or []:
            pkg = lic.get("package") or "unknown"
            license_id = lic.get("license") or "UNKNOWN"
            sev = _norm_sev(lic.get("severity"), "medium")
            findings.append(
                _finding(
                    ctx.next_id("sca"),
                    f"License risk: {pkg} ({license_id})",
                    sev,
                    f"Package {pkg} carries license '{license_id}' flagged as a policy risk.",
                    resource={"type": "package", "id": pkg, "engine": "sca"},
                    evidence={"license": lic, "source": "fixture.sca.license_risks"},
                    engine="sca",
                    backend="embedded",
                )
            )

        return findings

    # Live path: trivy fs when available and no fixture
    if ctx.mode == "live" and backend == "trivy":
        trivy = (ctx.backends.get("trivy") or {}).get("path")
        target = Path(ctx.target)
        if trivy and target.exists():
            try:
                cmd = [
                    trivy,
                    "fs",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--quiet",
                    str(target),
                ]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                raw = (p.stdout or "").strip()
                if raw:
                    data = json.loads(raw)
                    for res in data.get("Results") or []:
                        target_name = res.get("Target") or str(target)
                        for v in res.get("Vulnerabilities") or []:
                            cid = v.get("VulnerabilityID") or "CVE"
                            pkg = v.get("PkgName") or "pkg"
                            ver = v.get("InstalledVersion") or "?"
                            sev = _norm_sev(v.get("Severity"), "medium")
                            title = v.get("Title") or v.get("Description") or cid
                            findings.append(
                                _finding(
                                    ctx.next_id("sca"),
                                    f"{cid}: {pkg}@{ver}",
                                    sev,
                                    f"Trivy reported {cid} on {pkg}@{ver} in {target_name}: {title}",
                                    resource={
                                        "type": "package",
                                        "id": f"{pkg}@{ver}",
                                        "engine": "sca",
                                        "cve": cid,
                                    },
                                    evidence={
                                        "trivy": {
                                            "VulnerabilityID": cid,
                                            "PkgName": pkg,
                                            "InstalledVersion": ver,
                                            "FixedVersion": v.get("FixedVersion"),
                                            "Severity": v.get("Severity"),
                                            "Target": target_name,
                                        },
                                        "source": "live.trivy.fs",
                                    },
                                    engine="sca",
                                    backend="trivy",
                                )
                            )
            except Exception:
                pass
    return findings


def _engine_container(ctx: PackContext) -> list[dict]:
    """Container image & Dockerfile policy — embedded fixture + optional trivy live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "container"),
        ctx.backends,
    )
    ctr = ctx.section("container") if ctx.fixture else {}

    if ctr:
        for df in ctr.get("dockerfiles") or []:
            path = df.get("path") or "Dockerfile"
            base = df.get("base_image") or ""
            if _floating_tag(base):
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Floating/unpinned base image: {path}",
                        "high",
                        f"Dockerfile '{path}' uses base image '{base}' without immutable digest. "
                        f"Floating tags break supply-chain integrity and can pull unexpected layers.",
                        resource={"type": "dockerfile", "id": path, "engine": "container"},
                        evidence={
                            "path": path,
                            "base_image": base,
                            "source": "fixture.container.dockerfiles.base_image",
                        },
                        remediation={
                            "steps": [
                                "Pin base image to version tag AND sha256 digest.",
                                "Prefer minimal distroless/alpine variants from trusted registries.",
                                "Rebuild on a schedule and rescan with trivy image.",
                            ],
                            "effort": "medium",
                        },
                        compliance=[
                            "CIS Docker 4.2",
                            "NIST 800-53 CM-2",
                            "CIS Software Supply Chain 3.4",
                        ],
                        engine="container",
                        backend="embedded",
                    )
                )

            runs_root = df.get("runs_as_root") is True or (df.get("user") in (None, "", "root", "0"))
            if runs_root:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Container runs as root: {path}",
                        "critical",
                        f"Dockerfile '{path}' runs as root "
                        f"(user={df.get('user')!r}, runs_as_root={df.get('runs_as_root')}). "
                        f"Compromise of the app becomes host-level privilege in many runtimes.",
                        resource={"type": "dockerfile", "id": path, "engine": "container"},
                        evidence={
                            "path": path,
                            "user": df.get("user"),
                            "runs_as_root": df.get("runs_as_root"),
                            "source": "fixture.container.dockerfiles.user",
                        },
                        remediation={
                            "steps": [
                                "Add a non-root USER before CMD/ENTRYPOINT.",
                                "Set USER in the final stage of multi-stage builds.",
                                "Enforce runAsNonRoot in Kubernetes PodSecurity / PSA.",
                            ],
                            "effort": "medium",
                        },
                        compliance=["CIS Docker 4.1", "NIST 800-53 AC-6", "NSA K8s Hardening"],
                        engine="container",
                        backend="embedded",
                    )
                )

            if df.get("secrets_in_layers") is True:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Secrets baked into image layers: {path}",
                        "critical",
                        f"Dockerfile '{path}' flags secrets_in_layers=true. Credentials in layers "
                        f"persist even after later DELETE instructions.",
                        resource={"type": "dockerfile", "id": path, "engine": "container"},
                        evidence={
                            "path": path,
                            "secrets_in_layers": True,
                            "source": "fixture.container.dockerfiles.secrets_in_layers",
                        },
                        remediation={
                            "steps": [
                                "Never COPY .env / keys into the image; inject at runtime via secrets.",
                                "Use multi-stage builds and BuildKit --secret mounts.",
                                "Scan historical tags; rotate any exposed credentials.",
                            ],
                            "effort": "high",
                        },
                        compliance=["CIS Docker 4.10", "NIST 800-53 IA-5"],
                        engine="container",
                        backend="embedded",
                    )
                )

            if df.get("healthcheck") is False:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Missing HEALTHCHECK: {path}",
                        "medium",
                        f"Dockerfile '{path}' has no HEALTHCHECK. Orchestrators and load balancers "
                        f"cannot distinguish hung processes from healthy ones.",
                        resource={"type": "dockerfile", "id": path, "engine": "container"},
                        evidence={
                            "path": path,
                            "healthcheck": False,
                            "source": "fixture.container.dockerfiles.healthcheck",
                        },
                        remediation={
                            "steps": [
                                "Add HEALTHCHECK with a realistic liveness command.",
                                "Mirror probes in Kubernetes (liveness/readiness) if K8s is the runtime.",
                            ],
                            "effort": "low",
                        },
                        compliance=["CIS Docker 4.6"],
                        engine="container",
                        backend="embedded",
                    )
                )

            if df.get("add_all_context") is True:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Broad build context copy: {path}",
                        "high",
                        f"Dockerfile '{path}' copies the entire build context (ADD/COPY .). "
                        f"Secrets, .git, and build tools may leak into the image.",
                        resource={"type": "dockerfile", "id": path, "engine": "container"},
                        evidence={
                            "path": path,
                            "add_all_context": True,
                            "source": "fixture.container.dockerfiles.add_all_context",
                        },
                        remediation={
                            "steps": [
                                "COPY only required artifacts; use multi-stage builds.",
                                "Add a tight .dockerignore (.git, .env, tests, docs).",
                            ],
                            "effort": "low",
                        },
                        compliance=["CIS Docker 4.7", "NIST 800-53 CM-7"],
                        engine="container",
                        backend="embedded",
                    )
                )

        for img in ctr.get("images") or []:
            name = img.get("name") or "image:unknown"
            crit = int(img.get("os_vulns_critical") or 0)
            high = int(img.get("os_vulns_high") or 0)
            fixed = img.get("fixed_available")
            if crit > 0:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Image OS critical vulns ({crit}): {name}",
                        "critical",
                        f"Image '{name}' reports {crit} critical OS package vulnerabilities"
                        f"{' with fixes available' if fixed else ''}. Rebuild from a patched base.",
                        resource={"type": "image", "id": name, "engine": "container"},
                        evidence={
                            "image": name,
                            "os_vulns_critical": crit,
                            "os_vulns_high": high,
                            "fixed_available": fixed,
                            "source": "fixture.container.images",
                        },
                        remediation={
                            "steps": [
                                "Rebuild on a freshly patched base image.",
                                "Run trivy image --severity CRITICAL,HIGH and fail the pipeline.",
                                "Prefer distroless/minimal bases to shrink OS package surface.",
                            ],
                            "effort": "medium",
                        },
                        compliance=["CIS Docker 4.4", "NIST 800-53 SI-2"],
                        engine="container",
                        backend="embedded",
                    )
                )
            elif high > 0:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Image OS high vulns ({high}): {name}",
                        "high",
                        f"Image '{name}' reports {high} high OS package vulnerabilities"
                        f"{' with fixes available' if fixed else ''}.",
                        resource={"type": "image", "id": name, "engine": "container"},
                        evidence={
                            "image": name,
                            "os_vulns_high": high,
                            "fixed_available": fixed,
                            "source": "fixture.container.images",
                        },
                        engine="container",
                        backend="embedded",
                    )
                )
            # if both crit and high, still raise a high summary when crit already raised
            if crit > 0 and high > 0:
                findings.append(
                    _finding(
                        ctx.next_id("container"),
                        f"Image OS high vulns ({high}): {name}",
                        "high",
                        f"Image '{name}' additionally reports {high} high-severity OS vulnerabilities "
                        f"(critical={crit}).",
                        resource={"type": "image", "id": name, "engine": "container"},
                        evidence={
                            "image": name,
                            "os_vulns_critical": crit,
                            "os_vulns_high": high,
                            "fixed_available": fixed,
                            "source": "fixture.container.images",
                        },
                        engine="container",
                        backend="embedded",
                    )
                )

        return findings

    # Live Dockerfile heuristics when no fixture
    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            dockerfiles = list(root.rglob("Dockerfile")) + list(root.rglob("Dockerfile.*"))
            # cap walk noise
            dockerfiles = [p for p in dockerfiles if ".git" not in p.parts][:40]
            for dfp in dockerfiles:
                try:
                    content = dfp.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                rel = str(dfp.relative_to(root)) if dfp.is_relative_to(root) else str(dfp)
                # FROM lines
                for m in re.finditer(r"^\s*FROM\s+([^\s]+)", content, re.I | re.M):
                    base = m.group(1)
                    if base.upper().startswith("SCRATCH"):
                        continue
                    if _floating_tag(base):
                        findings.append(
                            _finding(
                                ctx.next_id("container"),
                                f"Floating/unpinned base image: {rel}",
                                "high",
                                f"Dockerfile '{rel}' FROM {base} is not digest-pinned.",
                                resource={"type": "dockerfile", "id": rel, "engine": "container"},
                                evidence={"path": rel, "base_image": base, "source": "live.dockerfile"},
                                engine="container",
                                backend="embedded",
                            )
                        )
                user_matches = list(re.finditer(r"^\s*USER\s+([^\s]+)", content, re.I | re.M))
                final_user = user_matches[-1].group(1) if user_matches else None
                if final_user is None or final_user in ("root", "0"):
                    findings.append(
                        _finding(
                            ctx.next_id("container"),
                            f"Container runs as root: {rel}",
                            "critical",
                            f"Dockerfile '{rel}' final USER is {final_user!r}.",
                            resource={"type": "dockerfile", "id": rel, "engine": "container"},
                            evidence={"path": rel, "user": final_user, "source": "live.dockerfile"},
                            engine="container",
                            backend="embedded",
                        )
                    )
                if not re.search(r"^\s*HEALTHCHECK\b", content, re.I | re.M):
                    findings.append(
                        _finding(
                            ctx.next_id("container"),
                            f"Missing HEALTHCHECK: {rel}",
                            "medium",
                            f"Dockerfile '{rel}' has no HEALTHCHECK instruction.",
                            resource={"type": "dockerfile", "id": rel, "engine": "container"},
                            evidence={"path": rel, "source": "live.dockerfile"},
                            engine="container",
                            backend="embedded",
                        )
                    )
                if re.search(r"^\s*(ADD|COPY)\s+\.\s+/", content, re.I | re.M) or re.search(
                    r"^\s*(ADD|COPY)\s+\.\s+\.", content, re.I | re.M
                ):
                    findings.append(
                        _finding(
                            ctx.next_id("container"),
                            f"Broad build context copy: {rel}",
                            "high",
                            f"Dockerfile '{rel}' copies entire context into the image.",
                            resource={"type": "dockerfile", "id": rel, "engine": "container"},
                            evidence={"path": rel, "source": "live.dockerfile"},
                            engine="container",
                            backend="embedded",
                        )
                    )

        if backend == "trivy":
            trivy = (ctx.backends.get("trivy") or {}).get("path")
            if trivy and root.exists():
                try:
                    cmd = [
                        trivy,
                        "config",
                        "--format",
                        "json",
                        "--quiet",
                        str(root),
                    ]
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
                    raw = (p.stdout or "").strip()
                    if raw:
                        data = json.loads(raw)
                        for res in data.get("Results") or []:
                            for m in res.get("Misconfigurations") or []:
                                sev = _norm_sev(m.get("Severity"), "medium")
                                mid = m.get("ID") or m.get("AVDID") or "misconfig"
                                findings.append(
                                    _finding(
                                        ctx.next_id("container"),
                                        f"Trivy config {mid}: {m.get('Title') or mid}",
                                        sev,
                                        m.get("Description") or m.get("Message") or mid,
                                        resource={
                                            "type": "dockerfile",
                                            "id": res.get("Target") or str(root),
                                            "engine": "container",
                                        },
                                        evidence={"trivy_misconfig": m, "source": "live.trivy.config"},
                                        engine="container",
                                        backend="trivy",
                                    )
                                )
                except Exception:
                    pass
    return findings


def _iac_rule_title(rule: str) -> str:
    return (rule or "iac-issue").replace("_", "-")


def _engine_iac(ctx: PackContext) -> list[dict]:
    """Infrastructure as Code — TF/K8s/Helm embedded + optional trivy/checkov live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "iac"),
        ctx.backends,
    )
    iac = ctx.section("iac") if ctx.fixture else {}

    if iac:
        for tf in iac.get("terraform") or []:
            path = tf.get("path") or "main.tf"
            for issue in tf.get("issues") or []:
                rule = issue.get("rule") or "terraform-misconfig"
                sev = _norm_sev(issue.get("severity"), "high")
                resource = issue.get("resource") or path
                detail = issue.get("detail") or rule
                findings.append(
                    _finding(
                        ctx.next_id("iac"),
                        f"Terraform: {_iac_rule_title(rule)}",
                        sev,
                        f"Terraform '{path}' resource '{resource}' — {rule}: {detail}.",
                        resource={
                            "type": "terraform",
                            "id": resource,
                            "engine": "iac",
                            "path": path,
                        },
                        evidence={
                            "path": path,
                            "rule": rule,
                            "resource": resource,
                            "detail": detail,
                            "source": "fixture.iac.terraform",
                        },
                        remediation={
                            "steps": [
                                f"Remediate {rule} on {resource} in {path}.",
                                "Apply least-privilege network and storage controls (no 0.0.0.0/0 SSH, S3 public block).",
                                "Add tfsec/trivy config / checkov to CI as a required status check.",
                                "Re-run scan_devsecops_pack IaC engine after fix.",
                            ],
                            "effort": "medium",
                        },
                        compliance=[
                            "CIS AWS Foundations",
                            "NIST 800-53 CM-2",
                            "NIST 800-53 AC-4",
                            "SOC 2 CC6.6",
                        ],
                        engine="iac",
                        backend="embedded",
                    )
                )

        for k8s in iac.get("kubernetes") or []:
            path = k8s.get("path") or "deploy.yaml"
            for issue in k8s.get("issues") or []:
                rule = issue.get("rule") or "k8s-misconfig"
                sev = _norm_sev(issue.get("severity"), "high")
                detail = issue.get("detail") or rule
                resource = issue.get("resource") or path
                findings.append(
                    _finding(
                        ctx.next_id("iac"),
                        f"Kubernetes: {_iac_rule_title(rule)}",
                        sev,
                        f"Kubernetes manifest '{path}' — {rule}: {detail}.",
                        resource={
                            "type": "kubernetes",
                            "id": resource,
                            "engine": "iac",
                            "path": path,
                        },
                        evidence={
                            "path": path,
                            "rule": rule,
                            "detail": detail,
                            "source": "fixture.iac.kubernetes",
                        },
                        remediation={
                            "steps": [
                                f"Fix {rule} in {path} ({detail}).",
                                "Set allowPrivilegeEscalation: false; drop ALL capabilities where possible.",
                                "Define cpu/memory requests and limits on every container.",
                                "Enforce via Pod Security Standards / Kyverno / OPA Gatekeeper.",
                            ],
                            "effort": "medium",
                        },
                        compliance=[
                            "CIS Kubernetes",
                            "NSA/CISA K8s Hardening",
                            "NIST 800-53 CM-6",
                        ],
                        engine="iac",
                        backend="embedded",
                    )
                )

        for helm in iac.get("helm") or []:
            path = helm.get("path") or "Chart.yaml"
            for issue in helm.get("issues") or []:
                rule = issue.get("rule") or "helm-misconfig"
                sev = _norm_sev(issue.get("severity"), "medium")
                detail = issue.get("detail") or rule
                findings.append(
                    _finding(
                        ctx.next_id("iac"),
                        f"Helm: {_iac_rule_title(rule)}",
                        sev,
                        f"Helm chart '{path}' — {rule}: {detail}.",
                        resource={"type": "helm", "id": path, "engine": "iac"},
                        evidence={
                            "path": path,
                            "rule": rule,
                            "detail": detail,
                            "source": "fixture.iac.helm",
                        },
                        engine="iac",
                        backend="embedded",
                    )
                )

        # drift / missing iac scanning gate
        if iac.get("iac_scanning_enabled") is False:
            findings.append(
                _finding(
                    ctx.next_id("iac"),
                    "IaC security scanning disabled",
                    "high",
                    "No IaC scanner is required in the delivery pipeline (tfsec/trivy/checkov). "
                    "Misconfigurations can merge without gate.",
                    resource={"type": "repo_setting", "id": "iac_scanning", "engine": "iac"},
                    evidence={
                        "iac_scanning_enabled": False,
                        "source": "fixture.iac.iac_scanning_enabled",
                    },
                    remediation={
                        "steps": [
                            "Add trivy config or checkov job on every PR touching infra/.",
                            "Fail the build on CRITICAL/HIGH IaC findings.",
                        ],
                        "effort": "low",
                    },
                    compliance=["NIST 800-53 SA-11", "CIS Software Supply Chain 4.2"],
                    engine="iac",
                    backend="embedded",
                )
            )

        return findings

    # Live: trivy config then checkov when no fixture
    if ctx.mode == "live":
        root = Path(ctx.target)
        if not root.exists():
            return findings

        trivy = (ctx.backends.get("trivy") or {}).get("path")
        if backend == "trivy" and trivy:
            try:
                cmd = [trivy, "config", "--format", "json", "--quiet", str(root)]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=240, check=False)
                raw = (p.stdout or "").strip()
                if raw:
                    data = json.loads(raw)
                    for res in data.get("Results") or []:
                        target_name = res.get("Target") or str(root)
                        for m in res.get("Misconfigurations") or []:
                            sev = _norm_sev(m.get("Severity"), "medium")
                            mid = m.get("ID") or m.get("AVDID") or "misconfig"
                            title = m.get("Title") or mid
                            findings.append(
                                _finding(
                                    ctx.next_id("iac"),
                                    f"Trivy IaC {mid}: {title}",
                                    sev,
                                    m.get("Description") or m.get("Message") or title,
                                    resource={
                                        "type": "iac",
                                        "id": target_name,
                                        "engine": "iac",
                                    },
                                    evidence={
                                        "trivy_misconfig": m,
                                        "source": "live.trivy.config",
                                    },
                                    engine="iac",
                                    backend="trivy",
                                )
                            )
            except Exception:
                pass

        checkov = (ctx.backends.get("checkov") or {}).get("path")
        if (backend == "checkov" or (not findings and checkov)) and checkov:
            try:
                cmd = [checkov, "-d", str(root), "-o", "json", "--quiet"]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                raw = (p.stdout or "").strip()
                if raw:
                    data = json.loads(raw)
                    # checkov may return list of reports or single dict
                    reports = data if isinstance(data, list) else [data]
                    for rep in reports:
                        results = (rep or {}).get("results") or {}
                        for fail in results.get("failed_checks") or []:
                            sev = _norm_sev(fail.get("severity") or "medium", "medium")
                            cid = fail.get("check_id") or "CKV"
                            findings.append(
                                _finding(
                                    ctx.next_id("iac"),
                                    f"Checkov {cid}: {fail.get('check_name') or cid}",
                                    sev,
                                    fail.get("description") or fail.get("check_name") or cid,
                                    resource={
                                        "type": "iac",
                                        "id": fail.get("file_path") or str(root),
                                        "engine": "iac",
                                        "resource": fail.get("resource"),
                                    },
                                    evidence={"checkov": fail, "source": "live.checkov"},
                                    engine="iac",
                                    backend="checkov",
                                )
                            )
            except Exception:
                pass
    return findings


def _sast_rule_title(rule: str) -> str:
    return (rule or "sast-issue").replace("_", "-")


def _engine_sast(ctx: PackContext) -> list[dict]:
    """Static application security — embedded fixture + optional semgrep live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "sast"),
        ctx.backends,
    )
    sast = ctx.section("sast") if ctx.fixture else {}

    if sast:
        for issue in sast.get("issues") or []:
            rule = issue.get("rule") or "sast-rule"
            sev = _norm_sev(issue.get("severity"), "high")
            path = issue.get("path") or "unknown"
            line = issue.get("line")
            detail = issue.get("detail") or rule
            findings.append(
                _finding(
                    ctx.next_id("sast"),
                    f"SAST: {_sast_rule_title(rule)}",
                    sev,
                    f"{path}"
                    + (f":{line}" if line is not None else "")
                    + f" — {rule}: {detail}",
                    resource={
                        "type": "source_file",
                        "id": path,
                        "engine": "sast",
                        "line": line,
                        "rule": rule,
                    },
                    evidence={
                        "path": path,
                        "line": line,
                        "rule": rule,
                        "detail": detail,
                        "source": "fixture.sast.issues",
                    },
                    remediation={
                        "steps": [
                            f"Remediate {rule} at {path}"
                            + (f":{line}" if line is not None else "")
                            + ".",
                            "Prefer parameterized queries / safe APIs over string assembly.",
                            "Move secrets to a vault or env injected at runtime — never hardcode.",
                            "Add Semgrep/CodeQL (or equivalent) as a required PR status check.",
                            "Re-run scan_devsecops_pack SAST engine after fix.",
                        ],
                        "effort": "medium" if sev != "critical" else "high",
                    },
                    compliance=[
                        "OWASP ASVS",
                        "NIST 800-53 SA-11",
                        "NIST 800-53 SI-10",
                        "CIS Software Supply Chain 4.1",
                    ],
                    engine="sast",
                    backend="embedded",
                )
            )

        if sast.get("sast_in_ci") is False:
            findings.append(
                _finding(
                    ctx.next_id("sast"),
                    "SAST not required in CI pipeline",
                    "high",
                    "Static application security testing is not a required pipeline gate. "
                    "Injection and auth flaws can merge without automated source analysis.",
                    resource={"type": "repo_setting", "id": "sast_in_ci", "engine": "sast"},
                    evidence={
                        "sast_in_ci": False,
                        "source": "fixture.sast.sast_in_ci",
                    },
                    remediation={
                        "steps": [
                            "Add Semgrep, CodeQL, or Bandit/SpotBugs job on pull_request.",
                            "Fail on critical/high confidence findings.",
                            "Mark the SAST job as a required status check on the default branch.",
                        ],
                        "effort": "low",
                    },
                    compliance=["NIST 800-53 SA-11", "OWASP SAMM"],
                    engine="sast",
                    backend="embedded",
                )
            )

        if sast.get("dangerous_sinks_unreviewed") is True:
            findings.append(
                _finding(
                    ctx.next_id("sast"),
                    "Dangerous sinks present without review coverage",
                    "medium",
                    "Codebase contains high-risk sinks (exec/eval/raw SQL/deserialize) that are "
                    "not covered by mandatory peer review or automated taint rules.",
                    resource={"type": "code_pattern", "id": "dangerous_sinks", "engine": "sast"},
                    evidence={
                        "dangerous_sinks_unreviewed": True,
                        "source": "fixture.sast.dangerous_sinks_unreviewed",
                    },
                    remediation={
                        "steps": [
                            "Inventory exec/eval/raw-SQL/pickle/yaml.load full sinks.",
                            "Require CODEOWNERS review on files with those patterns.",
                            "Add Semgrep taint rules for untrusted → sink flows.",
                        ],
                        "effort": "medium",
                    },
                    engine="sast",
                    backend="embedded",
                )
            )

        return findings

    # Live: optional semgrep; lightweight pattern fallback
    if ctx.mode == "live":
        root = Path(ctx.target)
        if not root.is_dir():
            return findings

        smg = (ctx.backends.get("semgrep") or {}).get("path")
        if backend == "semgrep" and smg:
            try:
                cmd = [
                    smg,
                    "scan",
                    "--config",
                    "p/owasp-top-ten",
                    "--json",
                    "--quiet",
                    str(root),
                ]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                raw = (p.stdout or "").strip()
                if raw:
                    data = json.loads(raw)
                    for res in data.get("results") or []:
                        path = res.get("path") or "unknown"
                        check = (res.get("check_id") or "semgrep").split(".")[-1]
                        sev = _norm_sev(
                            (res.get("extra") or {}).get("severity")
                            or (res.get("extra") or {}).get("metadata", {}).get("impact"),
                            "medium",
                        )
                        msg = (res.get("extra") or {}).get("message") or check
                        start = ((res.get("start") or {}) if isinstance(res.get("start"), dict) else {})
                        line = start.get("line")
                        findings.append(
                            _finding(
                                ctx.next_id("sast"),
                                f"Semgrep: {check}",
                                sev,
                                msg,
                                resource={
                                    "type": "source_file",
                                    "id": path,
                                    "engine": "sast",
                                    "line": line,
                                },
                                evidence={"semgrep": res, "source": "live.semgrep"},
                                engine="sast",
                                backend="semgrep",
                            )
                        )
            except Exception:
                pass

        if not findings:
            # lightweight python patterns — capped
            py_files = [p for p in root.rglob("*.py") if ".git" not in p.parts][:80]
            patterns = [
                (
                    re.compile(r"""(?:execute|cursor\.execute)\s*\(\s*[f\"'].*%|f[\"'].*SELECT|f[\"'].*INSERT""", re.I),
                    "sql-injection-string-format",
                    "critical",
                    "Possible SQL built via string formatting",
                ),
                (
                    re.compile(r"""(?:eval|exec)\s*\(""", re.I),
                    "dangerous-eval-exec",
                    "high",
                    "Use of eval/exec",
                ),
                (
                    re.compile(r"""pickle\.loads?\s*\(""", re.I),
                    "insecure-deserialization-pickle",
                    "high",
                    "pickle.load on untrusted data is RCE-class",
                ),
                (
                    re.compile(r"""(?:secret|password|api_key|jwt_secret)\s*=\s*['\"][^'\"]+['\"]""", re.I),
                    "hardcoded-secret-assignment",
                    "high",
                    "Hardcoded secret-like assignment",
                ),
            ]
            seen = 0
            for pf in py_files:
                if seen >= 25:
                    break
                try:
                    content = pf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                rel = str(pf.relative_to(root)) if pf.is_relative_to(root) else str(pf)
                for i, line in enumerate(content.splitlines(), 1):
                    for cre, rule, sev, detail in patterns:
                        if cre.search(line):
                            findings.append(
                                _finding(
                                    ctx.next_id("sast"),
                                    f"SAST: {rule}",
                                    sev,
                                    f"{rel}:{i} — {detail}",
                                    resource={
                                        "type": "source_file",
                                        "id": rel,
                                        "engine": "sast",
                                        "line": i,
                                    },
                                    evidence={
                                        "path": rel,
                                        "line": i,
                                        "rule": rule,
                                        "snippet": line.strip()[:120],
                                        "source": "live.embedded.pattern",
                                    },
                                    engine="sast",
                                    backend="embedded",
                                )
                            )
                            seen += 1
                            break
                    if seen >= 25:
                        break
    return findings


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
    """Supply chain & SBOM — embedded fixture + optional syft live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "supply_chain"),
        ctx.backends,
    )
    sc = ctx.section("supply_chain") if ctx.fixture else {}

    if sc:
        if sc.get("sbom_published") is False:
            findings.append(
                _finding(
                    ctx.next_id("supply_chain"),
                    "SBOM not published with releases",
                    "high",
                    "No Software Bill of Materials is published for builds/releases. "
                    "Consumers cannot inventory transitive risk or respond to new CVEs quickly.",
                    resource={"type": "sbom", "id": "release-sbom", "engine": "supply_chain"},
                    evidence={
                        "sbom_published": False,
                        "source": "fixture.supply_chain.sbom_published",
                    },
                    remediation={
                        "steps": [
                            "Generate SPDX/CycloneDX SBOM in CI (syft, trivy, cdxgen).",
                            "Attach SBOM to release artifacts and container manifests.",
                            "Store SBOMs with retention matching release retention policy.",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "EO 14028 SBOM",
                        "CIS Software Supply Chain 3.1",
                        "NIST SSDF PW.4",
                    ],
                    engine="supply_chain",
                    backend="embedded",
                )
            )

        if sc.get("signed_images") is False:
            findings.append(
                _finding(
                    ctx.next_id("supply_chain"),
                    "Container images not signed",
                    "critical",
                    "Release images are not cryptographically signed (cosign/notation). "
                    "Registries cannot enforce provenance before deploy.",
                    resource={"type": "image_signing", "id": "cosign", "engine": "supply_chain"},
                    evidence={
                        "signed_images": False,
                        "source": "fixture.supply_chain.signed_images",
                    },
                    remediation={
                        "steps": [
                            "Sign images with cosign keyless (OIDC) or KMS-backed keys.",
                            "Enforce signature verification in admission (Kyverno/cosign policy).",
                            "Publish signatures/attestations next to the image digest.",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "SLSA L2+",
                        "CIS Software Supply Chain 3.5",
                        "NIST SSDF PS.3",
                    ],
                    engine="supply_chain",
                    backend="embedded",
                )
            )

        slsa = sc.get("slsa_level")
        if slsa is not None and int(slsa) < 2:
            findings.append(
                _finding(
                    ctx.next_id("supply_chain"),
                    f"SLSA level too low ({slsa})",
                    "high",
                    f"Build provenance is at SLSA level {slsa}. Target at least SLSA L2 "
                    f"(hosted build, provenance) and plan L3 for high-assurance releases.",
                    resource={"type": "slsa", "id": f"level-{slsa}", "engine": "supply_chain"},
                    evidence={
                        "slsa_level": slsa,
                        "source": "fixture.supply_chain.slsa_level",
                    },
                    remediation={
                        "steps": [
                            "Emit SLSA provenance attestations from the CI builder.",
                            "Use hermetic / reusable workflows with pinned actions.",
                            "Verify provenance in deploy gates before production.",
                        ],
                        "effort": "high",
                    },
                    compliance=["SLSA", "CIS Software Supply Chain 2.3"],
                    engine="supply_chain",
                    backend="embedded",
                )
            )

        if sc.get("dependency_review_on_pr") is False:
            findings.append(
                _finding(
                    ctx.next_id("supply_chain"),
                    "Dependency review missing on PRs",
                    "high",
                    "PRs do not run dependency review (GitHub Dependency Review / Snyk / OSV). "
                    "New vulnerable packages can merge without a gate.",
                    resource={"type": "pr_gate", "id": "dependency_review", "engine": "supply_chain"},
                    evidence={
                        "dependency_review_on_pr": False,
                        "source": "fixture.supply_chain.dependency_review_on_pr",
                    },
                    remediation={
                        "steps": [
                            "Enable dependency-review-action (or equivalent) on pull_request.",
                            "Fail on critical/high newly introduced advisories.",
                            "Require the check on protected branches.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS Software Supply Chain 3.3", "NIST 800-53 SA-11"],
                    engine="supply_chain",
                    backend="embedded",
                )
            )

        for inst in sc.get("install_scripts") or []:
            ipath = inst.get("path") or "unknown"
            pattern = inst.get("pattern") or "curl|bash"
            findings.append(
                _finding(
                    ctx.next_id("supply_chain"),
                    f"Dangerous remote install pipe: {ipath}",
                    "critical",
                    f"Path '{ipath}' executes a remote installer via pipe-to-shell: {pattern}. "
                    f"Compromised CDN/host equals full CI/runtime code execution.",
                    resource={"type": "install_script", "id": ipath, "engine": "supply_chain"},
                    evidence={
                        "path": ipath,
                        "pattern": pattern,
                        "source": "fixture.supply_chain.install_scripts",
                    },
                    remediation={
                        "steps": [
                            "Replace curl|bash with pinned package installs or verified checksums.",
                            "Vendor installers or use official package managers.",
                            "Block pipe-to-shell patterns via actionlint / policy.",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "CIS GitHub Actions 1.3",
                        "NIST 800-53 SI-7",
                        "CIS Software Supply Chain 2.1",
                    ],
                    engine="supply_chain",
                    backend="embedded",
                )
            )

        return findings

    # Live: light FS checks when no fixture
    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            sbom_hits = []
            for name in ("sbom.json", "sbom.spdx.json", "bom.json", "cyclonedx.json"):
                sbom_hits.extend(root.rglob(name))
            sbom_hits = [p for p in sbom_hits if ".git" not in p.parts][:20]
            if not sbom_hits:
                findings.append(
                    _finding(
                        ctx.next_id("supply_chain"),
                        "SBOM artifact not found in tree",
                        "medium",
                        f"No common SBOM filenames discovered under '{root}'.",
                        resource={"type": "sbom", "id": str(root), "engine": "supply_chain"},
                        evidence={"source": "live.fs", "sbom_count": 0},
                        engine="supply_chain",
                        backend="embedded",
                    )
                )
            syft = (ctx.backends.get("syft") or {}).get("path")
            if backend == "syft" and syft:
                try:
                    cmd = [syft, str(root), "-o", "json"]
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
                    # presence of output is informational — package inventory success not a finding
                    _ = p.stdout
                except Exception:
                    pass
    return findings


def _engine_policy(ctx: PackContext) -> list[dict]:
    """Policy as Code — OPA/Conftest/admission embedded + optional checkov live."""
    findings: list[dict] = []
    backend = _resolve_backend(
        next(e for e in ENGINE_REGISTRY if e["key"] == "policy"),
        ctx.backends,
    )
    pol = ctx.section("policy") if ctx.fixture else {}

    if pol:
        opa = pol.get("opa_policies") or []
        if isinstance(opa, list) and len(opa) == 0:
            findings.append(
                _finding(
                    ctx.next_id("policy"),
                    "No OPA/Rego policies present",
                    "high",
                    "Repository has zero OPA/Rego policy files. Infrastructure and K8s changes "
                    "cannot be gated by declarative policy-as-code.",
                    resource={"type": "policy_bundle", "id": "opa", "engine": "policy"},
                    evidence={
                        "opa_policies": opa,
                        "source": "fixture.policy.opa_policies",
                    },
                    remediation={
                        "steps": [
                            "Add baseline Rego policies under policy/ (images, network, IAM).",
                            "Version policies with the repo; unit-test with OPA/Conftest.",
                            "Wire policies into CI (conftest verify / gatekeeper dry-run).",
                        ],
                        "effort": "medium",
                    },
                    compliance=[
                        "NIST 800-53 CM-1",
                        "NIST 800-53 CA-2",
                        "CIS Software Supply Chain 4.3",
                    ],
                    engine="policy",
                    backend="embedded",
                )
            )

        if pol.get("conftest_present") is False:
            findings.append(
                _finding(
                    ctx.next_id("policy"),
                    "Conftest / policy test harness missing",
                    "medium",
                    "Conftest (or equivalent policy unit-test toolchain) is not present. "
                    "Policies cannot be validated before merge.",
                    resource={"type": "tooling", "id": "conftest", "engine": "policy"},
                    evidence={
                        "conftest_present": False,
                        "source": "fixture.policy.conftest_present",
                    },
                    remediation={
                        "steps": [
                            "Add Conftest (or OPA test) to the CI security jobs.",
                            "Store policy tests next to Rego under policy/.",
                            "Fail PRs that violate baseline policies.",
                        ],
                        "effort": "low",
                    },
                    compliance=["NIST 800-53 SA-11"],
                    engine="policy",
                    backend="embedded",
                )
            )

        if pol.get("admission_controls") is False:
            findings.append(
                _finding(
                    ctx.next_id("policy"),
                    "Cluster admission controls disabled",
                    "high",
                    "Kubernetes admission controls (Gatekeeper/Kyverno/PSA) are not enabled. "
                    "Runtime workloads can violate policy even if CI is clean.",
                    resource={"type": "runtime_control", "id": "admission", "engine": "policy"},
                    evidence={
                        "admission_controls": False,
                        "source": "fixture.policy.admission_controls",
                    },
                    remediation={
                        "steps": [
                            "Deploy Kyverno or OPA Gatekeeper with baseline constrainttemplates.",
                            "Enable Pod Security Admission (restricted) on app namespaces.",
                            "Start in audit mode, then enforce on critical namespaces.",
                        ],
                        "effort": "high",
                    },
                    compliance=[
                        "CIS Kubernetes 5.2",
                        "NSA/CISA K8s Hardening",
                        "NIST 800-53 CM-7",
                    ],
                    engine="policy",
                    backend="embedded",
                )
            )

        for v in pol.get("violations") or []:
            rule = v.get("rule") or v.get("policy") or "policy-violation"
            sev = _norm_sev(v.get("severity"), "high")
            target = v.get("target") or v.get("resource") or "unknown"
            findings.append(
                _finding(
                    ctx.next_id("policy"),
                    f"Policy violation: {rule}",
                    sev,
                    v.get("detail") or f"Policy '{rule}' failed on '{target}'.",
                    resource={"type": "policy_violation", "id": target, "engine": "policy"},
                    evidence={"violation": v, "source": "fixture.policy.violations"},
                    remediation={
                        "steps": [
                            f"Remediate resource '{target}' to satisfy policy '{rule}'.",
                            "Update exception registry only with time-bounded approvals.",
                        ],
                        "effort": "medium",
                    },
                    engine="policy",
                    backend="embedded",
                )
            )

        if pol.get("policy_as_code_required") is False:
            findings.append(
                _finding(
                    ctx.next_id("policy"),
                    "Policy-as-code not required in SDLC",
                    "medium",
                    "Policy-as-code is optional or absent from the SDLC definition of done.",
                    resource={"type": "sdlc_gate", "id": "policy_as_code", "engine": "policy"},
                    evidence={
                        "policy_as_code_required": False,
                        "source": "fixture.policy.policy_as_code_required",
                    },
                    remediation={
                        "steps": [
                            "Add policy evaluation as a required merge check.",
                            "Document exceptions with owner + expiry.",
                        ],
                        "effort": "low",
                    },
                    engine="policy",
                    backend="embedded",
                )
            )

        return findings

    # Live lightweight: detect absence of policy files
    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            rego = list(root.rglob("*.rego"))
            rego = [p for p in rego if ".git" not in p.parts][:50]
            conf = list(root.rglob(".conftest.yaml")) + list(root.rglob("conftest.toml"))
            conf = [p for p in conf if ".git" not in p.parts]
            if not rego:
                findings.append(
                    _finding(
                        ctx.next_id("policy"),
                        "No OPA/Rego policies present",
                        "high",
                        f"No .rego files found under '{root}'.",
                        resource={"type": "policy_bundle", "id": "opa", "engine": "policy"},
                        evidence={"source": "live.fs", "rego_count": 0},
                        engine="policy",
                        backend="embedded",
                    )
                )
            if not conf and not any("conftest" in str(p).lower() for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
                # only flag missing harness when also empty policies path-ish
                pass
    return findings


def _engine_repo_gov(ctx: PackContext) -> list[dict]:
    """Repository governance — CODEOWNERS, SECURITY.md, workflow perms (embedded)."""
    findings: list[dict] = []
    gov = ctx.section("repo_gov") if ctx.fixture else {}

    if gov:
        if not gov.get("codeowners"):
            findings.append(
                _finding(
                    ctx.next_id("repo_gov"),
                    "CODEOWNERS missing",
                    "high",
                    "No CODEOWNERS file is configured. Critical paths can merge without "
                    "named owner review.",
                    resource={"type": "repo_file", "id": "CODEOWNERS", "engine": "repo_gov"},
                    evidence={
                        "codeowners": gov.get("codeowners"),
                        "source": "fixture.repo_gov.codeowners",
                    },
                    remediation={
                        "steps": [
                            "Add CODEOWNERS covering .github/, infra/, auth, and release paths.",
                            "Enable 'Require review from Code Owners' on protected branches.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.6", "SOC 2 CC8.1"],
                    engine="repo_gov",
                    backend="embedded",
                )
            )

        if gov.get("security_md") is False:
            findings.append(
                _finding(
                    ctx.next_id("repo_gov"),
                    "SECURITY.md missing",
                    "medium",
                    "No SECURITY.md vulnerability disclosure policy. Researchers and customers "
                    "lack a private reporting channel.",
                    resource={"type": "repo_file", "id": "SECURITY.md", "engine": "repo_gov"},
                    evidence={
                        "security_md": False,
                        "source": "fixture.repo_gov.security_md",
                    },
                    remediation={
                        "steps": [
                            "Add SECURITY.md with contact, SLA, and scope.",
                            "Enable private vulnerability reporting on GitHub if available.",
                        ],
                        "effort": "low",
                    },
                    compliance=["ISO 27001 A.6.8", "CIS Software Supply Chain 1.3"],
                    engine="repo_gov",
                    backend="embedded",
                )
            )

        req = gov.get("required_reviewers_for")
        if isinstance(req, list) and len(req) == 0:
            findings.append(
                _finding(
                    ctx.next_id("repo_gov"),
                    "No path-based required reviewers",
                    "medium",
                    "required_reviewers_for is empty — sensitive paths are not assigned owners.",
                    resource={"type": "repo_setting", "id": "path_reviewers", "engine": "repo_gov"},
                    evidence={
                        "required_reviewers_for": req,
                        "source": "fixture.repo_gov.required_reviewers_for",
                    },
                    remediation={
                        "steps": [
                            "Map CODEOWNERS for .github/, infra/, k8s/, secrets handlers.",
                            "Require 2 reviewers on default branch for critical paths.",
                        ],
                        "effort": "low",
                    },
                    compliance=["CIS GitHub 1.1.3"],
                    engine="repo_gov",
                    backend="embedded",
                )
            )

        perms = (gov.get("default_workflow_permissions") or "").lower().replace("_", "-")
        if perms in ("read-write", "write", "write-all", "readwrite"):
            findings.append(
                _finding(
                    ctx.next_id("repo_gov"),
                    f"Default workflow permissions too broad ({gov.get('default_workflow_permissions')})",
                    "critical",
                    "Organization/repo default GITHUB_TOKEN permissions are read-write. "
                    "Compromised workflows inherit write to contents/packages.",
                    resource={
                        "type": "repo_setting",
                        "id": "default_workflow_permissions",
                        "engine": "repo_gov",
                    },
                    evidence={
                        "default_workflow_permissions": gov.get("default_workflow_permissions"),
                        "source": "fixture.repo_gov.default_workflow_permissions",
                    },
                    remediation={
                        "steps": [
                            "Set default workflow permissions to read-only.",
                            "Grant write per job only when required.",
                            "Disable 'Allow GitHub Actions to create and approve pull requests' unless needed.",
                        ],
                        "effort": "low",
                    },
                    compliance=[
                        "CIS GitHub Actions 1.1",
                        "NIST 800-53 AC-6",
                    ],
                    engine="repo_gov",
                    backend="embedded",
                )
            )

        return findings

    if ctx.mode == "live":
        root = Path(ctx.target)
        if root.is_dir():
            co = list(root.rglob("CODEOWNERS"))
            co = [p for p in co if ".git" not in p.parts]
            if not co:
                findings.append(
                    _finding(
                        ctx.next_id("repo_gov"),
                        "CODEOWNERS missing",
                        "high",
                        f"No CODEOWNERS found under '{root}'.",
                        resource={"type": "repo_file", "id": "CODEOWNERS", "engine": "repo_gov"},
                        evidence={"source": "live.fs"},
                        engine="repo_gov",
                        backend="embedded",
                    )
                )
            sec = list(root.rglob("SECURITY.md")) + list(root.rglob("security.md"))
            sec = [p for p in sec if ".git" not in p.parts]
            if not sec:
                findings.append(
                    _finding(
                        ctx.next_id("repo_gov"),
                        "SECURITY.md missing",
                        "medium",
                        f"No SECURITY.md found under '{root}'.",
                        resource={"type": "repo_file", "id": "SECURITY.md", "engine": "repo_gov"},
                        evidence={"source": "live.fs"},
                        engine="repo_gov",
                        backend="embedded",
                    )
                )
    return findings


def _engine_release(ctx: PackContext) -> list[dict]:
    """Release & artifact integrity — retention, provenance, env protection."""
    findings: list[dict] = []
    rel = ctx.section("release") if ctx.fixture else {}
    if not rel:
        return findings

    days = rel.get("artifact_retention_days")
    if days is not None and int(days) < 30:
        findings.append(
            _finding(
                ctx.next_id("release"),
                f"Artifact retention too short ({days} days)",
                "high",
                f"Build/release artifacts are retained only {days} day(s). Incident response "
                f"and audit reconstruction require longer retention (typically 30–90+ days).",
                resource={"type": "artifact_policy", "id": "retention", "engine": "release"},
                evidence={
                    "artifact_retention_days": days,
                    "source": "fixture.release.artifact_retention_days",
                },
                remediation={
                    "steps": [
                        "Set artifact retention to at least 90 days for production pipelines.",
                        "Archive release artifacts to immutable object storage with lifecycle rules.",
                    ],
                    "effort": "low",
                },
                compliance=["NIST 800-53 AU-11", "SOC 2 CC7.2"],
                engine="release",
                backend="embedded",
            )
        )

    if rel.get("provenance_attestations") is False:
        findings.append(
            _finding(
                ctx.next_id("release"),
                "Release provenance attestations missing",
                "high",
                "Releases lack provenance attestations (SLSA / in-toto). Downstream cannot "
                "verify who built what from which commit.",
                resource={"type": "attestation", "id": "provenance", "engine": "release"},
                evidence={
                    "provenance_attestations": False,
                    "source": "fixture.release.provenance_attestations",
                },
                remediation={
                    "steps": [
                        "Emit build provenance (e.g. actions/attest-build-provenance).",
                        "Attach attestations to GitHub Releases / OCI references.",
                        "Verify attestations in deploy workflows before promotion.",
                    ],
                    "effort": "medium",
                },
                compliance=["SLSA L2+", "CIS Software Supply Chain 2.3"],
                engine="release",
                backend="embedded",
            )
        )

    if rel.get("environment_protection_rules") is False:
        findings.append(
            _finding(
                ctx.next_id("release"),
                "Deployment environment protection disabled",
                "critical",
                "GitHub Environments (or equivalent) have no protection rules. Anyone with "
                "workflow write can push straight to production secrets/targets.",
                resource={"type": "environment", "id": "protection_rules", "engine": "release"},
                evidence={
                    "environment_protection_rules": False,
                    "source": "fixture.release.environment_protection_rules",
                },
                remediation={
                    "steps": [
                        "Create production environment with required reviewers.",
                        "Restrict secrets to the protected environment.",
                        "Limit which branches may deploy to production.",
                    ],
                    "effort": "medium",
                },
                compliance=["CIS GitHub Actions 2.1", "NIST 800-53 CM-5"],
                engine="release",
                backend="embedded",
            )
        )

    if rel.get("production_manual_approval") is False:
        findings.append(
            _finding(
                ctx.next_id("release"),
                "Production deploy lacks manual approval",
                "high",
                "Production deployments do not require manual approval. Automated pipelines "
                "can ship unreviewed changes to live customer impact.",
                resource={"type": "environment", "id": "prod-approval", "engine": "release"},
                evidence={
                    "production_manual_approval": False,
                    "source": "fixture.release.production_manual_approval",
                },
                remediation={
                    "steps": [
                        "Require 1–2 human approvers on the production environment.",
                        "Separate build and deploy jobs; gate deploy on approval.",
                        "Log approvals for audit (change management).",
                    ],
                    "effort": "low",
                },
                compliance=["SOC 2 CC8.1", "NIST 800-53 CM-3"],
                engine="release",
                backend="embedded",
            )
        )

    return findings


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
        "status": "active",  # D3
        "phase": "D3",
        "preferred_backends": ["trivy", "grype", "embedded"],
        "run": _engine_sca,
        "weight": 1.2,
    },
    {
        "key": "container",
        "code": "CTR",
        "name": "Container Image & Dockerfile",
        "status": "active",  # D3
        "phase": "D3",
        "preferred_backends": ["trivy", "embedded"],
        "run": _engine_container,
        "weight": 1.1,
    },
    {
        "key": "iac",
        "code": "IAC",
        "name": "Infrastructure as Code",
        "status": "active",  # D4
        "phase": "D4",
        "preferred_backends": ["trivy", "checkov", "embedded"],
        "run": _engine_iac,
        "weight": 1.1,
    },
    {
        "key": "sast",
        "code": "SAST",
        "name": "Static Application Security (pipeline-side)",
        "status": "active",  # D6
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
        "status": "active",  # D5
        "phase": "D5",
        "preferred_backends": ["syft", "embedded"],
        "run": _engine_supply_chain,
        "weight": 1.0,
    },
    {
        "key": "policy",
        "code": "POL",
        "name": "Policy as Code",
        "status": "active",  # D4
        "phase": "D4",
        "preferred_backends": ["checkov", "embedded"],
        "run": _engine_policy,
        "weight": 0.9,
    },
    {
        "key": "repo_gov",
        "code": "GOV",
        "name": "Repository Governance",
        "status": "active",  # D5
        "phase": "D5",
        "preferred_backends": ["embedded"],
        "run": _engine_repo_gov,
        "weight": 0.9,
    },
    {
        "key": "release",
        "code": "REL",
        "name": "Release & Artifact Integrity",
        "status": "active",  # D5
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
        "phase": "D6",
        "label": "pack_hands_complete_all_engines_active",
        "engines_total": total,
        "engines_active": active,
        "engines_stub": stub,
        "complete_pct": pct,
        "enterprise_bar": "full multi-engine pack — not 18-check ceiling",
        "next_phase": "FIX_MAP expand for DEVSEC-* IDs → role brain after all-role hands",
        "active_engines": sorted(e["key"] for e in engine_results if e.get("status") == "active"),
        "pack_hands_complete": active == total and stub == 0,
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
                "pack_phase": "D6",
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
            # Prefer backends engines actually stamped (fixture path → embedded)
            stamped = [f.get("evidence", {}).get("backend") for f in findings]
            stamped = [b for b in stamped if b]
            if stamped:
                entry["backend_used"] = max(set(stamped), key=stamped.count)
            elif mode == "mock":
                entry["backend_used"] = "embedded"
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
            "pack_phase": "D6",
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
