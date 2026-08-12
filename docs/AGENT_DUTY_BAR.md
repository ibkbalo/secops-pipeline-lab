# Agent Duty Bar — Senior Technical Daily Work

**Purpose:** Scorecard for “~80% of repeatable senior technical duties” per Sentinel Stacks role.  
**Not covered:** standups, org politics, novel architecture judgment.  
**Rule:** Silent production auto-apply remains **forbidden**. Approve ≠ apply.

**Statuses:** `Have` = shipped · `Next` = remaining stretch · `Later` = after auth/tenants/packaging

**Worker loop build:** Brain `0.4.0-w1` · Face `0.2.0-w1` · Remediation `1.7.0` · `worker_gate` / `worker_alert` / `worker_draft`

---

## Shared worker capabilities (all four roles)

| Duty | Status |
|------|--------|
| Detect on a real cadence (cycle/watch + CI where natural) | Have |
| Alert on critical/high (workspace alerts + Face) | Have |
| Gate path when role owns delivery (CI fail on critical) | Have |
| Package teaching hardening kits | Have |
| Draft fix artifact after manager approve (no silent apply) | Have |
| Track backlog in Face (open findings, age, severity) | Have |
| Verify cleared on re-scan | Have (runbook) / Next (automated re-open) |
| Auth / multi-tenant MSSP | Later |
| Controlled prod apply | Later |

---

## DevSecOps Agent

| Duty | Status |
|------|--------|
| Scan secrets, CI/CD, SCA, containers, IaC, SAST, supply chain, policy, release | Have |
| Run on PR/push as CI gate; fail on critical `DEVSEC-*` | Have (`worker_gate` + `.github/workflows/devsecops-gate.yml`) |
| Alert critical/high to workspace + Face | Have |
| Teaching kits for top DEVSEC controls (SEC-001, CICD-001, CTR-002) | Have |
| Draft patch/PR bundle after Approve | Have (`brain_workspace/drafts/`) |
| Open GitHub PR automatically | Later (explicit enable) |
| Own branch protection / required checks admin | Later |

**80% bar for DevSecOps:** detect + CI gate + alert + kit/teach + draft bundle + backlog = **Have**.

---

## Security Engineer Agent

| Duty | Status |
|------|--------|
| Perimeter engines | Have |
| Continuous watch via Brain | Have |
| Alert critical/high | Have |
| Teaching kits (PERIM-DATA-001/002 gold) | Have |
| CI/watch gate adapter | Have (`worker_gate --role security-engineer` + role gates workflow) |
| Draft edge/config patch after Approve | Have (shared draft bundle) |
| Live nuclei/httpx always-on customer deploy | Later |

---

## Cloud Security Agent

| Duty | Status |
|------|--------|
| Cloud posture engines (fixture-first) | Have |
| Live soft mode (info when no fixture; SDK collectors deferred) | Have (C2 `0.2.0-c2`) |
| Drift / IAM alerts | Have (shared alert path) |
| Teaching kits (CLOUD-IAM-001/010, STO-002, NET-001) + draft | Have |
| Gate on scan/CI | Have (`worker_gate --role cloud`) |
| Full live SDK collectors | Next |
| Direct cloud mutate | Forbidden / Later controlled apply |

---

## AI Security Agent

| Duty | Status |
|------|--------|
| LLM/RAG/MCP/key engines | Have |
| Alert critical/high | Have |
| CI gate for AI app repos | Have (`worker_gate --role ai-security`) |
| Teaching kits (AISEC-KEY-001) + draft | Have |
| Runtime LLM proxy enforcement | Later |

---

## Scoring

Count checklist rows that are `Have`. Shared + role rows after this worker-loop build should clear **≥80%** of repeatable technical duties for DevSecOps; SE / Cloud / AI Sec share the same loop with role-specific pack depth still expanding (Cloud live collectors = Next).
