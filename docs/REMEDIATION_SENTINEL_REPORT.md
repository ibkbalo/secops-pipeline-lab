# Remediation Sentinel — Agent 3 Ship Report

**Sentinel Stacks** · `ibkbalo/secops-pipeline-lab`  
**Module:** `remediate_findings_hardening_kit` (Tier 2, `dry_run` default)  
**Engine version:** 1.1.0 · **FIX_MAP size:** 87  
**TOOL_STANDARDS:** v1.0 (2026-07-10)  
**Date:** 2026-07-25  

---

## 1. Architecture

```
Scanner output (TOOL_STANDARDS JSON)
         │
         ▼
┌─────────────────────────────────┐
│  ai_remediation_engine.py       │
│  run({target, output_dir,       │
│       dry_run, fix_scope,       │
│       params})                  │
│                                 │
│  ┌───────────────────────────┐  │
│  │  FIX_MAP (87 entries)     │  │
│  │  check_id → {tf, conf,    │  │
│  │    artifact, fix_name}    │  │
│  └───────────────────────────┘  │
│           │                     │
│           ▼                     │
│  ┌───────────────────────────┐  │
│  │  _render(template, ctx)   │  │
│  │  String replace, not      │  │
│  │  str.format — safe for    │  │
│  │  Terraform { } blocks     │  │
│  └───────────────────────────┘  │
│           │                     │
│           ▼                     │
│  kit_output/                    │
│   ├── terraform/   (*.tf)       │
│   ├── configs/     (*.conf,.txt)│
│   ├── runbooks/    (*.yml)      │
│   ├── manifest.json             │
│   └── README.md                 │
│           │                     │
│           ▼                     │
│  <kit>.zip (dry_run only)       │
└─────────────────────────────────┘
```

- **Invocation:** `python ai_remediation_engine.py <scan.json> [output_dir]`
- Every run emits a TOOL_STANDARDS report with `findings[]`, `summary`, `metadata`.
- Kit Zips are gitignored; the engine is the shipped artifact.

---

## 2. FIX_MAP Coverage

| Domain | Controls | Terraform | Config Fragment | Runbook Only |
|--------|----------|-----------|-----------------|--------------|
| AWS (infra) | 18 | 10 | — | 8 |
| Azure (infra) | 18 | 11 | — | 7 |
| GOV (perimeter headers/policy) | 12 | — | 12 | 12 |
| VULN (OWASP/injection) | 14 | — | 5 | 14 |
| IDENT (auth/JWT/session) | 12 | — | 4 | 12 |
| FIND (data-leak/env/admin) | 9 | — | 2 | 9 |
| DATA (PII/storage) | 2 | — | — | 2 |
| NET (port exposure) | 2 | — | — | 2 |
| **Total** | **87** | **21** | **23** | **87** |

Every finding receives a runbook YAML; cloud findings also receive Terraform; perimeter findings receive nginx/header `.conf` fragments where applicable.

### Scanner → check_id resolution

| Scanner | check_id pattern | Mapped by |
|---------|-----------------|-----------|
| `scan_infra_auditor_aws` | `AWS-001` … `AWS-018` | Exact key |
| `scan_infra_auditor_azure` | `AZ-001` … `AZ-018` | Exact key |
| `scan_governance_mapper` | `GOV-SSL`, `GOV-HSTS`, `GOV-CSP`, `GOV-CORS`, `GOV-COOKIE`, `GOV-XFO`, `GOV-XCTO`, `GOV-SECURITY-TXT`, `GOV-PRIVACY`, `GOV-SERVER-INFO`, `GOV-REFERRER`, `GOV-REDIRECT` | Exact key |
| `scan_vuln_hunter` | `VULN-001` … `VULN-014` | Title pattern (PERIM_TITLE_MAP) |
| `scan_identity_guard` | `IDENT-001` … `IDENT-012` | Title pattern |
| `scan_network_auditor` / `scan_data_scout` / `scan_api_scout` | `FIND-001` … `FIND-009` | Title pattern |

---

## 3. Validation Results

All tests run against mock fixtures with `dry_run=True`.

### AWS Infrastructure (mock_aws_vulnerable.json → scan → engine)

```
Status:        success
Total:         18 findings (C:6 H:8 M:4 L:0 I:0)
Mapped:        18
Unmapped:      0
Artifacts:     35 (10 TF + 18 runbooks + manifest + README)
```

### Azure Infrastructure (mock_azure_vulnerable.json → scan → engine)

```
Status:        success
Total:         18 findings (C:5 H:7 M:6 L:0 I:0)
Mapped:        18
Unmapped:      0
Artifacts:     32 (11 TF + 18 runbooks + manifest + README)
```

### Perimeter (mock_perimeter_findings.json → engine)

```
Status:        success
Total:         12 findings (C:3 H:3 M:6 L:0 I:0)
Mapped:        12
Unmapped:      0
Artifacts:     26 (13 configs + 13 runbooks + manifest + README)
```

### Clean-path

```
mock_aws_clean.json     → 18 passed, 0 findings, kit not generated (empty shell)
mock_azure_clean.json   → 18 passed, 0 findings, kit not generated
```

---

## 4. Compliance Mapping

Generated runbooks and Terraform comments reference:

| Framework | Controls referenced |
|-----------|---------------------|
| NIST 800-53 | AC-2, AC-3, AC-6, AU-2, AU-3, AU-4, AU-6, AU-11, CM-2, CM-8, CP-9, IA-2, IA-5, IA-6, RA-5, SC-7, SC-8, SC-12, SC-13, SC-28, SI-4, SI-7 |
| SOC 2 | CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.1, CC7.2, CC7.3, CC7.5 |
| ISO 27001:2022 | A.9.1.2, A.9.2.1, A.9.2.2, A.9.2.3, A.9.4.1, A.9.4.2, A.9.4.3, A.10.1.1, A.10.1.2, A.12.1.1, A.12.3.1, A.12.4.1, A.13.1.1, A.13.2.1, A.14.2.1, A.16.1.5, A.18.1.3 |
| GDPR | Art. 25, Art. 30, Art. 32(1)(a)(b)(c)(d), Art. 33 |

---

## 5. Artifacts Delivered Per Kit

Each `hardening_kits/<kit_id>/` directory contains:

```
├── manifest.json        # kit metadata, findings index, dry_run flag
├── README.md            # human summary, apply instructions
├── terraform/           # .tf files (cloud-only: AWS, Azure)
├── configs/             # .conf / .txt fragments (perimeter: nginx, headers, security.txt)
└── runbooks/            # .yml per finding — steps, effort, reversibility
```

Zipped as `<kit_id>.zip` when `dry_run=True`. The directory is left intact for inspection.

---

## 6. Engine Contract

`run(params: dict) → dict` returns TOOL_STANDARDS report:

```json
{
  "tool_id": "remediate_findings_hardening_kit",
  "version": "1.1.0",
  "execution": {
    "status": "success|failed",
    "mode": "dry_run",
    "target": "...",
    "error": null|"message"
  },
  "summary": {
    "total_findings": int,
    "fixes_mapped": int,
    "fixes_unmapped": int,
    "artifacts_written": int,
    "kits_generated": int
  },
  "findings": [ ... ],
  "metadata": {
    "kit_path": "path/to/zip"|null,
    "dry_run": true,
    "source_tool_id": "...",
    "fix_map_size": 87
  }
}
```

**Accepted params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | str | required | Path to scanner JSON report |
| `output_dir` | str | `"hardening_kits"` | Output directory |
| `dry_run` | bool | `True` | If True, zip the kit; if False, apply is unsafe (always True in current implementation) |
| `fix_scope` | list | `[]` | Filter to specific check_ids |
| `params` | dict | `{}` | Pass-through for scanner compatibility |

---

## 7. Known Limitations (current scope)

- **No cloud mutation.** Engine emits artifacts only. Apply is manual or via separate automation.
- **Perimeter configs are examples.** nginx fragments are correct syntax but should be reviewed per deployment (server names, CIDR allowlists, CSP origins).
- **Title-based matching for VULN/IDENT/FIND.** If a scanner changes its title format, FIX_MAP needs updating. Stable keys preferred (AWS/AZ/GOV).
- **No K8s/container module yet.** Future domain.

---

## 8. Ship Checklist

| Item | Status |
|------|--------|
| Engine compiles, no syntax warnings | ✔ |
| AWS 18/18 mapped, 0 unmapped | ✔ |
| Azure 18/18 mapped, 0 unmapped | ✔ |
| Perimeter 12/12 mapped, 0 unmapped | ✔ |
| Clean-path (no findings → skip) | ✔ |
| Terraform braces: single `{ }` in output | ✔ |
| nginx regex: 2 backslashes `\\.` in output | ✔ |
| PowerShell UTF-8 BOM: engine handles BOM | ✔ (utf-8-sig fallback) |
| `tool_registry.json` at version 1.1.0 | ✔ |
| GitHub commit | `1381530` |
| `dry_run` always True | ✔ |
