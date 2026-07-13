\# TOOL\_STANDARDS.md



\*\*Sentinel Stacks Tool Library — Official Standards\*\*  

\*\*Version:\*\* 1.0  

\*\*Last Updated:\*\* 2026-07-10  

\*\*Owner:\*\* Ibukun Balogun



\---



\## 1. Purpose



This document defines the mandatory standards for every tool in the Sentinel Stacks security tool library. Every script, whether existing or newly created, must comply with these rules.



Non-compliance = tool is not accepted into the library.



\---



\## 2. Tool Taxonomy Structure



\### Top-Level Organization



sentinel-stacks/ ├── cloud-security/ # Infrastructure Sentinel │ ├── aws/ │ ├── azure/ │ └── gcp/ ├── devsecops/ # Infrastructure Sentinel │ ├── cicd/ │ ├── containers/ │ ├── iac/ │ └── secrets/ ├── appsec/ # Perimeter Sentinel │ ├── owasp/ │ ├── dependency-scanning/ │ └── api-security/ ├── identity-access/ # Infrastructure Sentinel │ ├── iam/ │ ├── mfa/ │ └── privileged-access/ ├── ai-ml-security/ # Perimeter Sentinel │ ├── prompt-injection/ │ ├── model-integrity/ │ └── data-poisoning/ ├── governance/ # Command Center │ ├── compliance/ │ └── reporting/ └── \_templates/











\### Sentinel-to-Domain Mapping



| Sentinel              | Domains |

|-----------------------|---------|

| \*\*Perimeter Sentinel\*\*    | AppSec, API Security, AI/ML Security |

| \*\*Infrastructure Sentinel\*\* | Cloud Security, DevSecOps, Identity \& Access |

| \*\*Remediation Sentinel\*\*  | Consumes outputs only (no scanning tools) |

| \*\*Command Center\*\*        | Governance, Compliance, Reporting, Orchestration |



\---



\## 3. Folder \& File Naming Rules



\### Directory Naming Convention



Format: `verb\_platform\_resource\_action`



Examples:

\- `scan\_aws\_iam\_privilege\_escalation`

\- `audit\_azure\_storage\_public\_access`

\- `test\_k8s\_rbac\_overprivileged`

\- `remediate\_aws\_security\_group\_overly\_permissive`



\### File Naming Rules



| File | Required? | Notes |

|------|-----------|-------|

| `tool.py` | Yes | Always named `tool.py` inside each tool folder |

| `README.md` | Yes | Tool-level documentation |

| `schema.json` | Yes | Input/output schema |

| `CHANGELOG.md` | Yes | Version history |

| `tests/` | Yes | Test directory |



Allowed verbs:

\- `scan\_` → Read-only discovery

\- `audit\_` → Read-only + analysis

\- `test\_` → Active probing (controlled)

\- `remediate\_` → State-changing (Tier 2 only)



All lowercase + underscores only. No hyphens.



\---



\## 4. Mandatory JSON Output Schema



Every tool must return this exact structure:



```json

{

&#x20; "tool\_id": "scan\_aws\_iam\_privilege\_escalation",

&#x20; "version": "1.0.0",

&#x20; "execution": {

&#x20;   "timestamp": "2026-07-10T14:30:00Z",

&#x20;   "duration\_seconds": 12.4,

&#x20;   "target": "aws://account/123456789",

&#x20;   "status": "success | partial | failed",

&#x20;   "error": null

&#x20; },

&#x20; "summary": {

&#x20;   "total\_findings": 3,

&#x20;   "critical": 1,

&#x20;   "high": 1,

&#x20;   "medium": 1,

&#x20;   "low": 0,

&#x20;   "info": 0

&#x20; },

&#x20; "findings": \[

&#x20;   {

&#x20;     "id": "FIND-001",

&#x20;     "title": "IAM role allows privilege escalation",

&#x20;     "severity": "critical",

&#x20;     "confidence": "high",

&#x20;     "resource": {

&#x20;       "type": "aws::iam::role",

&#x20;       "id": "arn:aws:iam::123456789:role/DevRole",

&#x20;       "region": "us-east-1"

&#x20;     },

&#x20;     "description": "...",

&#x20;     "evidence": { },

&#x20;     "remediation": {

&#x20;       "steps": \["..."],

&#x20;       "effort": "low",

&#x20;       "tier": 2,

&#x20;       "reversible": true,

&#x20;       "requires\_approval": true

&#x20;     },

&#x20;     "compliance": \["CIS AWS 1.4", "SOC2 CC6.3", "NIST AC-6"]

&#x20;   }

&#x20; ],

&#x20; "metadata": {

&#x20;   "domain": "cloud-security",

&#x20;   "subdomain": "aws/iam",

&#x20;   "sentinel": "infrastructure",

&#x20;   "tier": 1,

&#x20;   "tags": \["iam", "privilege-escalation"],

&#x20;   "llm\_summary": "Single paragraph plain English summary for the AI agent."

&#x20; }

}

Rules:



severity must be one of: critical, high, medium, low, info

tier is set at the tool level (1 = read-only, 2 = state-changing)

llm\_summary is mandatory — this is what the AI Agent reads

5\. Input Parameter Standards

Every tool.py must accept this interface:



python







def run(params: dict) -> dict:

&#x20;   """

&#x20;   params = {

&#x20;       "credentials": {

&#x20;           "type": "aws\_keys | azure\_sp | api\_key",

&#x20;           "values": { }

&#x20;       },

&#x20;       "target": "aws://account/123456789",

&#x20;       "regions": \["us-east-1"],

&#x20;       "scope": "full | targeted",

&#x20;       "max\_runtime\_seconds": 300,

&#x20;       "dry\_run": false,

&#x20;       "severity\_threshold": "medium"

&#x20;   }

&#x20;   """

Key rules\_



Credentials are never logged or stored

All Tier 2 tools must support dry\_run=True

max\_runtime\_seconds must be respected

6\. Documentation Requirements

Every tool folder must contain a README.md with the following sections:



What It Does

When the Agent Should Call This

Inputs (table)

Outputs

Known Limitations

Test Coverage

References

7\. Versioning Rules

Format: MAJOR.MINOR.PATCH



MAJOR: Breaking change to input or output schema

MINOR: New features (backward compatible)

PATCH: Bug fixes / improvements

The agent will reject tools if the schema version does not match.



8\. Tool Registry (tool\_registry.json)

A machine-readable index located at the root of the repository. The AI Agent uses this file to discover available tools.



End of TOOL\_STANDARDS.md

