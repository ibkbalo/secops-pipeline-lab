# change_assurance/artifacts/kubernetes.py

from __future__ import annotations

import re
from typing import Any

from change_assurance.artifacts.base import ArtifactHandler
from change_assurance.models import stable_hash
from change_assurance.secret_redaction import redact_text


class KubernetesHandler(ArtifactHandler):
    artifact_type = "kubernetes"

    def detect(self, artifact: dict) -> bool:
        t = str(artifact.get("artifact_type") or "").lower()
        if t in {"kubernetes", "helm", "k8s"}:
            return True
        joined = " ".join(artifact.get("source_files") or []).lower()
        return any(x in joined for x in ("deployment", "clusterrole", "networkpolicy", "chart.yaml", "/k8s/", "helm"))

    def validate(self, artifact: dict, context: dict) -> dict[str, Any]:
        text, secrets = redact_text(str(artifact.get("content_preview") or ""))
        flags: dict[str, Any] = {}
        risks: list[str] = []
        errors: list[str] = []
        if not text.strip():
            return {
                "status": "VALIDATION_UNAVAILABLE",
                "errors": ["No Kubernetes manifest content"],
                "mode": "STATIC_ONLY",
                "capability": "CAPABILITY_PARTIAL",
            }
        # Basic YAML key presence — no kubectl apply
        if "kind:" not in text and "apiVersion:" not in text:
            errors.append("Manifest missing kind/apiVersion (YAML structural check)")
        checks = {
            "privileged": re.compile(r"privileged\s*:\s*true", re.I),
            "run_as_root": re.compile(r"runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0", re.I),
            "host_network": re.compile(r"hostNetwork\s*:\s*true", re.I),
            "host_pid": re.compile(r"hostPID\s*:\s*true", re.I),
            "host_ipc": re.compile(r"hostIPC\s*:\s*true", re.I),
            "host_path": re.compile(r"hostPath\s*:", re.I),
            "cluster_role": re.compile(r"kind:\s*ClusterRole\b", re.I),
            "cluster_role_binding": re.compile(r"kind:\s*ClusterRoleBinding\b", re.I),
            "network_policy": re.compile(r"kind:\s*NetworkPolicy\b", re.I),
            "load_balancer": re.compile(r"type:\s*LoadBalancer", re.I),
            "secret_kind": re.compile(r"kind:\s*Secret\b", re.I),
        }
        for name, pat in checks.items():
            if pat.search(text):
                flags[name] = True
                risks.append(name)
        if secrets:
            errors.append("SECRET_REDACTED: credential-like content in manifest")
        status = "FAIL" if errors and "SECRET" in " ".join(errors) else ("FAIL" if errors else "PASS")
        # kubectl dry-run intentionally not run unless SAFE policy configured
        return {
            "status": status if text.strip() else "VALIDATION_UNAVAILABLE",
            "errors": errors,
            "mode": "STATIC_ONLY",
            "analysis": {
                "flags": flags,
                "risks": risks,
                "scope_hint": self._scope_hint(flags, text),
            },
            "secrets_redacted": [{"status": "SECRET_REDACTED", "secret_type": s.get("secret_type")} for s in secrets],
        }

    def _scope_hint(self, flags: dict, text: str) -> str:
        if flags.get("cluster_role") or flags.get("cluster_role_binding"):
            return "CLUSTER"
        if flags.get("network_policy") and re.search(r"namespace:\s*(prod|production)", text, re.I):
            return "PRODUCTION"
        if re.search(r"kind:\s*Deployment\b", text, re.I):
            return "WORKLOAD"
        if re.search(r"kind:\s*Namespace\b", text, re.I):
            return "NAMESPACE"
        return "WORKLOAD"

    def analyze_changes(self, artifact: dict, context: dict) -> dict[str, Any]:
        val = artifact.get("validation") or self.validate(artifact, context)
        flags = (val.get("analysis") or {}).get("flags") or {}
        scope = (val.get("analysis") or {}).get("scope_hint") or "WORKLOAD"
        return {
            "actions": [{"action": "UPDATE", "target": "kubernetes_manifest", "scope": scope}],
            "plan": {"status": "static", "summary": {"scope": scope, "risks": (val.get("analysis") or {}).get("risks")}},
            "flags": {
                **flags,
                "k8s_rbac_change": bool(flags.get("cluster_role") or flags.get("cluster_role_binding")),
                "container_privilege": bool(flags.get("privileged") or flags.get("run_as_root")),
                "network_policy_change": bool(flags.get("network_policy")),
                "production_impact": scope in {"PRODUCTION", "CLUSTER"},
            },
        }

    def detect_destructive_actions(self, artifact: dict, context: dict) -> dict[str, Any]:
        text = str(artifact.get("content_preview") or "")
        destructive = bool(re.search(r"(?im)^\s*-\s*apiVersion:|^-\s*kind:\s*ClusterRoleBinding", text))
        return {"destructive": destructive, "details": "Possible delete markers" if destructive else "NONE"}

    def calculate_hash(self, artifact: dict) -> str:
        return stable_hash(
            {"type": "kubernetes", "files": artifact.get("source_files"), "preview": artifact.get("content_preview")}
        )

    def build_rollback_plan(self, artifact: dict, context: dict) -> dict[str, Any]:
        return {
            "available": True,
            "procedure": "Re-apply previous manifest revision via approved CD; verify workload health; re-scan policy.",
            "confidence": "MEDIUM",
        }
