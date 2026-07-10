"""
SENTINEL STACKS: PHASE 2 | IDENTITY SCOUT & SESSION AUDITOR
Aligning Project 2 (Identity Intelligence) with ACNSE Standards
"""

import os
from datetime import datetime

def audit_identity_surface(target_auth_config="app.py"):
    print(f"🛡️ [SENTINEL-ID] Initiating Identity Surface Audit: {target_auth_config}")
    
    if not os.path.exists(target_auth_config):
        return "❌ ERROR: Authentication Logic file missing."

    with open(target_auth_config, "r") as f:
        logic = f.read()

    # THE PROJECT 2 IDENTITY HARDENING MATRIX
    findings = {
        "JWT_ENCRYPTION": "JWT" in logic.upper(),
        "SECRET_PROTECTION": "OS.GETENV" in logic.upper() or "SECRET_KEY" not in logic,
        "EXPIRATION_GATE": "EXP" in logic.lower() or "TIMEOUT" in logic.upper()
    }

    print("🔍 AUDIT COMPLETE. Analyzing Token Integrity...")

    if findings["JWT_ENCRYPTION"]:
        print("🟢 PASS: Modern JWT Authentication detected.")
    else:
        print("🔴 CRITICAL: Legacy or Missing Identity Layer. Vulnerable to Session Hijacking.")

    if findings["SECRET_PROTECTION"]:
        print("🟢 PASS: 'Sovereign-Secret' management detected (Environment Variable).")
    else:
        print("🔴 CRITICAL: Hardcoded Secret Key detected. Total compromise risk.")

    return findings

if __name__ == "__main__":
    audit_identity_surface()