"""
SENTINEL STACKS: PHASE 3 | AUTONOMOUS API-SCOUT (SURFACE DISCOVERY)
Aligning Project 5 (API Fuzzing & Discovery) with Sentinel Standards
"""

import os
from datetime import datetime

def perform_api_surface_audit(target_file="app.py"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] 🛡️ [SENTINEL-API] Initiating Surface Discovery: {target_file}")
    
    if not os.path.exists(target_file):
        print(f"❌ ERROR: Target architecture file '{target_file}' not found.")
        return

    with open(target_file, "r", encoding="utf-8") as f:
        logic = f.read().lower()

    # THE SENTINEL "EXPOSURE" DICTIONARY
    # We are hunting for Project 5 'Ghost' Endpoints
    potential_endpoints = {
        "/health": "@app.route('/health')" in logic,
        "/vault-data": "@app.route('/vault-data')" in logic,
        "/admin": "@app.route('/admin')" in logic,
        "/debug": "@app.route('/debug')" in logic,
        "/config": "@app.route('/config')" in logic
    }

    print("🔍 Discovery Complete. Mapping Application Footprint...")

    found_count = 0
    # THE SENTINEL VERDICT
    for endpoint, exists in potential_endpoints.items():
        if exists:
            found_count += 1
            if "/admin" in endpoint or "/debug" in endpoint or "/config" in endpoint:
                print(f"🔴 CRITICAL SURPLUS: Unauthorized 'Ghost' Path detected: {endpoint}")
            else:
                print(f"🟢 VERIFIED: Authorized Sentinel Route: {endpoint}")

    if found_count > 2:
        print("⚠️ WARNING: Application Surface is larger than the 'Minimalist' standard.")
    else:
        print("✅ PASS: Minimalist API Footprint confirmed (Project 25 Standard).")

    return potential_endpoints

if __name__ == "__main__":
    perform_api_surface_audit()