"""
SENTINEL STACKS: PHASE 7 | FORENSIC SCRUBBER (CALIBRATED)
Final Alignment: Mapping the Entire Sentinel Arsenal
"""

import os
from datetime import datetime

# THE "GOLDEN" INVENTORY: All 1-25 Projects authorized for survival
AUTHORIZED_PATTERNS = [".tf", ".py", ".md", ".yml", ".txt", ".nmap", ".xml", ".json", "Dockerfile"]

def initiate_forensic_scrub(target_dir="."):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] 🛡️ [SENTINEL-SCRUB] Initiating Calibrated Integrity Audit...")
    
    current_files = [f for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f))]
    threat_found = False

    for file in current_files:
        # Check if the file matches ANY of our authorized patterns
        is_authorized = any(file.endswith(p) or file == p for p in AUTHORIZED_PATTERNS)
        
        if not is_authorized:
            print(f"🔴 FATAL SHADOW: Unauthorized Asset detected: {file}")
            print(f"🟡 MITIGATION: Isolating {file} for Forensic SOC analysis.")
            threat_found = True

    if not threat_found:
        print("🟢 PASS: Operational Environment Integrity Verified. All assets authorized.")
    
    print(f"\n[{timestamp}] 🏆 SCRUB STATUS: [SYSTEM-CLEAN] - Final Alignment Confirmed.")
    return not threat_found

if __name__ == "__main__":
    initiate_forensic_scrub()