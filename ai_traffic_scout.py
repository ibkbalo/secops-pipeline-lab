"""
SENTINEL STACKS: PHASE 4 | AUTONOMOUS TRAFFIC ANOMALY DISCOVERY
Aligning Project 8 (Traffic Intelligence) with Sentinel Standards
"""

import os
from datetime import datetime

# THE "HEARTBEAT" SOURCE (Project 17 & 18 Logs)
LOG_FILE = "security-operations/incident_response.log"

def analyze_traffic_pulse():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] 🛡️ [SENTINEL-TRAFFIC] Analyzing Infrastructure Heartbeat...")
    
    if not os.path.exists(LOG_FILE):
        return "⚠️ WARNING: No heartbeat telemetry found. Monitoring is inactive."

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = f.readlines()

    # THE SENTINEL "ABNORMALITY" MATRIX
    # We are hunting for Project 18 'Spike' and 'Attack' patterns
    request_count = len(logs)
    attack_alerts = sum(1 for line in logs if "ALERT" in line or "BLOCKED" in line)
    
    print(f"🔍 Audit Complete. Processed {request_count} Traffic Events.")

    # THE SENTINEL VERDICT (AI Logic)
    if attack_alerts > 5:
        print(f"🔴 CRITICAL: DDoS / Brute-Force Anomaly detected ({attack_alerts} Blocks).")
    elif request_count > 100:
        print(f"🟡 WARNING: High-Volume Traffic detected. Stress-Limit approaching.")
    else:
        print("🟢 PASS: Steady Network Heartbeat. No anomalous spikes observed.")

    return {"volume": request_count, "attacks": attack_alerts}

if __name__ == "__main__":
    analyze_traffic_pulse()