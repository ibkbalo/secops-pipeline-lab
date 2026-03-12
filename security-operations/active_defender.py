import os
import sys
from datetime import datetime

# THE "ATTACKER" FROM PROJECT 15/16 (Replace with your actual Kali IP if needed)
ATTACKER_IP = "192.168.1.186" 
DEFENSE_LOG = "security-operations/incident_response.log"

def block_attacker(ip):
    print(f"[{datetime.now()}] 🛡️ SOAR: Identifying Persistent Threat-Actor: {ip}")
    
    # THE "ACTIVE DEFENSE" COMMAND (Windows Netsh API)
    # This command creates a formal FIREWALL RULE to DENY the attacker
    cmd = f'netsh advfirewall firewall add rule name="PROJECT_18_BLOCK" dir=in action=block remoteip={ip}'
    
    try:
        # EXECUTION: This is where we 'Automate' the response
        response = os.system(cmd)
        
        if response == 0:
            print(f"[{datetime.now()}] ✅ SOAR: Attack Vector {ip} NEUTRALIZED. Firewall Updated.")
            log_incident(f"SUCCESS: Blocked Persistent Threat {ip}")
        else:
            print(f"[{datetime.now()}] ⚠️ SOAR: FAILED to Update Firewall. Check Admin Privileges.")
            log_incident(f"FAILURE: Could not block {ip}")
            
    except Exception as e:
        print(f"❌ SOAR: CRITICAL ERROR during Orchestration: {e}")

def log_incident(message):
    with open(DEFENSE_LOG, 'a') as log:
        log.write(f"[{datetime.now()}] - {message}\n")

if __name__ == "__main__":
    block_attacker(ATTACKER_IP)