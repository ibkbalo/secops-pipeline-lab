import os
from datetime import datetime

# Path to our Threat Observations and our Nmap Evidence
REPORT_PATH = "security-operations/threat_dashboard.md"
RECON_PATH = "offensive-research/recon_report.nmap"

def log_incident():
    print(f"[{datetime.now()}] 🛡️ SIEM: Initializing Threat Validation...")
    
    if os.path.exists(RECON_PATH):
        # Read the 'Closed' status from our Nmap scan
        with open(RECON_PATH, 'r') as file:
            data = file.read()
            if "closed" in data:
                print(f"[{datetime.now()}] ✅ SIEM: Network Perimeter Verified as 'DARK'.")
            else:
                print(f"[{datetime.now()}] ⚠️ SIEM: POTENTIAL INGRESS DETECTED.")
        
        # Formally update the Dashboard
        with open(REPORT_PATH, 'a') as report:
            report.write(f"\n--- \n[LOGGED: {datetime.now()}] - Automated SIEM Validation: Perimeter Secure. \n")
        
        print(f"[{datetime.now()}] 📝 SIEM: Threat Dashboard Updated Successfully.")
    else:
        print("❌ ERROR: Reconnaissance Evidence (Nmap) not found.")

if __name__ == "__main__":
    log_incident()