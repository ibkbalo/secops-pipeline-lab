"""
PRISM-NEURAL: PHASE 1 | PERIMETER ASSURANCE AUDITOR
AI-Network-Auditor (v1.0.1) - Senior Operational Release
"""

import os
import subprocess


# PHASE 1: THE BLUEPRINT AUDIT (Project 1-5 Alignment)
def analyze_network_risk(terraform_code):
    """Parses Terraform Code for Security Anti-Patterns."""
    print("🛡️ [AI-NG-AUDIT] Phase 1: Scanning Network Blueprint...")
    if "map_public_ip_on_launch = true" in terraform_code:
        return "CRITICAL RISK: Blueprint exposes Database to Public Internet."
    if 'cidr_blocks = ["0.0.0.0/0"]' in terraform_code:
        return "HIGH RISK: Wildcard Network Access Detected in Blueprint."
    return "PASS: Blueprint meets 'Zero-Visibility' standards."


# PHASE 2: THE PHYSICAL AUDIT (The Identity Gateway Scan)
def run_physical_surface_audit():
    """Performs a live Nmap Fingerprint on the Project 25 Container."""
    print("🛡️ [AI-NG-AUDIT] Phase 2: Auditing Physical Surface...")
    try:
        # Utilizing Nmap for the Surface Audit (Standard Project 1 Logic)
        result = subprocess.run(["nmap", "-sV", "-p", "5000", "127.0.0.1"], capture_output=True, text=True)
        scan_data = result.stdout
        
        # RECORDING THE RECEIPT (Forensic Audit Trail)
        with open("security-operations/recon_report.nmap", "w") as f:
            f.write(scan_data)
        
        if "5000/tcp open" in scan_data:
            return "🟢 SUCCESS: Project 25 Gateway is EXPOSED & HEALTHY."
        else:
            return "🔴 ALERT: Physical Firewall Blocking Gateway."
    except Exception as e:
        return f"❌ SCAN FAILURE: {e}"


if __name__ == "__main__":
    print("\n🚀 INITIATING PERIMETER ASSURANCE PROTOCOL...")
    
    # PART 1: THE BLUEPRINT CHECK
    if os.path.exists("network_moat.tf"):
        with open("network_moat.tf", "r") as f:
            print(f"RESULT: {analyze_network_risk(f.read())}")
    else:
        print("❌ ERROR: network_moat.tf not found.")

    # PART 2: THE PHYSICAL CHECK
    print(f"RESULT: {run_physical_surface_audit()}")
    