import re

def ai_governance_scan(file_content):
    """
    AI Logic simulating a Risk Assessment of Cloud & Application code.
    """
    findings = []
    
    # AI Pattern Matching for Data Leakage
    if re.search(r"AKIA[0-9A-Z]{16}", file_content):
        findings.append("[CRITICAL] AI detected a Hardcoded Cloud Credential.")
    
    # AI Logic for Architectural Governance
    if "public-read" in file_content:
        findings.append("[HIGH] Governance Violation: Public S3 Exposure detected.")
        
    if "0.0.0.0/0" in file_content:
        findings.append("[MEDIUM] Perimeter Risk: Unrestricted Network Access.")

    return findings

# Test the scanner against our new app
with open("app.py", "r") as f:
    print(f"Scanning App Logic...\n{ai_governance_scan(f.read())}")

with open("infrastructure.tf", "r") as f:
    print(f"\nScanning Cloud Infrastructure...\n{ai_governance_scan(f.read())}")