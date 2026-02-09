def analyze_network_risk(terraform_code):
    print("[AI-NG-AUDIT] Scanning Network Architecture...")
    
    # AI Logic: Detecting "Exposure" Patterns
    if "map_public_ip_on_launch = true" in terraform_code and "database" in terraform_code.lower():
        return "CRITICAL RISK: Database is exposed to the Public Internet. Remediation required."
    
    if "cidr_blocks = [\"0.0.0.0/0\"]" in terraform_code:
        return "HIGH RISK: Wildcard Network Access (All-Open ports) detected."

    return "PASS: Network segmentation meets 'Zero-Visibility' standards."

# Testing the audit
with open("network_moat.tf", "r") as f:
    result = analyze_network_risk(f.read())
    print(f"RESULT: {result}")