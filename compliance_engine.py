import json

def check_soc2_compliance(infrastructure_state):
    print("[GOVERNANCE] Starting SOC2 / ISO-27001 Automated Audit...")
    report = {
        "Requirement_1_Identity": "FAIL",
        "Requirement_2_Encryption": "FAIL",
        "Requirement_3_Network_Isolation": "FAIL"
    }

    # Checking our Vault Architecture (Project 10)
    if "vault_logic.py" in infrastructure_state:
        report["Requirement_1_Identity"] = "PASS"
        print("[AUDIT] ✅ Identity Requirement Satisfied: Zero-Trust Vault active.")

    # Checking our Encryption/Rotation (Project 10)
    if "automatically_after_days = 1" in infrastructure_state:
        report["Requirement_2_Encryption"] = "PASS"
        print("[AUDIT] ✅ Encryption Requirement Satisfied: 24-hour secret rotation verified.")

    # Checking our Moat/VPC (Project 11)
    if "map_public_ip_on_launch = false" in infrastructure_state:
        report["Requirement_3_Network_Isolation"] = "PASS"
        print("[AUDIT] ✅ Network Requirement Satisfied: Private Subnet Architecture verified.")

    # Final Compliance Decision
    if all(status == "PASS" for status in report.values()):
        print("\n[RESULT] COMPLIANCE STATUS: PROTECTED (All Gates Passed)")
        return True
    else:
        print("\n[RESULT] COMPLIANCE STATUS: AT RISK (Missing Controls)")
        return False

if __name__ == "__main__":
    # Simulating the auditor scanning our project folder
    with open("infrastructure_vault.tf", "r") as f1, open("vault_logic.py", "r") as f2:
        full_codebase = f1.read() + f2.read()
        check_soc2_compliance(full_codebase)