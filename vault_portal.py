import os
import jwt
from datetime import datetime, timezone, timedelta

# THE "NON-HARDCODED" DISCOVERY (Project 22 Architecture)
# We are 'Fetching' the secret from the System Environment, NOT the code.
MASTER_KEY = os.environ.get("ACNSE_MASTER_SECRET")

def generate_vault_token(username, role):
    # SAFETY CHECK: If the Vault is empty, the app refuses to run.
    if not MASTER_KEY:
        print("❌ CRITICAL: Vault Access Denied. Secret Key Missing from System Environment.")
        return None

    # THE "IDENTITY" PAYLOAD (Future-Proof Python 3.12+ UTC Logic)
    # This maps to NIST SP 800-53 Access Control (AC-1)
    payload = {
        'user': username,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    }
    
    # SIGNING WITH THE VAULT-INJECTED KEY
    return jwt.encode(payload, MASTER_KEY, algorithm='HS256')

if __name__ == "__main__":
    print("🛡️ ACNSE: Accessing Automated Secrets Vault...")
    token = generate_vault_token("ibukun_admin", "ADMIN")
    
    if token:
        print(f"✅ VAULT HANDSHAKE SUCCESSFUL.")
        print(f"Token Generated using System-Injected Secret:\n{token}")