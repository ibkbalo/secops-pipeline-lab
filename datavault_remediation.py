"""
SENTINEL STACKS: REMEDIATION FOR DATAVAULT IDOR & PCI DATA LEAK
Author: Ibukun Balogun (Principal Architect)
Vulnerability: IDOR (Insecure Direct Object Reference) & Excessive Data Exposure
"""

def secure_get_customer(session_user_id, requested_id):
    """
    REMEDIATION LOGIC:
    1. RESOURCE OWNERSHIP: Check if session_user_id matches the data owner.
    2. DATA TRANSFER OBJECT (DTO): Only return safe, non-PCI fields.
    """
    
    # SIMULATED DATABASE RECORD (The raw data with the CC Leak we found)
    raw_db_record = {
        "id": 1,
        "company_name": "Apex Technologies LLC",
        "credit_card_number": "4532-1234-5678-9012", # SENSITIVE DATA
        "credit_card_cvv": "441",                   # SENSITIVE DATA
        "owner_id": 505                              # The AUTHORIZED owner
    }

    print(f"\n🛡️ [SENTINEL-AUDIT] Validating Request: User {session_user_id} -> Record {requested_id}")

    # --- STEP 1: AUTHORIZATION CHECK (Fixes IDOR) ---
    if session_user_id != raw_db_record['owner_id']:
        print("🔴 ACCESS DENIED: Identity mismatch. Data Access Blocked.")
        return {"error": "Unauthorized Access Denied - Incident Logged."}

    # --- STEP 2: DATA SCRUBBING (Fixes Excessive Data Exposure) ---
    # We EXPLICITLY filter out 'credit_card_number' and 'cvv'
    safe_data = {
        "id": raw_db_record["id"],
        "company_name": raw_db_record["company_name"],
        "status": "Verified - Secure Payload"
    }

    print("🟢 ACCESS GRANTED: Resource ownership verified. Scrubbing sensitive PII...")
    return safe_data

# --- UNIT TESTS FOR VERIFICATION ---
if __name__ == "__main__":
    print("==================================================")
    print("SENTINEL STACKS: REMEDIATION VERIFICATION SUITE")
    print("==================================================")

    # SCENARIO A: THE HACKER ATTEMPT
    # Hacker (User 99) tries to access Record 1 (Owned by 505)
    print("\n[TEST 1] SIMULATING UNAUTHORIZED HACKER (IDOR ATTEMPT)...")
    hacker_result = secure_get_customer(session_user_id=99, requested_id=1)
    print(f"RESULT: {hacker_result}")

    # SCENARIO B: THE AUTHORIZED OWNER
    # The real client (User 505) views their own data
    print("\n[TEST 2] SIMULATING AUTHORIZED OWNER (SECURE RETRIEVAL)...")
    owner_result = secure_get_customer(session_user_id=505, requested_id=1)
    print(f"RESULT: {owner_result}")