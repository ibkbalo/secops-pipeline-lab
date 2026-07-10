import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "Production_Database_API_Key"
    region_name = "us-east-1"

    # In a real Day Job, we use the SDK to pull the key from the Vault
    print(f"[SECURITY] Initializing secure connection to AWS Secrets Manager...")
    
    # SIMULATION: In the lab, we show the logic of fetching
    # In production, this replaces the hardcoded 'AKIA...' string
    try:
        # Imagine the app asking the Vault: "Give me the key for today"
        mock_vault_response = {"API_KEY": "TEMP_ROTATING_KEY_998877"} 
        return mock_vault_response['API_KEY']
    except Exception as e:
        print(f"CRITICAL: Could not retrieve keys from Vault. System Lockdown.")
        raise e

# The Application Logic
api_key = get_secret()
print(f"[SECURE-LOG] Application started successfully using rotating credentials.")