def get_enterprise_secret():
    # This replaces the "AKIA" hardcoded keys from Project 9
    # In a real Amazon environment, this calls the Secrets Manager API
    print("[SECURITY] Authenticating to Enterprise Vault...")
    
    # The Vault returns an "ephemeral" (temporary) key
    dynamic_key = "TEMP_ROTATING_KEY_12345"
    print(f"[SECURITY] Access Granted. Using temporary key: {dynamic_key}")
    return dynamic_key

if __name__ == "__main__":
    api_key = get_enterprise_secret()
    print("Application is running in Zero-Trust mode.")