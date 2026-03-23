import logging
import json
from datetime import datetime, timezone

# THE "FORENSIC DATA FORMATTER" (Project 23)
# We convert security events into JSON so AI/Splunk can search them instantly.
class ACNSEJSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "system": "ACNSE_IDENTITY_CORE",
            "event_id": "SEC_AUDIT_301", # Unique ID for Security Audits
            "message": record.getMessage()
        }
        return json.dumps(log_entry)

def setup_forensic_logger():
    # 1. Initialize the Secure Logger
    logger = logging.getLogger("ACNSE_WATCHTOWER")
    logger.setLevel(logging.INFO)

    # 2. Define the "Black Box" file destination
    # This creates a log file that can't be easily tampered with.
    file_handler = logging.FileHandler("security-operations/forensic_audit.json")
    file_handler.setFormatter(ACNSEJSONFormatter())
    
    # 3. Attach the handler to the logger
    if not logger.handlers:
        logger.addHandler(file_handler)
        
    return logger

if __name__ == "__main__":
    print("🛡️ ACNSE: Initializing Forensic Data Stream...")
    test_logger = setup_forensic_logger()
    test_logger.info("FORENSIC_INITIALIZATION: Deep-Watch Logger is now ACTIVE.")
    print("✅ LOG FILE CREATED: security-operations/forensic_audit.json")