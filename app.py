import os

def process_data(user_folder):
    # SECURITY RISK: Path Traversal vulnerability
    # A hacker could use '../../etc/passwd' to steal system files
    path = os.path.join("/var/data", user_folder)
    print(f"Accessing data at: {path}")

# AWS Credentials hardcoded (Bad Practice)
AWS_ACCESS_KEY = "AKIA-FAKE-KEY-FOR-TESTING"