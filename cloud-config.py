# AWS Configuration
# These are test keys to verify pipeline security
AWS_ACCESS_KEY_ID = "AKIAID846SHEXAMPLEPR"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def connect_to_aws():
    print("Initiating secure connection...")
    import os

# DANGEROUS: This is a Remote Code Execution (RCE) vulnerability.
# It takes user input and runs it directly on the OS.
def execute_system_maintenance():
    cmd = input("Enter maintenance command: ")
    os.system(cmd)