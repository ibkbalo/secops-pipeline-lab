import boto3
import datetime

def trigger_forensic_snapshot(instance_id):
    """
    Simulates an automated response to a high-severity GuardDuty alert.
    It 'Freezes' the disk of the compromised server for investigation.
    """
    print(f"[SECURITY-ALERT] High-severity anomaly detected on instance: {instance_id}")
    print(f"[RESPONSE] Initializing Automated Forensic Response...")

    # Timestamp for the evidence log
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    snapshot_name = f"Forensic-Evidence-{instance_id}-{timestamp}"

    # In a real Amazon environment, we call: ec2.create_snapshot()
    print(f"[ACTION] Creating EBS Snapshot: {snapshot_name}")
    print(f"[ACTION] Isolating EBS Volume. Evidence preserved for SOC analysis.")
    
    # SECURITY BEST PRACTICE: Add tags so it's not accidentally deleted
    print(f"[TAGGING] Marking snapshot as 'LEGAL_HOLD' and 'DO_NOT_DELETE'")
    
    return snapshot_name

if __name__ == "__main__":
    # Simulating an automated trigger from a Security Hub alert
    test_instance = "i-0abcdef1234567890"
    evidence_id = trigger_forensic_snapshot(test_instance)
    print(f"[SUCCESS] Incident Response complete. Snapshot ID: {evidence_id}")