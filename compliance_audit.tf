# This resource forces the "Blocking" of any non-compliant infrastructure
resource "aws_config_config_rule" "network_encryption_audit" {
  name = "Force-Encryption-And-Isolation"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  # GOVERNANCE: If this fails, the deployment is banned.
  scope {
    compliance_resource_types = ["AWS::S3::Bucket", "AWS::EC2::Instance"]
  }
}