# This looks like a vulnerability, but it is a "Security Trap"
resource "aws_s3_bucket" "decoy_data" {
  bucket = "amazon-internal-test-decoy-999"
  # This triggers our Project 13 Compliance Auditor immediately
  tags = { Security_Level = "Honeypot" }
}