# AWS Infrastructure Blueprint
resource "aws_s3_bucket" "company_data" {
  bucket = "amazon-confidential-data-999"
}

# DANGER: This makes the bucket PUBLIC to the whole internet!
resource "aws_s3_bucket_public_access_block" "bad_logic" {
  bucket = aws_s3_bucket.company_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# DANGER: Security Group allowing SSH (Port 22) from EVERYWHERE
resource "aws_security_group" "allow_ssh" {
  name        = "open-access"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # This is the "Open Door"
  }
}