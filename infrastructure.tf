resource "aws_s3_bucket" "company_logs" {
  bucket = "amazon-security-lab-999"
  # GOVERNANCE RISK: Public S3 Bucket
  acl    = "public-read"
}

resource "aws_security_group" "web_access" {
  name = "allow-web"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Open to the world
  }
}