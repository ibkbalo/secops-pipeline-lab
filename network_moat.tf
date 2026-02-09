# 1. Create the Private Cloud (VPC)
resource "aws_vpc" "production_moat" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "Production-Isolated-Network" }
}

# 2. The "Public" Subnet (The Front Gate - where the Web Server lives)
resource "aws_subnet" "public_gateway" {
  vpc_id     = aws_vpc.production_moat.id
  cidr_block = "10.0.1.0/24"
  tags = { Name = "Public-Gateway" }
}

# 3. THE MOAT: The "Private" Subnet (The Inner Vault - where the Database lives)
resource "aws_subnet" "private_vault" {
  vpc_id     = aws_vpc.production_moat.id
  cidr_block = "10.0.2.0/24"
  # GOVERNANCE: No MapPublicIP - This ensures the DB has NO internet access
  map_public_ip_on_launch = false 
  tags = { Name = "Private-Subnet-Database" }
}

# 4. The Firewall (Security Group) - Only allow the Web Server to talk to the DB
resource "aws_security_group" "database_guard" {
  name        = "DB-Shield"
  vpc_id      = aws_vpc.production_moat.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    # SECURITY BEST PRACTICE: Only allow traffic from the Public Gateway subnet
    cidr_blocks     = ["10.0.1.0/24"] 
  }
}