resource "aws_secretsmanager_secret" "db_key" {
  name        = "Production_Database_API_Key"
  description = "Managed by Security Engineering - Auto-rotating key"
}

# GOVERNANCE: Setting the rotation policy to 1 day
resource "aws_secretsmanager_secret_rotation" "daily_rotation" {
  secret_id           = aws_secretsmanager_secret.db_key.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789:function:rotation_logic"

  rotation_rules {
    automatically_after_days = 1
  }
}