resource "aws_secretsmanager_secret" "company_vault" {
  name        = "Enterprise_Production_Key"
  description = "Managed by Security Engineering - 24hr Rotation"
}

resource "aws_secretsmanager_secret_rotation" "rotation_policy" {
  secret_id           = aws_secretsmanager_secret.company_vault.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789:function:rotator"

  rotation_rules {
    automatically_after_days = 1 # This is the "Self-Destruct" logic
  }
}