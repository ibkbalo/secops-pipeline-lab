resource "aws_secretsmanager_secret" "production_vault" {
  name        = "Enterprise_API_Key"
  description = "Managed Secret with 24-hour Rotation Policy"
}

resource "aws_secretsmanager_secret_rotation" "rotation_logic" {
  secret_id           = aws_secretsmanager_secret.production_vault.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789:function:rotation_logic"

  rotation_rules {
    automatically_after_days = 1 # The "Self-Destruct" Rotation Policy
  }
}