# This policy gives our Response Team the power to "Freeze" the crime scene
resource "aws_iam_policy" "forensic_responder" {
  name        = "Security-Forensic-Responder"
  description = "Allows automated snapshots of compromised instances for investigation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}