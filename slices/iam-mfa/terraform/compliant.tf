# COMPLIANT reference: deny all IAM actions unless MFA is present, for the human group.
# Phishing-resistant enrollment (security keys) is an operational step layered on top;
# this Terraform proves MFA is *enforced by policy*, which the collector reports as
# mfa_required_by_policy = true.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_iam_group" "humans" {
  name = "humans"
}

resource "aws_iam_group_policy" "require_mfa" {
  name  = "require-mfa"
  group = aws_iam_group.humans.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyAllExceptWithoutMFA"
      Effect    = "Deny"
      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"]
      Resource  = "*"
      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
    }]
  })
}
