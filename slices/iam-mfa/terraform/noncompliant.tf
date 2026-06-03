# NON-COMPLIANT variant: the same group with NO MFA-enforcing policy, so the collector
# reports mfa_required_by_policy = false and the Rego fails. Apply only in a throwaway
# account to demonstrate the policy catches the gap.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_iam_group" "humans_insecure" {
  name = "humans-insecure"
}
# (intentionally no aws_iam_group_policy requiring MFA)
