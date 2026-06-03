# NON-COMPLIANT variant: SSH open to the entire internet (admin port exposure) — the
# collector reports it under public_admin_exposures and the Rego fails. Apply only in
# a throwaway account to demonstrate the policy catches the gap.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_security_group" "web_insecure" {
  name        = "web-insecure"
  description = "SSH exposed to the internet"

  ingress {
    description = "SSH from anywhere (violation: AC-17(3))"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
