# COMPLIANT reference: a security group that allows only HTTPS from the internet and
# restricts SSH to an internal management CIDR — admin access never reaches 0.0.0.0/0,
# and there is no wide-open ingress. The collector reports empty exposure lists.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

resource "aws_security_group" "web" {
  name        = "web-restricted"
  description = "HTTPS public, SSH internal only"

  ingress {
    description = "HTTPS from anywhere (intentional public service)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from the management network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
