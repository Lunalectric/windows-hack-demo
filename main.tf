################################################################################
# Data & Locals
################################################################################

data "aws_availability_zones" "available" {}

#data "aws_caller_identity" "current" {}

locals {
  name            = "${random_string.suffix.result}-${var.demo_name}-mondoo-hacklab"
  default_tags = {
    Name       = local.name
    GitHubRepo = "windows-hack-demo"
    GitHubOrg  = "Lunalectric"
    Terraform  = true
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  #upper   = false
}

################################################################################
# VPC Configuration
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.14.0"

  name                 = "${local.name}-vpc"
  cidr                 = "10.0.0.0/16"
  azs                  = data.aws_availability_zones.available.names
  private_subnets      = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

  tags = merge(
    local.default_tags, {
      "Name"                                = "${local.name}-vpc"
      "${local.name}" = "shared"
    },
  )

  public_subnet_tags = {
    "public/${local.name}" = "shared"
  }

  private_subnet_tags = {
    "private/${local.name}" = "shared"
  }
}

################################################################################
# SSM IAM role
################################################################################

resource "aws_iam_instance_profile" "dev-resources-iam-profile" {
  name = "ec2_ssm_profile-${local.name}-${random_string.suffix.result}"
  role = aws_iam_role.dev-resources-iam-role.name
}

resource "aws_iam_role" "dev-resources-iam-role" {
  name        = "SSM-role-${local.name}-${random_string.suffix.result}"
  description = "The SSM role for Mondoo Hacklab"
  assume_role_policy = <<EOF
  {
  "Version": "2012-10-17",
  "Statement": {
  "Effect": "Allow",
  "Principal": {"Service": "ec2.amazonaws.com"},
  "Action": "sts:AssumeRole"
  }
  }
  EOF
  tags = merge(
    local.default_tags, {
      "Name" = "${random_string.suffix.result}-minikube-demo"
    },
  )
}

resource "aws_iam_role_policy_attachment" "dev-resources-ssm-policy" {
  role       = aws_iam_role.dev-resources-iam-role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

################################################################################
# Kali Linux Instance
################################################################################

data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["kali-last-snapshot-amd64*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "template_file" "change_password" {
  template = file("${path.module}/templates/change-password.tpl")
  vars = {
    pass_string = "${random_string.suffix.result}"
  }
}

resource "aws_security_group" "kali_linux_access" {
  name_prefix = "${random_string.suffix.result}_kali_linux_access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "10.0.0.0/8",
      "${var.publicIP}"
    ]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = local.default_tags
}

module "kali" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 4.0"

  name = "${local.name}-kali-linux"

  ami                    = data.aws_ami.kali_linux.id
  instance_type          = "t3.medium"
  key_name               = var.ssh_key
  iam_instance_profile   = aws_iam_instance_profile.dev-resources-iam-profile.name
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.kali_linux_access.id]
  subnet_id              = element(module.vpc.public_subnets, 0)
  user_data              = data.template_file.change_password.rendered

  tags = merge(
    local.default_tags, {
      "Name" = "${random_string.suffix.result}-kali-linux-hacker-instance"
    },
  )
}

################################################################################
# Windows Instance
################################################################################

data "aws_ami" "windows" {
  most_recent = true
  owners      = ["921877552404"]

  filter {
    name   = "name"
    values = ["win2016-dvwa-printnightmare-final-2022*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "windows_access" {
  name_prefix = "${random_string.suffix.result}_windows_access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "10.0.0.0/8",
      "${var.publicIP}"
    ]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = local.default_tags
}

module "windows-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 4.0"

  name = "${local.name}-windows-dvwa"

  ami                    = data.aws_ami.windows.id #"ami-0937b231c090e893d"
  instance_type          = "t3.medium"
  key_name               = var.ssh_key
  iam_instance_profile   = aws_iam_instance_profile.dev-resources-iam-profile.name
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.windows_access.id]
  subnet_id              = element(module.vpc.public_subnets, 0)

  tags = merge(
    local.default_tags, {
      "Name" = "${random_string.suffix.result}-windows-dvwa-instance"
    },
  )
}
