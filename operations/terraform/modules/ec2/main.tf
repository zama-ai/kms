# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}

locals {
  cloud_config_config = <<-END
    #cloud-config
    ${jsonencode({
      packages-update = true,
      packages = ["jq","mode_ssl", "htop", "git", "docker", "aws-cfn-bootstrap", "awslogs", "amazon-cloudwatch-agent"],
      runcmd = ["chown -R ec2-user:ec2-user /home/ec2-user", "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s"]
      write_files = [
        {
          path        = "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/scripts/amazon-cloudwatch-agent.json")
        },
      ]
    })}
  END
}

data "cloudinit_config" "init_files" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content      = local.cloud_config_config
  }

  part {
    content_type = "text/x-shellscript"
    filename     = "init.sh"
    content  = templatefile("${path.module}/scripts/init.tftpl", {
      image = var.image,
      secret_key = var.repository_arn_aws_creds,
    })
  }
}

resource "aws_security_group" "kms_cent_sg" {
  name = "kms-cent-instance-sg"
  vpc_id = var.vpc_id

  dynamic "ingress" {
    for_each = var.environment == "dev" ? [1] : []
    content {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  ingress {
    from_port = 50050
    to_port = 50050
    protocol = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "kms_cent_ec2_role" {
  name = "kms_cent_ec2_role"

   assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "kms_cent_ec2_role_attach" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::324777464715:policy/EcsSecretFetcher",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  ])
  role = aws_iam_role.kms_cent_ec2_role.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "kms_cent_ec2_profile" {
  name = "kms_cent_ec2_profile"
  role = aws_iam_role.kms_cent_ec2_role.name
}

resource "aws_instance" "kms_cent_instance" {
  tags = {
    Name = "kms_centralized_${var.environment}"
  }
  ami = data.aws_ami.amazon-linux-2.id
  instance_type = var.instance_type
  key_name = var.ssh_key_name
  iam_instance_profile = aws_iam_instance_profile.kms_cent_ec2_profile.name
  subnet_id = var.subnet_id
  associate_public_ip_address = true
  security_groups = [aws_security_group.kms_cent_sg.id]
  user_data = data.cloudinit_config.init_files.rendered
  user_data_replace_on_change = true
}

