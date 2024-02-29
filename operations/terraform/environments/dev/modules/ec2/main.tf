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
      write_files = [
        {
          path        = "/home/ec2-user/config.toml"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/scripts/config.toml")
        },
        {
          path        = "/home/ec2-user/small_test_params.json"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.cwd}/parameters/small_test_params.json")
        },
        {
          path        = "/home/ec2-user/run-mobygo.sh"
          permissions = "0774"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/scripts/run-mobygo.sh")
        },
      ]
      packages = ["jq","mode_ssl", "htop", "git", "docker"]
      runcmd = ["chown -R ec2-user:ec2-user /home/ec2-user"]
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
    content  = templatefile("${path.module}/scripts/init-ami-aws.tftpl", {
      image = var.image,
      secret_key = var.repository_arn_aws_creds,
    })
  }
}

resource "aws_security_group" "ddec-choreo-instance-test-sg" {
  name = "ddec-choreo-instance-test-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port = 22
    to_port = 22
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

resource "aws_iam_role" "ddec_choreo_ec2_role" {
  name = "ddec_choreo_ec2_role"

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

resource "aws_iam_role_policy_attachment" "ddec_choreo_ec2_role_attach" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::324777464715:policy/EcsSecretFetcher"
  ])
  role = aws_iam_role.ddec_choreo_ec2_role.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "ddec_choreo_ec2_profile" {
  name = "ddec_ec2_profile"
  role = aws_iam_role.ddec_choreo_ec2_role.name
}

resource "aws_instance" "ddec-choreo-instance-test" {
  tags = {
    Name = "ddec-choreo-instance-test"
  }
  ami = data.aws_ami.amazon-linux-2.id
  instance_type = "t2.micro" # change this to your preferred instance type
  key_name = "kms_team_ddec_choreo_test"
  iam_instance_profile = aws_iam_instance_profile.ddec_choreo_ec2_profile.name
  subnet_id = var.subnet_id
  associate_public_ip_address = true
  security_groups = [aws_security_group.ddec-choreo-instance-test-sg.id, var.security_group_default_id]
  user_data = data.cloudinit_config.init_files.rendered
  user_data_replace_on_change = true
}

