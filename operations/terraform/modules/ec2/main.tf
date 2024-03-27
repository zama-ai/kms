# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon-linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}


resource "aws_iam_role" "kms_instance_role" {
  name = "kms_instance_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "assume_role_kms_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    resources = [
      "${aws_iam_role.kms_instance_role.arn}",
    ]
  }
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["${aws_iam_role.kms_instance_role.arn}"]
    }
  }
}

resource "aws_iam_role" "kms_assume_role" {
  name = "kms_assume_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}


resource "aws_iam_role_policy" "kms_assume_role_assume_instance_role_policy" {
  name   = "kms_assume_role_assume_instance_role_policy"
  role = "${aws_iam_role.kms_instance_role.name}"
  policy = "${data.aws_iam_policy_document.assume_role_kms_policy.json}"
}



locals {
  cloud_config_config = <<-END
    #cloud-config
    ${jsonencode({
      bootcmd = ["amazon-linux-extras install aws-nitro-enclaves-cli"],
      packages-update = true,
      packages = ["jq","htop", "git", "docker", "aws-cfn-bootstrap", "amazon-cloudwatch-agent", "aws-nitro-enclaves-cli", "socat"],
      runcmd = [
        "mkdir -p /home/ec2-user/app",
        "chown -R ec2-user:ec2-user /home/ec2-user",
        "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s"
      ]
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
      image_eif = var.image_eif,
      secret_key = var.repository_arn_aws_creds,
      region = data.aws_region.current.name,
      role_arn = aws_iam_role.kms_assume_role.arn,
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



resource "aws_iam_role_policy_attachment" "kms_cent_ec2_role_attach" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::324777464715:policy/EcsSecretFetcher",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ])
  role = aws_iam_role.kms_instance_role.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "kms_cent_ec2_profile" {
  name = "kms_cent_ec2_profile"
  role = aws_iam_role.kms_instance_role.name
}

resource "aws_instance" "kms_cent_instance" {
  tags = {
    Name = "kms_centralized_${var.environment}"
  }
  root_block_device {
    volume_type = "gp2"
    volume_size = 120
  }
  ami = data.aws_ami.amazon-linux.id
  instance_type = var.instance_type
  key_name = var.ssh_key_name
  iam_instance_profile = aws_iam_instance_profile.kms_cent_ec2_profile.name
  subnet_id = var.subnet_id
  associate_public_ip_address = true
  security_groups = [aws_security_group.kms_cent_sg.id]
  user_data = data.cloudinit_config.init_files.rendered
  user_data_replace_on_change = true
  enclave_options {
    enabled = true
  }
}

