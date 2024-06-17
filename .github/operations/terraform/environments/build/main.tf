locals {
  region = "eu-west-3"
  arm = {
    # Buildkite Elastic Stack (Amazon Linux 2023 w/ docker)
    ami           = "ami-0bb87f0dc4192d154"
    instance_type = "t4g.xlarge"
    name          = "kms-core-docker-builder-arm"
    key_name      = "docker_builder_arm"
    subnet_id     = "subnet-a886b4c1"
    vpc_id        = "vpc-24988f4d"
  }
}

terraform {
  backend "s3" {
    bucket               = "kms-terraform-state"
    key                  = "build/terraform.tfstate"
    region               = "eu-west-3"
    workspace_key_prefix = "build"
  }
}


provider "aws" {
  region = local.region
}

module "ec2_docker_builder_arm" {
  source = "terraform-aws-modules/ec2-instance/aws"

  name = local.arm.name

  ami                    = local.arm.ami
  instance_type          = local.arm.instance_type
  key_name               = local.arm.key_name
  monitoring             = true
  vpc_security_group_ids = [module.sg_remote_docker_builder.security_group_id]
  subnet_id              = local.arm.subnet_id

  root_block_device = [{
    volume_size           = "500"
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }]

  tags = {
    Terraform   = "true"
    Environment = "build"
    Platform    = "arm"
    Name        = local.arm.name
  }
}

module "sg_remote_docker_builder" {
  source = "terraform-aws-modules/security-group/aws//modules/ssh"

  name        = "remote docker builder"
  description = "Security group for remote docker builders"
  vpc_id      = local.arm.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
}

# These are only needed for shared CI deployment
# noop for this particular plan
# @TODO remove this requirement from CI
variable "image" {
  type = string
  description = "The name of the Docker image url with its tag to use for the app service"
}

variable "eif_pcr0" {
  type = string
  description = "The PCR0 value from the EIF build"
}

variable "image_eif" {
  type = string
  description = "The name of the Docker image url with its tag to use for the app service"
}

output "public_dns" {
  value = module.ec2_docker_builder_arm.public_dns
}

output "public_ip" {
  value = module.ec2_docker_builder_arm.public_ip
}
