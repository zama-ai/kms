terraform {
  backend "s3" {
    bucket = "kms-terraform-state"
    key    = "centralized/dev/terraform.tfstate"
    region = "eu-west-3"
    workspace_key_prefix = "kms-centralized"
  }

}

provider "aws" {
  region = "eu-west-3"
}

module "ec2" {
  source = "../../modules/ec2"
  environment = var.environment
  image = var.image
  vpc_id = var.vpc_id_private
  subnet_id = var.subnet_id
  repository_arn_aws_creds = var.repository_arn_aws_creds
  instance_type = var.instance_type
}


