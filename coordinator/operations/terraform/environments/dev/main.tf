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
  vpc_id = var.vpc_id
  subnet_id = var.subnet_id
  repository_arn_aws_creds = var.repository_arn_aws_creds
  instance_type = var.instance_type
  ssh_key_name = var.ssh_key_name
  eif_pcr0 = var.eif_pcr0
  image_eif = var.image_eif
}


module "iam" {
  source = "./modules/iam"
  environment = var.environment
  eif_pcr0 = var.eif_pcr0
  kms_cent_ec2_role_arn = module.ec2.kms_cent_ec2_role_arn
}

