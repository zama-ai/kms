terraform {
  backend "s3" {
    bucket = "kms-terraform-state"
    key    = "ddec/terraform.tfstate"
    region = "eu-west-3"
    workspace_key_prefix = "ddec"
  }

}

provider "aws" {
  region = "eu-west-3"
}

module "cloudwatch" {
  source = "../../modules/cloudwatch"
  environment = var.environment
}

module "ecs" {
  source = "../../modules/ecs"
  environment = var.environment
  image = var.image
  desired_count = var.desired_count
  vpc_id = var.vpc_id_private
  cloudwatch_log_group_name = module.cloudwatch.log_group_name
  subnet_ids = var.subnet_ids
  repository_arn_aws_creds = var.repository_arn_aws_creds
}


