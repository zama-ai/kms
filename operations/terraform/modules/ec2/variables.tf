variable "environment" {
  type = string
  description = "The environment to deploy the app service to"
}

variable "subnet_id" {
  type = string
  description = "The subnet ID to deploy the app service to"
}

variable "vpc_id" {
  type = string
  description = "The VPC ID to deploy the app service to"
}

variable "image" {
  type = string
  description = "The Docker image to use for the ECS task"
}

variable "repository_arn_aws_creds" {
  type = string
  description = "The ARN of the AWS Secrets Manager secret containing the Docker repository credentials"
}

variable "instance_type" {
  type = string
  description = "The instance type to use for the app service"
}

variable "ssh_key_name" {
  type = string
  description = "The name of the SSH key to use for the app service"
}

variable "image_eif" {
  type = string
  description = "The name of the Docker image url with its tag to use for the app service"
}

variable "eif_pcr0" {
  type = string
  description = "The PCR0 value from the EIF build"
}


