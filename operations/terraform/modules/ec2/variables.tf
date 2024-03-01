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
