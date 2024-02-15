variable "desired_count" {
  type = number
  description = "The number of tasks to run for the app service"
}

variable "image" {
  type = string
  description = "The name of the Docker image url with its tag to use for the app service"
}

variable "environment" {
  type = string
  description = "The environment to deploy the app service to"
}

variable "vpc_id_private" {
  type = string
  description = "The VPC ID to deploy the app service to"
}

variable "repository_arn_aws_creds" {
  type = string
  description = "The ARN of the AWS credentials to use for the ECR repository"
}

variable "subnet_id_private" {
  type = string
  description = "The subnet ID to deploy the app service to"
}

variable "subnet_ids" {
  type = list(string)
  description = "The subnet IDs to deploy the app service to"
}

variable "security_group_default_id" {
  type = string
  description = "The security group ID to deploy the app service to"
}

variable "ubuntu_ami_id" {
  type = string
  description = "The AMI ID to use for the EC2 instances"
}
