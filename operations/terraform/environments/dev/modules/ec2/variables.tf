variable "environment" {
  type = string
  description = "The environment to deploy the app service to"
}

variable "subnet_id" {
  type = string
  description = "The subnet ID to deploy the app service to"
}

variable "security_group_default_id" {
  type = string
  description = "The security group ID to deploy the app service to"
}

variable "vpc_id" {
  type = string
  description = "The VPC ID to deploy the app service to"
}

variable "ubuntu_ami_id" {
  type = string
  description = "The AMI ID to use for the EC2 instances"
}
