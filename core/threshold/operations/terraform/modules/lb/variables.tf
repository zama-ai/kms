variable "environment" {
  type        = string
  description = "The environment to deploy to"
}

variable "subnet_ids" {
  type        = list(string)
  description = "The subnet to deploy the load balancer to"
}

variable "vpc_id" {
  type        = string
  description = "The VPC to deploy the load balancer to"
}

