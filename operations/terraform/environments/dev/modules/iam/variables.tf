variable "kms_cent_ec2_role_arn" {
  description = "The ARN of the IAM role for the KMS Centralized EC2 instance"
  type = string
}

variable "environment" {
  description = "The environment in which the resources are deployed"
  type = string
}


variable "eif_pcr0" {
  description = "The ARN of the IAM role for the KMS Centralized EC2 instance"
  type = string
}
