# ec2/output.tf
output "kms_cent_ec2_role_arn" {
  value = aws_iam_role.kms_instance_role.arn
  description = "The ARN of the IAM role for the KMS Centralized EC2 instance"
}
