# ec2/output.tf
output "ec2_public_ip" {
  value = aws_instance.kms_cent_instance.public_ip
  description = "The public IP address of the KMS Centralized Server EC2 instance"
}
