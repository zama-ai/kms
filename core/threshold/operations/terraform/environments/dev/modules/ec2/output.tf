# ec2/output.tf
output "ec2_public_ip" {
  value = aws_instance.ddec-choreo-instance-test.public_ip
  description = "The public IP address of the Choreographer EC2 instance"
}
