resource "aws_security_group" "ddec-choreo-instance-test-sg" {
  name = "ddec-choreo-instance-test-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port = 22
    to_port = 22
    protocol = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ddec-choreo-instance-test" {
  tags = {
    Name = "ddec-choreo-instance-test"
  }
  ami = var.ubuntu_ami_id
  instance_type = "t2.micro" # change this to your preferred instance type
  key_name = "kms_team_ddec_choreo_test"
  subnet_id = var.subnet_id
  associate_public_ip_address = true
  security_groups = [aws_security_group.ddec-choreo-instance-test-sg.id, var.security_group_default_id]
}
