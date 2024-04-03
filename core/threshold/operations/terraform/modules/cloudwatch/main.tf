resource "aws_cloudwatch_log_group" "ddec" {
  name = "ddec-log-group-${var.environment}"

  tags = {
    Environment = "${var.environment}"
    Application = "ddec-party"
  }
}
