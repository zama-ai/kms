data "aws_caller_identity" "current" {}
data "aws_elb_service_account" "elb_account_id" {}

resource "aws_security_group" "ddec_lb_sg" {
  name        = "ddec-lb-sg-${var.environment}"
  vpc_id      = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "ddec_lb_logs" {
  bucket = "ddec-lb-logs-${var.environment}"

  tags = {
    Name        = "Bucket for ddec-lb logs"
    Environment = "${var.environment}"
  }
}

data "aws_iam_policy_document" "ddec_allow_lb" {
  statement {
    effect = "Allow"
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.ddec_lb_logs.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]
    actions = ["s3:PutObject"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_elb_service_account.elb_account_id.id}:root"]
    }
  }

  statement {
    effect = "Allow"
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.ddec_lb_logs.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect = "Allow"
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.ddec_lb_logs.bucket}",
    ]
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "ddec_allow_lb" {
  bucket = aws_s3_bucket.ddec_lb_logs.id
  policy = data.aws_iam_policy_document.ddec_allow_lb.json
}

resource "aws_lb" "ddec_lb" {
  name            = "ddec-lb-${var.environment}"
  subnets         = var.subnet_ids
  security_groups = [aws_security_group.ddec_lb_sg.id]
  access_logs {
    bucket  = aws_s3_bucket.ddec_lb_logs.id
    enabled = true
  }
}

resource "aws_lb_target_group" "ddec_lb_target_group" {
  name        = "ddec-lb-tg-${var.environment}"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    port                = "3000"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
  }
}

resource "aws_lb_listener" "ddec_lb_listener" {
  load_balancer_arn = aws_lb.ddec_lb.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.ddec_lb_target_group.id
    type             = "forward"
  }
}

