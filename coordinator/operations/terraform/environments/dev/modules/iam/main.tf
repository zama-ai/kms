data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms_cent_enclave_policy" {
  policy_id        = "kms-cent-enclave-policy-document"

  statement {
    sid = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "Enable Instance Only"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = ["${var.kms_cent_ec2_role_arn}"]
    }
    actions = ["kms:Decrypt", "kms:Encrypt"]
    resources = ["*"]
    condition {
      test     = "StringEqualsIgnoreCase"
      variable = "kms:RecipientAttestation:ImageSha384"
      values   = ["${var.eif_pcr0}"]
    }
  }
}

resource "aws_kms_key" "kms_cent_dev_key" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  description = "aws-nitro-enclaves"
  tags = {
    Name = "kms-cent-aws-nitro-enclaves-key-${var.environment}"
  }
  policy = data.aws_iam_policy_document.kms_cent_enclave_policy.json
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "km_cent_dev_key_alias" {
  name          = "alias/kms-cent-aws-nitro-enclaves-key-${var.environment}"
  target_key_id = aws_kms_key.kms_cent_dev_key.id
}

