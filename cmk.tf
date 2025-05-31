locals {
  cmk_alias = "alias/VeraCmk"
}

# Create the KMS key
resource "aws_kms_key" "cmk" {
  description             = "Key for encrypting access tokens between Vera lambda layers"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "VeraCmk"
  }
}

# Optional alias for easier reference
resource "aws_kms_alias" "cmk_alias" {
  name          = local.cmk_alias
  target_key_id = aws_kms_key.cmk.key_id
}