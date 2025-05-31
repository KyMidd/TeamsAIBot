###
# General data sources
###

# Current AWS account id
data "aws_caller_identity" "current" {}

# Region
data "aws_region" "current" {}


###
# Fetch secret ARNs from Secrets Manager
###
data "aws_secretsmanager_secret" "verateams_secrets_json" {
  name = "YOUR_SECRET_NAME" # Replace with your secret name
}

# Find the CMK's ARN
data "aws_kms_key" "vera_cmk" {
  key_id = var.vera_cmk_alias
}