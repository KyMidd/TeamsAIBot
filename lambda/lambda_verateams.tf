### 
# Names
###

locals {
  # Name of the lambda function
  vera_lambda_name = "VeraTeams"
}


###
# IAM Role and policies for GitHubCop Trigger Lambda
###

data "aws_iam_policy_document" "VeraTeamsRole_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "VeraTeamsRole" {
  name               = "VeraTeamsRole"
  assume_role_policy = data.aws_iam_policy_document.VeraTeamsRole_assume_role.json
}

resource "aws_iam_role_policy" "VeraTeamsSlack_ReadSecret" {
  name = "ReadSecret"
  role = aws_iam_role.VeraTeamsRole.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecretVersionIds"
          ],
          "Resource" : [
            data.aws_secretsmanager_secret.verateams_secrets_json.arn,
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : "secretsmanager:ListSecrets",
          "Resource" : "*"
        },
      ]
    }
  )
}

resource "aws_iam_role_policy" "VeraTeamsSlack_Bedrock" {
  name = "Bedrock"
  role = aws_iam_role.VeraTeamsRole.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        # Grant permission to invoke bedrock models of any type in us-west-2 region
        {
          "Effect" : "Allow",
          "Action" : [
            "bedrock:InvokeModel",
            "bedrock:InvokeModelStream",
            "bedrock:InvokeModelWithResponseStream",
          ],
          # Both no longer specify region, since Bedrock wants cross-region access
          "Resource" : [
            "arn:aws:bedrock:us-east-1::foundation-model/*",
            "arn:aws:bedrock:us-east-2::foundation-model/*",
            "arn:aws:bedrock:us-west-1::foundation-model/*",
            "arn:aws:bedrock:us-west-2::foundation-model/*",
            "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-east-2:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-west-1:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:inference-profile/*",
          ]
        },
        # Grant permission to invoke bedrock guardrails of any type in us-west-2 region
        {
          "Effect" : "Allow",
          "Action" : "bedrock:ApplyGuardrail",
          "Resource" : "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:guardrail/*"
        },
        # Grant permissions to use knowledge bases in us-west-2 region
        {
          "Effect" : "Allow",
          "Action" : [
            "bedrock:Retrieve",
            "bedrock:RetrieveAndGenerate",
          ],
          "Resource" : "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:knowledge-base/*"
        },
      ]
    }
  )
}

# Cloudwatch
resource "aws_iam_role_policy" "VeraTeamsSlackTrigger_Cloudwatch" {
  name = "Cloudwatch"
  role = aws_iam_role.VeraTeamsRole.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "logs:CreateLogGroup",
          "Resource" : "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.id}:*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : [
            "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/${local.vera_lambda_name}:*"
          ]
        }
      ]
    }
  )
}

# Access the CMK
resource "aws_iam_role_policy" "VeraTeamsSlackTrigger_KMS" {
  name = "KMS"
  role = aws_iam_role.VeraTeamsRole.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "kms:Decrypt",
          ],
          "Resource" : data.aws_kms_key.vera_cmk.arn
        }
      ]
    }
  )
}


###
# Create lambda layers
###

# Create requests layer
/*
mkdir -p lambda/requests/python/lib/python3.12/site-packages/
pip3 install requests -t lambda/requests/python/lib/python3.12/site-packages/. --no-cache-dir 
*/
# data "archive_file" "requests_layer" {
#   type        = "zip"
#   source_dir  = "${path.module}/requests"
#   output_path = "${path.module}/requests_layer.zip"
# }
resource "aws_lambda_layer_version" "requests" {
  layer_name               = "Requests"
  filename                 = "${path.module}/requests_layer.zip"
  source_code_hash         = filesha256("${path.module}/requests_layer.zip")
  compatible_runtimes      = ["python3.12"]
  compatible_architectures = ["arm64"]
}


###
# Build lambda
###

# Zip up python lambda code
data "archive_file" "verateams_trigger_lambda" {
  type        = "zip"
  source_file = "${path.module}/src/verateams.py"
  output_path = "${path.module}/verateams.zip"
}

# Build lambda function
resource "aws_lambda_function" "verateams" {
  filename      = "${path.module}/verateams.zip"
  function_name = local.vera_lambda_name
  role          = aws_iam_role.VeraTeamsRole.arn
  handler       = "verateams.lambda_handler"
  timeout       = 180
  memory_size   = 512
  runtime       = "python3.12"
  architectures = ["arm64"]
  publish       = true

  # Layers are packaged code for lambda
  layers = [
    # This layer permits us to ingest secrets from Secrets Manager
    "arn:aws:lambda:us-east-1:177933569100:layer:AWS-Parameters-and-Secrets-Lambda-Extension-Arm64:12",
    # Requests
    aws_lambda_layer_version.requests.arn,
  ]

  source_code_hash = data.archive_file.verateams_trigger_lambda.output_base64sha256

  environment {
    variables = {
      CMK_ALIAS  = var.vera_cmk_alias
      VERA_DEBUG = "True"
    }
  }
}
