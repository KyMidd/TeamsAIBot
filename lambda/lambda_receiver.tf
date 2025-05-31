###
# Naming
###

locals {
  receiver_lambda_name = "VeraTestReceiverTeams"
}

###
# IAM Role and policies for Message Receiver Lambda
###

data "aws_iam_policy_document" "ReceiverRole_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ReceiverRole" {
  name               = "ReceiverRole"
  assume_role_policy = data.aws_iam_policy_document.ReceiverRole_assume_role.json
}

# Invoke the worker lambda
resource "aws_iam_role_policy" "VeraTeamsReceiver_Lambda" {
  name = "InvokeLambda"
  role = aws_iam_role.ReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ]
        Resource = [aws_lambda_function.verateams.arn]
      }
    ]
  })
}

# Cloudwatch
resource "aws_iam_role_policy" "VeraTeamsReceiver_Cloudwatch" {
  name = "Cloudwatch"
  role = aws_iam_role.ReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "logs:CreateLogGroup"
        Resource = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/${local.receiver_lambda_name}:*"
        ]
      }
    ]
  })
}

# dynamodb policy
resource "aws_iam_role_policy" "VeraTeamsReceiver_DynamoDB" {
  name = "DynamoDB"
  role = aws_iam_role.ReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:DeleteItem",
          # "dynamodb:Scan",
        ]
        Resource = [
          var.conversation_table_arn, # Store conversation events
          var.token_table_arn,        # Stores auth codes from users
        ]
      }
    ]
  })
}

# Secrets
resource "aws_iam_role_policy" "VeraTeamsReceiver_SecretsManager" {
  name = "SecretsManager"
  role = aws_iam_role.ReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = [
          data.aws_secretsmanager_secret.verateams_secrets_json.arn,
        ]
      }
    ]
  })
}

# Access the CMK
resource "aws_iam_role_policy" "VeraTeamsReceiver_CMK" {
  name = "CMK"
  role = aws_iam_role.ReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:DescribeKey",
        ]
        Resource = [
          data.aws_kms_key.vera_cmk.arn,
        ]
      }
    ]
  })
}


###
# Build receiver lambda
###

data "archive_file" "VeraTeams_receiver_lambda" {
  type        = "zip"
  source_file = "${path.module}/src/receiver.py"
  output_path = "${path.module}/receiver.zip"
}

resource "aws_lambda_function" "VeraTest_receiver" {
  filename      = "${path.module}/receiver.zip"
  function_name = local.receiver_lambda_name
  role          = aws_iam_role.ReceiverRole.arn
  handler       = "receiver.lambda_handler"
  timeout       = 10
  memory_size   = 128
  runtime       = "python3.12"
  architectures = ["arm64"]

  source_code_hash = data.archive_file.VeraTeams_receiver_lambda.output_base64sha256

  layers = [
    # This layer permits us to ingest secrets from Secrets Manager
    "arn:aws:lambda:us-east-1:177933569100:layer:AWS-Parameters-and-Secrets-Lambda-Extension-Arm64:12",
    # Requests
    aws_lambda_layer_version.requests.arn,
  ]

  environment {
    variables = {
      VERA_DEBUG             = "True" # Prints lots of logs, only enable for debugging or in pre-prod
      WORKER_LAMBDA_NAME     = aws_lambda_function.verateams.function_name
      CONVERSATION_TABLE_ARN = var.conversation_table_arn
      TOKEN_TABLE_ARN        = var.token_table_arn
      CMK_ALIAS              = var.vera_cmk_alias
    }
  }
}

# Publish alias of new version
resource "aws_lambda_alias" "VeraTest_receiver_alias" {
  name             = "Newest"
  function_name    = aws_lambda_function.VeraTest_receiver.arn
  function_version = aws_lambda_function.VeraTest_receiver.version

  # Add ignore for routing_configuration
  lifecycle {
    ignore_changes = [
      routing_config, # This sometimes has a race condition, so ignore changes to it
    ]
  }
}

# Point lambda function url at new version
resource "aws_lambda_function_url" "VeraTestReceiver_teams_Trigger_FunctionUrl" {
  function_name      = aws_lambda_function.VeraTest_receiver.function_name
  qualifier          = aws_lambda_alias.VeraTest_receiver_alias.name
  authorization_type = "NONE"
}

# Print the URL we can use to trigger the bot
output "ReceiverFunctionUrl" {
  value = aws_lambda_function_url.VeraTestReceiver_teams_Trigger_FunctionUrl.function_url
}