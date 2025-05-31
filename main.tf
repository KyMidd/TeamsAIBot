# Define Terraform provider
terraform {
  required_version = "~> 1.7"

  required_providers {
    aws = {
      version = "~> 5.77"
      source  = "hashicorp/aws"
    }
  }
}

# Download AWS provider
provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Contact            = "YourName"
      Team               = "YourTeam"
      CodeAt             = "https://github.com/YourGitHub/YourRepo"
      SuperCoolContentAt = "LetsDoDevOps.com"
    }
  }
}

# Provider in AI region
provider "aws" {
  alias  = "west2"
  region = "us-west-2"

  default_tags {
    tags = {
      Contact            = "YourName"
      Team               = "YourTeam"
      CodeAt             = "https://github.com/YourGitHub/YourRepo"
      SuperCoolContentAt = "LetsDoDevOps.com"
    }
  }
}

# Build lambda
module "lambda" {
  source = "./lambda"

  # Tables
  conversation_table_arn = aws_dynamodb_table.conversations.arn
  token_table_arn        = aws_dynamodb_table.tokens.arn

  # CKM for encryption
  vera_cmk_alias = local.cmk_alias

  # Pass providers
  providers = {
    aws       = aws
    aws.west2 = aws.west2
  }
}

output "receiver_function_url" {
  value = module.lambda.ReceiverFunctionUrl
}