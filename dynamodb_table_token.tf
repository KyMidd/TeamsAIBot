locals {
  # This is the name of the DynamoDB table
  token_table_name = "VeraTeamsTokens"
}

resource "aws_dynamodb_table" "tokens" {
  name           = local.token_table_name
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "aadObjectId"

  attribute {
    name = "aadObjectId"
    type = "S"
  }

  # Store accessToken from oauth2 server as string with name accessToken

  ttl {
    attribute_name = "deleteAt" # Epoch time in seconds, needs to match token validity
    enabled        = true
  }

  tags = {
    Name = local.token_table_name
  }
}