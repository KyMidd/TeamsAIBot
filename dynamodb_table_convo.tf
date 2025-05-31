locals {
  # This is the name of the DynamoDB table
  conversation_table_name = "VeraTeamsConversations"
}

resource "aws_dynamodb_table" "conversations" {
  name           = local.conversation_table_name
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "aadObjectId"

  attribute {
    name = "aadObjectId"
    type = "S"
  }

  # Store entire conversation event as a JSON string with name conversationEvent

  ttl {
    attribute_name = "deleteAt" # Epoch time in seconds, needs to match token validity
    enabled        = true
  }

  tags = {
    Name = local.conversation_table_name
  }
}