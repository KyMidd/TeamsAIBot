# DynamoDB Tables
variable "conversation_table_arn" {
  description = "ARN of the DynamoDB conversations table"
  type        = string
}

variable "token_table_arn" {
  description = "ARN of the DynamoDB tokens table"
  type        = string
}

# CMK for encryption
variable "vera_cmk_alias" {
  description = "Alias of the CMK for encryption"
  type        = string
}