locals {
    allowlist_table_name = "${terraform.workspace == "prod" ? "delegator-storage-provider-allow-list" : "staging-warm-delegator-storage-provider-allow-list"}"
    allowlist_table_region = "${terraform.workspace == "prod" ? "us-west-2" : "us-east-2"}"

    providerinfo_table_name = "${terraform.workspace == "prod" ? "upload-api-storage-provider" : "staging-warm-upload-api-storage-provider"}"
    providerinfo_table_region = "${terraform.workspace == "prod" ? "us-west-2" : "us-east-2"}"
}

provider "aws" {
  alias = "allowlist"
  region = local.allowlist_table_region
}

data "aws_dynamodb_table" "allowlist_table" {
  provider = aws.allowlist
  name = local.allowlist_table_name
}

provider "aws" {
  alias = "providerinfo"
  region = local.providerinfo_table_region
}

data "aws_dynamodb_table" "providerinfo_table" {
  provider = aws.providerinfo
  name = local.providerinfo_table_name
}

data "aws_iam_policy_document" "task_external_dynamodb_document" {
  statement {
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:CreateTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.allowlist_table.arn,
      data.aws_dynamodb_table.providerinfo_table.arn,
    ]
  }
}

resource "aws_iam_policy" "task_external_dynamodb" {
  name        = "${terraform.workspace}-${var.app}-task-external-dynamodb"
  description = "Allows an ECS task to describe and create tables, and get, put, and delete items from external DynamoDB tables"
  policy      = data.aws_iam_policy_document.task_external_dynamodb_document.json
}

resource "aws_iam_role_policy_attachment" "task_external_dynamodb" {
  role       = module.app.deployment.task_role.name
  policy_arn = aws_iam_policy.task_external_dynamodb.arn
}
