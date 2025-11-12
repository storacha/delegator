locals {
    providerinfo_table_name = "${terraform.workspace == "forge-prod" ? "forge-prod-upload-api-storage-provider" : "staging-warm-upload-api-storage-provider"}"
    providerinfo_table_region = "${terraform.workspace == "forge-prod" ? "us-west-2" : "us-east-2"}"
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
