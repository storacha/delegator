terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.86.0"
    }
    archive = {
      source = "hashicorp/archive"
    }
  }
  backend "s3" {
    bucket = "storacha-terraform-state"
    key = "storacha/${var.app}/terraform.tfstate"
    region = "us-west-2"
    encrypt = true
  }
}

provider "aws" {
  allowed_account_ids = [var.allowed_account_id]
  region = var.region
  default_tags {
    tags = {
      "Environment" = terraform.workspace
      "ManagedBy"   = "OpenTofu"
      Owner         = "storacha"
      Team          = "Storacha Engineering"
      Organization  = "Storacha"
      Project       = "${var.app}"
    }
  }
}

# CloudFront is a global service. Certs must be created in us-east-1, where the core ACM infra lives
provider "aws" {
  region = "us-east-1"
  alias = "acm"
}



module "app" {
  source = "github.com/storacha/storoku//app?ref=v0.5.0"
  private_key = var.private_key
  private_key_env_var = "REGISTRAR_DELEGATOR_KEY"
  principal_mapping = var.principal_mapping
  did = var.did
  did_env_var = "REGISTRAR_DELEGATOR_DID"
  app = var.app
  appState = var.app
  write_to_container = false
  environment = terraform.workspace
  network = var.network
  # if there are any env vars you want available only to your container
  # in the vpc as opposed to set in the dockerfile, enter them here
  # NOTE: do not put sensitive data in env-vars. use secrets
  deployment_env_vars = []
  image_tag = var.image_tag
  create_db = false
  # enter secret values your app will use here -- these will be available
  # as env vars in the container at runtime
  secrets = { 
    "REGISTRAR_DELEGATOR_INDEXING_SERVICE_PROOF" = var.indexing_service_proof
    "REGISTRAR_DELEGATOR_EGRESS_TRACKING_SERVICE_PROOF" = var.egress_tracking_service_proof
    "REGISTRAR_CONTRACT_TRANSACTOR_KEY" = var.contract_transactor_key
  }
  # enter any sqs queues you want to create here
  queues = []
  caches = []
  topics = []
  tables = [
    {
      name = "storage-provider-allow-list"
      attributes = [
        {
          name = "did"
          type = "S"
        },
      ]
      hash_key = "did"
    },
  ]
  buckets = [
  ]
  providers = {
    aws = aws
    aws.acm = aws.acm
  }
  env_files = var.env_files
  domain_base = var.domain_base
}
