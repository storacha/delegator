#!/bin/bash
set -e

echo "Starting DynamoDB setup..."

# Wait for DynamoDB to be ready
echo "Waiting for DynamoDB to be available..."
max_retries=30
retry_count=0

while [ $retry_count -lt $max_retries ]; do
  if curl -s -f http://dynamodb-local:8000 > /dev/null 2>&1; then
    echo "DynamoDB is up - continuing with setup"
    break
  else
    retry_count=$((retry_count+1))
    echo "DynamoDB is unavailable - sleeping (attempt $retry_count of $max_retries)"
    sleep 3
  fi
done

if [ $retry_count -eq $max_retries ]; then
  echo "Error: DynamoDB did not become available in time"
  exit 1
fi

# Add small delay to ensure DynamoDB is fully ready
sleep 3

echo "Creating DynamoDB tables..."

# Create Allow List table
echo "Creating allow list table..."
aws dynamodb create-table \
  --endpoint-url http://dynamodb-local:8000 \
  --region us-west-1 \
  --table-name delegator-allow-list \
  --attribute-definitions AttributeName=DID,AttributeType=S \
  --key-schema AttributeName=DID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  || echo "Allow list table may already exist, continuing..."

# Create Provider Info table
echo "Creating provider info table..."
aws dynamodb create-table \
  --endpoint-url http://dynamodb-local:8000 \
  --region us-west-1 \
  --table-name delegator-provider-info \
  --attribute-definitions AttributeName=DID,AttributeType=S \
  --key-schema AttributeName=DID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  || echo "Provider info table may already exist, continuing..."

# Check if tables were created
echo "Verifying tables were created..."
TABLES=$(aws dynamodb list-tables --endpoint-url http://dynamodb-local:8000 --region us-west-1 --output text)
echo "Available tables: $TABLES"

# Seed the allow list table with initial values
echo "Seeding allow list table with initial values..."
aws dynamodb put-item \
  --endpoint-url http://dynamodb-local:8000 \
  --region us-west-1 \
  --table-name delegator-allow-list \
  --item '{"DID": {"S": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e"}}' \
  || echo "Failed to seed table, may already contain the item"

echo "Setup complete!"