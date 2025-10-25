# Delegator HTTP Server

A delegation service that manages storage provider registration and proof generation for the Storacha network. The service validates provider identities, manages their registration status, and issues delegations for interaction with indexing services.

## Architecture

Built with:
- **Cobra** - CLI framework for command management
- **Viper** - Configuration management (files, env vars, flags)
- **Uber.fx** - Dependency injection framework
- **Echo** - High-performance HTTP server
- **DynamoDB** - Persistent storage for provider registry

## Quick Start

```bash
# Build the server
go build -o delegator

# Run the server
./delegator serve

# Or with custom host/port
./delegator serve --host 127.0.0.1 --port 9090
```

## API Endpoints

### Health & Status

#### `GET /` 
Simple root endpoint for basic connectivity check.

**Response:**
- `200 OK` - Returns plain text "hello"

#### `GET /healthcheck`
Health check endpoint for monitoring service availability.

**Response:**
- `200 OK` - Service is healthy
```json
{
  "status": "healthy"
}
```

### Provider Registration

#### `PUT /registrar/register-node`
Register a storage provider node with the delegator service. Validates the provider's identity, proof, and endpoint availability.

**Request Body:**
```json
{
  "did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e",
  "owner_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "proof_set_id": 1,
  "operator_email": "operator@example.com",
  "public_url": "https://storage.example.com",
  "proof": "<base64-encoded-delegation-proof>"
}
```

**Validation:**
- DID must be in the allow list
- DID must not already be registered
- Public URL must serve the provider's DID at root endpoint
- Proof must be valid delegation from provider to upload service with required capabilities:
  - `blob/accept`
  - `blob/allocate`
  - `blob/replica/allocate`
  - `pdp/info`

**Response:**
- `201 Created` - Successfully registered
- `400 Bad Request` - Invalid request data or unauthorized DID
- `500 Internal Server Error` - Server-side processing error

#### `GET /registrar/is-registered`
Check if a provider DID is registered with the service.

**Request Body:**
```json
{
  "did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e"
}
```

**Response:**
- `200 OK` - Provider is registered
- `404 Not Found` - Provider is not registered
- `400 Bad Request` - Invalid DID format

#### `GET /registrar/request-proof`
Request a delegation proof for a registered provider to interact with the indexing service.

**Request Body:**
```json
{
  "did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e"
}
```

**Response:**
- `200 OK` - Returns delegation proof
```json
{
  "proof": "<base64-encoded-delegation-for-indexing>"
}
```
- `400 Bad Request` - Invalid DID or provider not registered/authorized

The returned proof grants the provider the `claim/cache` capability for the indexing service.

### Benchmarking

#### `POST /benchmark/upload`
Perform an upload benchmark test against a storage provider node.

**Request Body:**
```json
{
  "operator_did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e",
  "operator_endpoint": "https://storage.example.com",
  "operator_proof": "<base64-encoded-delegation-proof>",
  "size": 1048576
}
```

**Validation:**
- Proof must delegate capabilities to the delegator service (not upload service)
- Size must be greater than 0

**Response:**
- `200 OK` - Benchmark completed successfully
```json
{
  "allocate_duration": "100ms",
  "upload_duration": "500ms", 
  "accept_duration": "200ms",
  "download_url": "https://storage.example.com/download/abc123",
  "piece_link": "baga6ea4seaqtest"
}
```
- `400 Bad Request` - Invalid parameters
- `500 Internal Server Error` - Benchmark execution failed

#### `POST /benchmark/download`
Perform a download benchmark test from a storage endpoint.

**Request Body:**
```json
{
  "endpoint": "https://storage.example.com/download/abc123"
}
```

**Response:**
- `200 OK` - Download benchmark completed
```json
{
  "download_duration": "250ms"
}
```
- `400 Bad Request` - Invalid URL
- `500 Internal Server Error` - Download failed

## Client Library

A Go client library is provided in the `client/` package for interacting with the delegator service:

```go
import "github.com/storacha/delegator/client"

// Create client
c, err := client.New("http://localhost:8080")

// Register a provider
err = c.Register(ctx, &client.RegisterRequest{
    DID:           "did:key:...",
    OwnerAddress:  "0x...",
    ProofSetID:    1,
    OperatorEmail: "operator@example.com",
    PublicURL:     "https://storage.example.com",
    Proof:         proofString,
})

// Check registration status
registered, err := c.IsRegistered(ctx, &client.IsRegisteredRequest{
    DID: "did:key:...",
})

// Request proof
resp, err := c.RequestProof(ctx, "did:key:...")
```

## Testing

### Run All Tests
```bash
# Run all tests including system tests
go test ./...

# Run with verbose output
go test -v ./...

# Run only system tests
go test -v ./test/...
```

### System Tests
The comprehensive system test suite in `test/system_test.go` covers:
- Full server lifecycle testing
- All API endpoints with success and failure scenarios
- End-to-end registration workflow
- Mock storage node interactions
- Concurrent request handling
- Input validation and error cases

### Test Individual Components
```bash
# Test specific functionality
go test -v ./test/... -run TestSystemRegistrationFlow
go test -v ./test/... -run TestSystemRequestProof
go test -v ./test/... -run TestSystemBenchmark
```

### Test Coverage
```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Configuration

The server can be configured through multiple sources (in order of precedence):
1. Command line flags
2. Environment variables
3. Configuration file (`.delegator.yaml`)

### Configuration File Example
```yaml
server:
  host: 0.0.0.0
  port: 8080

store:
  region: us-east-1
  allowlist_table_name: delegator-allowlist
  providerinfo_table_name: delegator-providers
  providerweight: 100
  endpoint: "" # Optional: for local DynamoDB

delegator:
  key_file: /path/to/private/key.pem
  indexing_service_web_did: did:web:indexing.example.com
  indexing_service_proof: "<base64-proof>"
  upload_service_did: did:key:uploadservice...
```

### Environment Variables
All configuration values can be set via environment variables with the prefix `REGISTRAR_`:
```bash
export REGISTRAR_SERVER_PORT=9090
export REGISTRAR_STORE_REGION=us-west-2
```

## Development

### Prerequisites
- Go 1.24.4 or later
- Access to DynamoDB (AWS or local)
- Ed25519 private key for delegator identity

### Local Development with Docker
```bash
# Run local DynamoDB
docker run -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -sharedDb

# Configure for local development
export REGISTRAR_STORE_ENDPOINT=localhost:8000
```