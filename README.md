# Delegator Service

Warm Storage Provider (WSP) onboarding service for the Storacha network. This service manages secure multi-step provider registration, DID verification, delegation generation, and FQDN validation.

## Project Structure

```
.
├── cmd/
│   ├── root.go           # Root cobra command and configuration
│   ├── server.go         # Server command
│   ├── client.go         # Client command base
│   ├── provider.go       # Provider management commands
│   ├── server/main.go    # Server binary main
│   └── client/main.go    # Client binary main
├── internal/
│   ├── api/
│   │   └── routes.go     # Echo API routes and handlers
│   ├── config/
│   │   └── config.go     # Configuration management with Viper
│   └── models/
│       ├── provider.go   # Provider data models
│       └── response.go   # API response models
├── config.yaml          # Example configuration file
└── bin/                  # Built binaries
```

## Quick Start

### Build

```bash
# Using Makefile (recommended)
make build

# Or manually
go build -o bin/delegator-server ./cmd/server
go build -o bin/delegator-client ./cmd/client
```

### Development

```bash
# Full development setup
make dev

# Quick build and test
make quick

# Run demo
make demo

# See all available targets
make help
```

### Run Server

```bash
# Start with default settings
./bin/delegator-server server

# Start with custom host/port
./bin/delegator-server server --host 0.0.0.0 --port 8081

# Start with config file
./bin/delegator-server server --config ./config.yaml
```

### Use Client

```bash
# List providers
./bin/delegator-client client provider list

# Onboard a new provider
./bin/delegator-client client provider onboard \
  --did did:key:example123 \
  --fqdn provider.example.com \
  --filecoin-address f1abc123 \
  --proof-set-id proof-123

# Get provider details
./bin/delegator-client client provider get <provider-id>

# Use custom API URL
./bin/delegator-client client provider list --api-url http://staging.delegator.warm.storacha.network
```

## API Endpoints

- `GET /health` - Health check
- `POST /api/v1/providers/onboard` - Onboard a new provider
- `GET /api/v1/providers` - List all providers
- `GET /api/v1/providers/:id` - Get provider details
- `PUT /api/v1/providers/:id/status` - Update provider status
- `POST /api/v1/delegations/generate` - Generate delegation
- `GET /api/v1/delegations/:id` - Get delegation
- `POST /api/v1/verify/did` - Verify DID
- `POST /api/v1/verify/fqdn` - Verify FQDN

## Configuration

Configuration can be provided via:
1. YAML config file (see `config.yaml`)
2. Environment variables (prefixed with `DELEGATOR_`)
3. Command line flags

Example environment variables:
```bash
export DELEGATOR_SERVER_HOST=0.0.0.0
export DELEGATOR_SERVER_PORT=8080
export DELEGATOR_AWS_REGION=us-west-2
export DELEGATOR_DATABASE_TABLE_NAME=providers
```

## Development

The project follows standard Go project layout with:
- **Echo v4** for the API server
- **Cobra** for CLI commands
- **Viper** for configuration management
- **Structured logging** (configurable JSON/text)
- **Graceful shutdown** with signal handling

### TODO

The API handlers currently return placeholder responses. Next steps:
1. Implement DynamoDB integration
2. Add DID verification logic
3. Add FQDN validation
4. Implement delegation generation
5. Add authentication/authorization
6. Add comprehensive logging
7. Add metrics and monitoring
8. Write tests