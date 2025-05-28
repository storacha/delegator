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
go build -o bin/delegator .
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
./bin/delegator server

# Start with custom host/port
./bin/delegator server --host 0.0.0.0 --port 8081

# Start with config file
./bin/delegator server --config ./config.yaml
```

### Web Interface

Access the web UI at `http://localhost:8080` for a user-friendly onboarding experience:

- **Dashboard**: Service status and quick onboarding access
- **Step-by-step onboarding**: Guided WSP registration process
- **Session tracking**: Monitor progress and download delegations
- **Mobile-friendly**: Responsive design for all devices

### Command Line Client

```bash
# Register a new provider DID
./bin/delegator client register-did did:key:z6MkjApdj1bAgFyvC9AyNEUxZ3hQKXMLLUmG6rEpkPbSypAv

# Register FQDN for a session
./bin/delegator client register-fqdn <session-id> https://your-storage-node.example.com

# Submit delegation proof
./bin/delegator client register-proof <session-id> <delegation-proof>

# Check session status
./bin/delegator client status <session-id>

# Use custom API URL
./bin/delegator client --api-url http://staging.delegator.warm.storacha.network status <session-id>
```

## API Endpoints

### Web Interface
- `GET /` - Dashboard homepage
- `GET /onboard` - Onboarding flow interface
- `GET /onboard/status/:session_id` - Session status page
- `GET /health` - Service health check

### JSON API
- `POST /api/v1/onboard/register-did` - Register DID for onboarding
- `POST /api/v1/onboard/register-fqdn` - Register and verify FQDN
- `POST /api/v1/onboard/register-proof` - Submit delegation proof
- `GET /api/v1/onboard/status/:session_id` - Get session status
- `GET /api/v1/onboard/delegation/:session_id` - Download delegation file

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