# Delegator

Delegator is a service that facilitates the onboarding and delegation process for storage providers in the Storacha warm storage network. It handles the registration, verification, and authorization of storage node operators joining the network.

## Key Features

- **Storage Provider Onboarding**: Streamlined process for operators to join the network
- **DID Verification**: Secure identity verification using decentralized identifiers
- **Domain Verification**: FQDN verification for operator domains
- **Delegation Management**: Generation and management of cryptographic delegations for storage providers
- **Access Control**: Configurable allow-list system for controlling who can register

## Architecture

Delegator consists of:

- **Server**: Main service that handles API requests and web interface
- **Client**: Go library for programmatic access to the service
- **Web Interface**: Browser-based onboarding flow for providers
- **DynamoDB Storage**: Persistence layer for provider information and access control

## Getting Started

### Prerequisites

- Go 1.23 or later
- DynamoDB (local instance for development, AWS for production)
- Private keys for delegation signing

### Installation

```bash
git clone https://github.com/storacha/delegator.git
cd delegator
make build
```

### Configuration

Delegator can be configured via YAML files or environment variables. See the [Configuration Guide](CONFIG.md) for detailed information on all available options.

### Running

#### Standard Method

```bash
# Run server
./bin/delegator server

# Run with specific config
./bin/delegator server --config /path/to/config.yaml
```

#### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Stop the services
docker-compose down
```

The Docker setup includes:
- Delegator service
- Local DynamoDB instance
- Automatic table creation and initialization

Configuration for the Docker environment is stored in `docker-config.yaml`, which is mounted into the container. You can modify this file to change the service configuration without rebuilding the container.

## Development

```bash
# Format code
make fmt

# Run tests
make test

# Quick development cycle (format, vet, build)
make quick
```

## License

This project is licensed under the terms found in the [LICENSE](LICENSE) file.