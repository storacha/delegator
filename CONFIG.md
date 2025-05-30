# Configuration Guide

This document details all configuration options for the Delegator application. Configuration can be provided through:

1. Configuration file (YAML)
2. Environment variables

## Configuration File Locations

The application searches for a `config.yaml` file in the following locations (in order):
- Current working directory
- `./configs` directory
- `$HOME/.delegator` directory
- `/etc/delegator` directory

## Environment Variables

Environment variables take precedence over config file settings. All environment variables are prefixed with `STORACHA_DELEGATOR_` and use underscores instead of dots. For example, `server.host` becomes `STORACHA_DELEGATOR_SERVER_HOST`.

## Configuration Options

### Server Configuration

| Field | Description | Environment Variable | Default | Required |
|-------|-------------|----------------------|---------|----------|
| `server.host` | Host address to bind the server to | `STORACHA_DELEGATOR_SERVER_HOST` | `0.0.0.0` | No |
| `server.port` | Port to run the server on (1-65535) | `STORACHA_DELEGATOR_SERVER_PORT` | `8080` | No |
| `server.read_timeout` | Maximum duration for reading the entire request | `STORACHA_DELEGATOR_SERVER_READ_TIMEOUT` | `1m` | No |
| `server.write_timeout` | Maximum duration before timing out writes of the response | `STORACHA_DELEGATOR_SERVER_WRITE_TIMEOUT` | `1m` | No |
| `server.session_key` | Secret key used for session encryption | `STORACHA_DELEGATOR_SERVER_SESSION_KEY` | `storacha-delegator-secret-key` | Yes |

### Onboarding Configuration

| Field | Description | Environment Variable | Default | Required |
|-------|-------------|----------------------|---------|----------|
| `onboarding.session_timeout` | Duration a session will remain active | `STORACHA_DELEGATOR_ONBOARDING_SESSION_TIMEOUT` | `12h` | No |
| `onboarding.fqdn_verification_timeout` | Duration to wait when dialing the operator's domain | `STORACHA_DELEGATOR_ONBOARDING_FQDN_VERIFICATION_TIMEOUT` | `1m` | No |
| `onboarding.indexing_service_key` | Private key of the indexing service for signing delegations | `STORACHA_DELEGATOR_ONBOARDING_INDEXING_SERVICE_KEY` | empty | Yes |
| `onboarding.upload_service_did` | DID for instruction to operator when creating a delegation | `STORACHA_DELEGATOR_ONBOARDING_UPLOAD_SERVICE_DID` | empty | Yes |
| `onboarding.allow_list` | List of DIDs allowed to register | `STORACHA_DELEGATOR_ONBOARDING_ALLOW_LIST` | `[]` | No |

### Logging Configuration

| Field | Description | Environment Variable | Default | Required |
|-------|-------------|----------------------|---------|----------|
| `log.level` | Log level (debug, info, warn, error) | `STORACHA_DELEGATOR_LOG_LEVEL` | `info` | No |

### DynamoDB Configuration

| Field | Description | Environment Variable | Default | Required |
|-------|-------------|----------------------|---------|----------|
| `dynamo.region` | AWS region of the DynamoDB instance | `STORACHA_DELEGATOR_DYNAMO_REGION` | empty | Yes |
| `dynamo.allow_list_table_name` | Table for storing allowed DIDs | `STORACHA_DELEGATOR_DYNAMO_ALLOW_LIST_TABLE_NAME` | empty | Yes |
| `dynamo.provider_info_table_name` | Table for persisting registered user data | `STORACHA_DELEGATOR_DYNAMO_PROVIDER_INFO_TABLE_NAME` | empty | Yes |
| `dynamo.endpoint` | Custom endpoint for local testing | `STORACHA_DELEGATOR_DYNAMO_ENDPOINT` | empty | No |

## Example Configuration

```yaml
server:
  host: 0.0.0.0
  port: 8080
  read_timeout: 1m
  write_timeout: 1m
  session_key: your-secure-session-key

onboarding:
  session_timeout: 12h
  fqdn_verification_timeout: 1m
  indexing_service_key: "your-private-key-here"
  upload_service_did: "did:key:example"
  allow_list:
    - "did:key:allowed-user1"
    - "did:key:allowed-user2"

log:
  level: info

dynamo:
  region: us-west-2
  allow_list_table_name: delegator-allow-list
  provider_info_table_name: delegator-provider-info
  # Only for local development:
  # endpoint: http://localhost:8000
```

## Notes

- Duration fields (like timeouts) use Go's duration format: `300ms`, `1.5h`, `2h45m`, etc.
- For the `allow_list`, DIDs can be specified either in the config or in the DynamoDB allow list table.
- The `endpoint` field in DynamoDB config should only be used for local development and testing.