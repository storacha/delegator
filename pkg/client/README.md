# Delegator Client

A Go client library for the Storacha Delegator API, providing a clean and idiomatic interface for Warm Storage Provider (WSP) onboarding.

## Features

- **Complete API Coverage**: Supports all delegator endpoints including DID registration, FQDN verification, proof submission, and status checking
- **Robust Error Handling**: Structured error types with helper methods for common HTTP status codes
- **Configurable**: Support for custom HTTP clients, timeouts, and user agents
- **Context Support**: All methods accept context for cancellation and timeouts
- **Type Safety**: Uses strongly-typed request/response models
- **Testing**: Comprehensive test suite with examples

## Installation

```bash
go get github.com/storacha/delegator/pkg/client
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/storacha/delegator/pkg/client"
)

func main() {
    // Create a new client
    c, err := client.New("http://localhost:8080",
        client.WithTimeout(30*time.Second),
        client.WithUserAgent("my-app/1.0"),
    )
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Check service health
    if err := c.HealthCheck(ctx); err != nil {
        log.Fatalf("Service unhealthy: %v", err)
    }

    // Register DID
    did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    resp, err := c.RegisterDID(ctx, did)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Session ID: %s\n", resp.SessionID)
}
```

## Complete Onboarding Workflow

The client supports the full WSP onboarding flow:

### 1. Register DID

```go
resp, err := client.RegisterDID(ctx, "did:key:z6Mk...")
if err != nil {
    if apiErr, ok := err.(*client.APIError); ok {
        if apiErr.IsForbidden() {
            // DID not in allowlist
        } else if apiErr.IsConflict() {
            // DID already registered
        }
    }
    return err
}
sessionID := resp.SessionID
```

### 2. Download Delegation

```go
delegationData, err := client.DownloadDelegation(ctx, sessionID)
if err != nil {
    return err
}

// Save to file
if err := os.WriteFile("delegation.json", delegationData, 0644); err != nil {
    return err
}
```

### 3. Register FQDN

```go
resp, err := client.RegisterFQDN(ctx, sessionID, "https://my-provider.com")
if err != nil {
    if apiErr, ok := err.(*client.APIError); ok {
        if apiErr.IsBadRequest() {
            // Invalid FQDN or wrong session state
        }
    }
    return err
}
```

### 4. Submit Proof

```go
proof := "base64-encoded-delegation-proof"
resp, err := client.RegisterProof(ctx, sessionID, proof)
if err != nil {
    return err
}

if resp.Status == "completed" {
    fmt.Println("Onboarding complete!")
}
```

### 5. Check Status

```go
status, err := client.GetStatus(ctx, sessionID)
if err != nil {
    return err
}

fmt.Printf("Current status: %s\n", status.Status)
fmt.Printf("Next step: %s\n", status.NextStep)
```

## Configuration Options

### Custom HTTP Client

```go
httpClient := &http.Client{
    Timeout: 60 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns: 10,
        IdleConnTimeout: 30 * time.Second,
    },
}

client, err := client.New("http://localhost:8080",
    client.WithHTTPClient(httpClient),
)
```

### Timeout Configuration

```go
client, err := client.New("http://localhost:8080",
    client.WithTimeout(45*time.Second),
)
```

### Custom User Agent

```go
client, err := client.New("http://localhost:8080",
    client.WithUserAgent("my-storage-app/2.1"),
)
```

## Error Handling

The client provides structured error handling with the `APIError` type:

```go
resp, err := client.RegisterDID(ctx, did)
if err != nil {
    if apiErr, ok := err.(*client.APIError); ok {
        // Check specific error types
        switch {
        case apiErr.IsBadRequest():    // 400
        case apiErr.IsForbidden():     // 403
        case apiErr.IsNotFound():      // 404
        case apiErr.IsConflict():      // 409
        default:
            // Other HTTP status codes
            fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
        }
    } else {
        // Network or other errors
        fmt.Printf("Network error: %v\n", err)
    }
}
```

## Session States

The onboarding process follows these states:

- `started` → Initial state after DID registration
- `did_verified` → DID has been verified and delegation generated
- `fqdn_verified` → FQDN has been verified and is accessible
- `proof_verified` → Proof delegation has been validated
- `completed` → WSP is fully onboarded and registered

## Best Practices

### Context Usage

Always use context for cancellation and timeouts:

```go
// With deadline
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resp, err := client.RegisterDID(ctx, did)
```

### Error Logging

Log errors with sufficient context:

```go
if err != nil {
    log.Printf("Failed to register DID %s: %v", did, err)
    return err
}
```

### Resource Cleanup

The client handles HTTP connections automatically, but ensure proper context cancellation:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel() // Always call cancel

// Use ctx for all operations
```

### Retry Logic

Implement retry logic for network errors:

```go
func registerDIDWithRetry(client *client.Client, did string) error {
    for i := 0; i < 3; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        _, err := client.RegisterDID(ctx, did)
        cancel()
        
        if err == nil {
            return nil
        }
        
        if apiErr, ok := err.(*client.APIError); ok {
            // Don't retry client errors
            if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
                return err
            }
        }
        
        time.Sleep(time.Duration(i+1) * time.Second)
    }
    return fmt.Errorf("failed after 3 retries")
}
```

## Thread Safety

The client is safe for concurrent use across multiple goroutines. Each method call is independent and doesn't modify shared state.

## Testing

The package includes comprehensive tests and examples. Run tests with:

```bash
go test ./pkg/client
```

Run examples:

```bash
go test ./pkg/client -run Example
```