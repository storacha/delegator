package client_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/storacha/delegator/pkg/client"
)

// Example demonstrates how to use the delegator client for the complete
// onboarding workflow. This is documentation only and does not run.
func Example() {
	// Create a new client
	c, err := client.New("http://localhost:8080",
		client.WithTimeout(30*time.Second),
		client.WithUserAgent("example-app/1.0"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Check service health
	if err := c.HealthCheck(ctx); err != nil {
		log.Fatalf("Service unhealthy: %v", err)
	}

	// Step 1: Register DID
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	didResp, err := c.RegisterDID(ctx, did)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsForbidden() {
				log.Fatalf("DID not in allowlist: %v", err)
			}
			if apiErr.IsConflict() {
				log.Fatalf("DID already registered: %v", err)
			}
		}
		log.Fatalf("Failed to register DID: %v", err)
	}

	sessionID := didResp.SessionID
	fmt.Printf("DID registered successfully. Session ID: %s\n", sessionID)

	// Step 2: Download delegation
	delegationData, err := c.DownloadDelegation(ctx, sessionID)
	if err != nil {
		log.Fatalf("Failed to download delegation: %v", err)
	}
	fmt.Printf("Downloaded delegation: %d bytes\n", len(delegationData))

	// Step 3: Register FQDN (after configuring your node)
	fqdnURL := "https://my-storage-provider.com"
	fqdnResp, err := c.RegisterFQDN(ctx, sessionID, fqdnURL)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsNotFound() {
				log.Fatalf("Session not found: %v", err)
			}
			if apiErr.IsBadRequest() {
				log.Fatalf("Invalid FQDN or session state: %v", err)
			}
		}
		log.Fatalf("Failed to register FQDN: %v", err)
	}
	fmt.Printf("FQDN registered successfully: %s\n", fqdnResp.FQDN)

	// Step 4: Submit proof delegation
	proof := "base64-encoded-delegation-proof"
	proofResp, err := c.RegisterProof(ctx, sessionID, proof)
	if err != nil {
		log.Fatalf("Failed to register proof: %v", err)
	}
	fmt.Printf("Proof registered successfully. Status: %s\n", proofResp.Status)

	// Step 5: Check final status
	status, err := c.GetStatus(ctx, sessionID)
	if err != nil {
		log.Fatalf("Failed to get status: %v", err)
	}
	fmt.Printf("Final status: %s\n", status.Status)
}

// Example_errorHandling demonstrates proper error handling with the client.
// This is documentation only and does not run.
func Example_errorHandling() {
	c, err := client.New("http://localhost:8080")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Example of handling different types of API errors
	_, err = c.RegisterDID(ctx, "invalid-did")
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			switch {
			case apiErr.IsBadRequest():
				fmt.Println("Bad request: check your DID format")
			case apiErr.IsForbidden():
				fmt.Println("DID not allowed: contact support")
			case apiErr.IsConflict():
				fmt.Println("DID already registered")
			case apiErr.IsNotFound():
				fmt.Println("Resource not found")
			default:
				fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Error())
			}
		} else {
			fmt.Printf("Network or other error: %v\n", err)
		}
	}
}

// Example_customHTTPClient shows how to use a custom HTTP client.
// This is documentation only and does not run.
func Example_customHTTPClient() {
	// Create a custom HTTP client with specific settings
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: true,
		},
	}

	// Create delegator client with custom HTTP client
	c, err := client.New("https://delegator.storacha.com",
		client.WithHTTPClient(httpClient),
		client.WithUserAgent("my-storage-app/2.1"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Use the client normally
	if err := c.HealthCheck(context.Background()); err != nil {
		log.Printf("Health check failed: %v", err)
	}
}
